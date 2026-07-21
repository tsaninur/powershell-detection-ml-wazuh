import json
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from sklearn.metrics import roc_curve, auc, precision_recall_curve, average_precision_score

# ================= KONFIGURASI =================
FILE_LOG_ONLINE = 'custom_ml_alerts.json'
FILE_RANGKUMAN  = 'rangkuman_evaluasi_skenario.csv'
# ===============================================

# Noise PowerShell runtime — pencocokan eksak
PURE_NOISE_CONTENTS = {
    "{ Set-StrictMode -Version 1; $_.PSMessageDetails }",
    "{ Set-StrictMode -Version 1; $this.Exception.InnerException.PSMessageDetails }",
    "{ Set-StrictMode -Version 1; $_.ErrorCategory_Message }"
}

# Noise PowerShell runtime — pencocokan pola (Set-Alias CimCmdlets)
def is_pattern_noise(content):
    return all(p in content for p in ("Set-Alias", "ReadOnly, AllScope", "-ErrorAction SilentlyContinue"))

def get_scenario(path):
    p = path.lower().replace('\\\\', '/').replace('\\', '/').replace('//', '/')
    if 'test_set/benign' in p:            return 'Benign',               0, 'benign'
    if 'test_set/malicious' in p:         return 'Malicious',            1, 'malicious'
    if 'ascii_encoding' in p:             return 'ASCII_Encoding',       1, 'malicious'
    if 'string_concatenation' in p:       return 'String_Concatenation', 1, 'malicious'
    if 'string_reordering' in p:          return 'String_Reordering',    1, 'malicious'
    if 'token_manipulation' in p:         return 'Token_Manipulation',   1, 'malicious'
    return None, -1, ''

def extract_filename(path):
    return path.replace('\\\\', '\\').replace('//', '/').split('\\')[-1].split('/')[-1]

def hitung_status(gt, verdict):
    if gt == 1 and verdict == 'malicious': return 'TP'
    if gt == 0 and verdict == 'benign':    return 'TN'
    if gt == 0 and verdict == 'malicious': return 'FP'
    if gt == 1 and verdict == 'benign':    return 'FN'
    return 'UNKNOWN'

def hitung_metrik(TP, TN, FP, FN):
    total = TP + TN + FP + FN
    if total == 0:
        return 0, 0, 0, 0, 0, 0, 0
    acc = (TP + TN) / total
    pre = TP / (TP + FP) if (TP + FP) > 0 else 0
    rec = TP / (TP + FN) if (TP + FN) > 0 else 0
    f1  = 2 * (pre * rec) / (pre + rec) if (pre + rec) > 0 else 0
    fpr = FP / (FP + TN) if (FP + TN) > 0 else 0
    fnr = FN / (FN + TP) if (FN + TP) > 0 else 0
    return total, acc, pre, rec, f1, fpr, fnr

def hitung_latensi(list_data):
    lats = [d.get('latency_ms', 0) for d in list_data if d.get('latency_ms') is not None]
    if not lats:
        return 0, 0, 0, 0
    return (
        round(min(lats), 2),
        round(max(lats), 2),
        round(sum(lats) / len(lats), 2),
        round(sorted(lats)[len(lats) // 2], 2)
    )

def build_rangkuman_row(nama, list_data):
    TP = sum(1 for d in list_data if d['status_evaluasi'] == 'TP')
    TN = sum(1 for d in list_data if d['status_evaluasi'] == 'TN')
    FP = sum(1 for d in list_data if d['status_evaluasi'] == 'FP')
    FN = sum(1 for d in list_data if d['status_evaluasi'] == 'FN')
    total, acc, pre, rec, f1, fpr, fnr = hitung_metrik(TP, TN, FP, FN)
    lat_min, lat_max, lat_avg, lat_med = hitung_latensi(list_data)
    return TP, TN, FP, FN, {
        "Skenario":       nama,
        "Total_Data":     total,
        "TP": TP, "TN": TN, "FP": FP, "FN": FN,
        "Akurasi (%)":    round(acc*100, 2),
        "Presisi (%)":    round(pre*100, 2),
        "Recall (%)":     round(rec*100, 2),
        "F1_Score":       round(f1, 4),
        "FPR":            round(fpr, 4),
        "FNR":            round(fnr, 4),
        "Latensi_Min_ms": lat_min,
        "Latensi_Max_ms": lat_max,
        "Latensi_Avg_ms": lat_avg,
        "Latensi_Med_ms": lat_med,
    }

def plot_curves(y_true, y_probs):
    if len(set(y_true)) < 2:
        print("[SKIP] Kurva ROC/PR tidak dapat dibuat — hanya satu kelas.")
        return
    fpr_c, tpr, _ = roc_curve(y_true, y_probs)
    roc_auc = auc(fpr_c, tpr)
    precision, recall, _ = precision_recall_curve(y_true, y_probs)
    pr_auc = average_precision_score(y_true, y_probs)

    plt.figure(figsize=(12, 5))
    plt.subplot(1, 2, 1)
    plt.plot(fpr_c, tpr, color='darkorange', lw=2, label=f'ROC AUC = {roc_auc:.4f}')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlabel('False Positive Rate (FPR)')
    plt.ylabel('True Positive Rate (TPR)')
    plt.title('Receiver Operating Characteristic (ROC)')
    plt.legend(loc="lower right")
    plt.grid(True, linestyle=':', alpha=0.6)

    plt.subplot(1, 2, 2)
    plt.plot(recall, precision, color='green', lw=2, label=f'PR AUC = {pr_auc:.4f}')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall (PR) Curve')
    plt.legend(loc="lower left")
    plt.grid(True, linestyle=':', alpha=0.6)

    plt.tight_layout()
    plt.savefig('evaluasi_curves.png', dpi=300)
    plt.close()
    print("[SUCCESS] Grafik disimpan: evaluasi_curves.png")

def main():
    print("=" * 70)
    print(" GENERATE ML REPORT")
    print(" Metode: hanya entri berpath, deduplikasi per file (blok terpanjang)")
    print("=" * 70)

    # ── 1. Baca semua entri ──────────────────────────────────────────────────
    skip_noise  = 0
    skip_uji    = 0
    skip_inmem  = 0
    skip_noise_pattern = 0

    # skenario -> dict[filename -> data terpanjang]
    from collections import defaultdict
    skenario_best = defaultdict(dict)  # skenario -> {fname: data_blok_terpanjang}

    try:
        with open(FILE_LOG_ONLINE, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    path    = data.get('script_path', '')
                    content = data.get('script_content', '')

                    # Lewati In-Memory
                    if 'In-Memory' in path:
                        skip_inmem += 1
                        continue

                    # Lewati skrip penguji
                    if 'uji_otomatis' in path.lower():
                        skip_uji += 1
                        continue

                    # Lewati noise eksak
                    if content in PURE_NOISE_CONTENTS:
                        skip_noise += 1
                        continue

                    # Lewati noise pola CimAlias
                    if is_pattern_noise(content):
                        skip_noise_pattern += 1
                        continue

                    sken, gt, gt_label = get_scenario(path)
                    if not sken:
                        continue

                    fname = extract_filename(path)
                    length = data.get('script_length', 0)

                    # Deduplikasi: simpan hanya blok terpanjang per file per skenario
                    existing = skenario_best[sken].get(fname)
                    if existing is None or length > existing.get('script_length', 0):
                        data['_skenario'] = sken
                        data['_gt']       = gt
                        data['_gt_label'] = gt_label
                        data['_fname']    = fname
                        skenario_best[sken][fname] = data

                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"[ERROR] File log '{FILE_LOG_ONLINE}' tidak ditemukan!")
        return

    total_raw    = skip_inmem + skip_uji + skip_noise + skip_noise_pattern + \
                   sum(len(v) for v in skenario_best.values())
    total_unik   = sum(len(v) for v in skenario_best.values())

    print(f"\n[INFO] Total entri dibaca              : {total_raw + skip_inmem}")
    print(f"[INFO] Dilewati (In-Memory)            : {skip_inmem}")
    print(f"[INFO] Dilewati (skrip penguji)        : {skip_uji}")
    print(f"[INFO] Dilewati (noise eksak runtime)  : {skip_noise}")
    print(f"[INFO] Dilewati (noise pola CimAlias)  : {skip_noise_pattern}")
    print(f"[INFO] Entri berpath unik (deduplikasi): {total_unik}")

    # ── 2. Hitung status confusion matrix ────────────────────────────────────
    skenario_data = {
        "Benign": [], "Malicious": [],
        "ASCII_Encoding": [], "String_Concatenation": [],
        "String_Reordering": [], "Token_Manipulation": []
    }

    y_true_all  = []
    y_probs_all = []

    for sken, file_dict in skenario_best.items():
        for fname, data in file_dict.items():
            gt      = data['_gt']
            gt_lbl  = data['_gt_label']
            verdict = data.get('ml_verdict', 'unknown')
            prob    = data.get('ml_probability', 0)

            status = hitung_status(gt, verdict)
            data['ground_truth']    = gt_lbl
            data['status_evaluasi'] = status

            skenario_data[sken].append(data)
            y_true_all.append(gt)
            y_probs_all.append(prob)

    # ── 3. Tampilkan distribusi per skenario ─────────────────────────────────
    print(f"\n{'Skenario':<25} {'File Unik':>10} {'TP':>5} {'TN':>5} {'FP':>5} {'FN':>5}")
    print("-" * 55)
    for sken, lst in skenario_data.items():
        TP = sum(1 for d in lst if d['status_evaluasi'] == 'TP')
        TN = sum(1 for d in lst if d['status_evaluasi'] == 'TN')
        FP = sum(1 for d in lst if d['status_evaluasi'] == 'FP')
        FN = sum(1 for d in lst if d['status_evaluasi'] == 'FN')
        print(f"{sken:<25} {len(lst):>10} {TP:>5} {TN:>5} {FP:>5} {FN:>5}")

    # ── 4. Output CSV detail per skenario ────────────────────────────────────
    print("\n[INFO] Menyimpan CSV detail per skenario...")
    cols_drop = ['_skenario', '_gt', '_gt_label', '_fname']
    for nama_skenario, list_data in skenario_data.items():
        if not list_data:
            continue
        df = pd.DataFrame(list_data)
        df = df.drop(columns=[c for c in cols_drop if c in df.columns], errors='ignore')
        df.to_csv(f"hasil_detail_{nama_skenario}.csv", index=False)

    # ── 5. Rangkuman metrik ───────────────────────────────────────────────────
    rangkuman_list = []
    total_TP = total_TN = total_FP = total_FN = 0

    for nama_skenario, list_data in skenario_data.items():
        if not list_data:
            continue
        TP, TN, FP, FN, row = build_rangkuman_row(nama_skenario, list_data)
        rangkuman_list.append(row)
        total_TP += TP; total_TN += TN; total_FP += FP; total_FN += FN

    # Baris OVERALL
    total, acc, pre, rec, f1, fpr, fnr = hitung_metrik(total_TP, total_TN, total_FP, total_FN)
    all_data = [d for lst in skenario_data.values() for d in lst]
    lat_min, lat_max, lat_avg, lat_med = hitung_latensi(all_data)
    rangkuman_list.append({
        "Skenario":       "KESELURUHAN (OVERALL)",
        "Total_Data":     total,
        "TP": total_TP, "TN": total_TN, "FP": total_FP, "FN": total_FN,
        "Akurasi (%)":    round(acc*100, 2),
        "Presisi (%)":    round(pre*100, 2),
        "Recall (%)":     round(rec*100, 2),
        "F1_Score":       round(f1, 4),
        "FPR":            round(fpr, 4),
        "FNR":            round(fnr, 4),
        "Latensi_Min_ms": lat_min,
        "Latensi_Max_ms": lat_max,
        "Latensi_Avg_ms": lat_avg,
        "Latensi_Med_ms": lat_med,
    })

    df_rangkuman = pd.DataFrame(rangkuman_list)
    df_rangkuman.to_csv(FILE_RANGKUMAN, index=False)

    # ── 6. Tampilkan di terminal ──────────────────────────────────────────────
    print("\n" + "=" * 80)
    print(" RANGKUMAN METRIK EVALUASI (berpath unik, deduplikasi blok terpanjang)")
    print("=" * 80)
    print(df_rangkuman.to_string(index=False))
    print("\n" + "=" * 80)
    print(f"[SUCCESS] {FILE_RANGKUMAN} disimpan")

    # ── 7. Grafik kurva ───────────────────────────────────────────────────────
    plot_curves(y_true_all, y_probs_all)

if __name__ == "__main__":
    main()