from __future__ import annotations

import argparse
import math
import re
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)


# ============================================================
# UTILITAS DASAR
# ============================================================

def norm_path(value: object) -> str:
    """Normalisasi path Windows agar perbandingan konsisten."""
    s = str(value).strip().strip('"').replace("/", "\\")
    s = re.sub(r"\\+", r"\\", s)
    return s.casefold()


def infer_actual_label(path: str) -> int:
    p = norm_path(path)
    if "\\benign\\" in p:
        return 0
    if "\\malicious\\" in p:
        return 1
    raise ValueError(f"Label aktual tidak dapat ditentukan dari path: {path}")


def infer_scenario(path: str) -> str:
    p = norm_path(path)

    if "\\test_set\\benign\\" in p:
        return "Benign"
    if "\\test_set\\malicious\\" in p and "test_set_obf" not in p:
        return "Original Malicious"
    if "\\test_set_obf\\ascii_encoding\\malicious\\" in p:
        return "ASCII Encoding"
    if "\\test_set_obf\\string_concatenation\\malicious\\" in p:
        return "String Concatenation"
    if "\\test_set_obf\\string_reordering\\malicious\\" in p:
        return "String Reordering"
    if "\\test_set_obf\\token_manipulation\\malicious\\" in p:
        return "Token Manipulation"

    return "Tidak Dikenali"


def safe_div(num: float, den: float) -> float:
    return math.nan if den == 0 else num / den


def read_jsonl(path: Path) -> pd.DataFrame:
    df = pd.read_json(path, lines=True)

    required = {"script_path", "ml_probability", "ml_verdict"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(
            f"{path.name} tidak memiliki kolom: {', '.join(sorted(missing))}"
        )

    df["_path_key"] = df["script_path"].map(norm_path)
    df["ml_probability"] = pd.to_numeric(
        df["ml_probability"], errors="coerce"
    )
    return df


def natural_key(path: Path):
    """Agar file ...1, ...2, ...10 diurutkan secara numerik."""
    parts = re.split(r"(\d+)", path.name)
    return [int(p) if p.isdigit() else p.casefold() for p in parts]


# ============================================================
# METRIK
# ============================================================

def calculate_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_score: np.ndarray,
) -> dict[str, float | int]:
    tn, fp, fn, tp = confusion_matrix(
        y_true, y_pred, labels=[0, 1]
    ).ravel()

    specificity = safe_div(tn, tn + fp)
    fpr = safe_div(fp, fp + tn)
    fnr = safe_div(fn, fn + tp)
    npv = safe_div(tn, tn + fn)

    return {
        "N": int(len(y_true)),
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "TP": int(tp),
        "Accuracy": float(accuracy_score(y_true, y_pred)),
        "Precision": float(
            precision_score(y_true, y_pred, zero_division=0)
        ),
        "Recall": float(
            recall_score(y_true, y_pred, zero_division=0)
        ),
        "Specificity": float(specificity),
        "F1_Score": float(
            f1_score(y_true, y_pred, zero_division=0)
        ),
        "FPR": float(fpr),
        "FNR": float(fnr),
        "NPV": float(npv),
        "Balanced_Accuracy": float(
            balanced_accuracy_score(y_true, y_pred)
        ),
        "MCC": float(matthews_corrcoef(y_true, y_pred)),
        "ROC_AUC": float(roc_auc_score(y_true, y_score)),
        "PR_AUC": float(
            average_precision_score(y_true, y_score)
        ),
    }


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluasi fixed test set 582 untuk 5 percobaan, "
            "dengan detail TP/TN/FP/FN per skrip dan analisis konsistensi."
        )
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        required=True,
        help="Folder 'log bersih' berisi 5 JSONL hasil ML.",
    )
    parser.add_argument(
        "--test-list",
        type=Path,
        required=True,
        help="TXT berisi tepat 582 path fixed test set.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Folder output.",
    )
    parser.add_argument(
        "--pattern",
        default="04_ml_alert_berhasil_dicocokkan*.jsonl",
        help="Pola file JSONL.",
    )
    parser.add_argument(
        "--trial-labels",
        nargs=5,
        default=["11", "12", "13", "14", "15"],
        help="Label lima percobaan.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Threshold malicious. Default: 0.5",
    )
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    # --------------------------------------------------------
    # 1. Baca fixed test set 582
    # --------------------------------------------------------
    test_paths = [
        line.strip()
        for line in args.test_list.read_text(
            encoding="utf-8-sig"
        ).splitlines()
        if line.strip()
    ]

    if len(test_paths) != 582:
        raise ValueError(
            f"Daftar uji harus tepat 582 baris. Ditemukan: {len(test_paths)}"
        )

    test_keys = [norm_path(p) for p in test_paths]
    if len(set(test_keys)) != 582:
        raise ValueError("Daftar uji memiliki path duplikat.")

    fixed = pd.DataFrame({
        "script_path": test_paths,
        "_path_key": test_keys,
    })
    fixed["actual_label"] = fixed["script_path"].map(infer_actual_label)
    fixed["actual_class"] = fixed["actual_label"].map(
        {0: "benign", 1: "malicious"}
    )
    fixed["scenario"] = fixed["script_path"].map(infer_scenario)

    distribution = (
        fixed.groupby(["scenario", "actual_class"], as_index=False)
        .size()
        .rename(columns={"size": "jumlah"})
    )
    distribution.to_csv(
        args.output_dir / "00_distribusi_fixed_582.csv",
        index=False,
        encoding="utf-8-sig",
    )

    # --------------------------------------------------------
    # 2. Temukan lima file log
    # --------------------------------------------------------
    files = sorted(
        args.input_dir.glob(args.pattern),
        key=natural_key,
    )

    if len(files) != 5:
        raise ValueError(
            f"Harus ada tepat 5 file log bersih. Ditemukan: {len(files)}"
        )

    print("Urutan file -> percobaan:")
    for trial, file_path in zip(args.trial_labels, files):
        print(f"  Trial {trial}: {file_path.name}")

    metrics_rows = []
    detail_frames = []

    # --------------------------------------------------------
    # 3. Evaluasi per percobaan
    # --------------------------------------------------------
    for trial, file_path in zip(args.trial_labels, files):
        trial_dir = args.output_dir / f"percobaan_{trial}"
        trial_dir.mkdir(parents=True, exist_ok=True)

        log = read_jsonl(file_path)

        # Hanya data yang memang ada pada fixed set 582.
        log = log[
            log["_path_key"].isin(set(test_keys))
        ].copy()

        # Satu skrip bisa punya lebih dari satu Script Block.
        # Keputusan skrip menggunakan probabilitas maksimum.
        per_script = (
            log.groupby("_path_key", as_index=False)
            .agg(
                observed_path=("script_path", "first"),
                max_probability=("ml_probability", "max"),
                mean_probability=("ml_probability", "mean"),
                min_probability=("ml_probability", "min"),
                alert_count=("script_path", "size"),
                verdicts=(
                    "ml_verdict",
                    lambda s: ", ".join(
                        dict.fromkeys(
                            str(x) for x in s.dropna()
                        )
                    ),
                ),
            )
        )

        # Left join: semua 582 file tetap berada di tabel.
        result = fixed.merge(
            per_script,
            on="_path_key",
            how="left",
            validate="one_to_one",
        )

        result["has_ml_output"] = result[
            "max_probability"
        ].notna()

        # Evaluasi sistem end-to-end:
        # tidak ada output ML = tidak terdeteksi = prediksi benign.
        result["score_for_eval"] = (
            result["max_probability"].fillna(0.0)
        )
        result["predicted_label"] = (
            result["score_for_eval"] >= args.threshold
        ).astype(int)

        result["predicted_class"] = result[
            "predicted_label"
        ].map({0: "benign", 1: "malicious"})

        result["confusion_result"] = np.select(
            [
                (result["actual_label"] == 1)
                & (result["predicted_label"] == 1),
                (result["actual_label"] == 0)
                & (result["predicted_label"] == 0),
                (result["actual_label"] == 0)
                & (result["predicted_label"] == 1),
                (result["actual_label"] == 1)
                & (result["predicted_label"] == 0),
            ],
            ["TP", "TN", "FP", "FN"],
            default="UNKNOWN",
        )

        result["correct"] = (
            result["actual_label"] == result["predicted_label"]
        )

        result.insert(0, "Percobaan", trial)

        # Metrik keseluruhan trial.
        y_true = result["actual_label"].to_numpy(dtype=int)
        y_pred = result["predicted_label"].to_numpy(dtype=int)
        y_score = result["score_for_eval"].to_numpy(dtype=float)

        metric = {
            "Percobaan": trial,
            "File": file_path.name,
            "Fixed_Test_Set": 582,
            "Dengan_Output_ML": int(result["has_ml_output"].sum()),
            "Tanpa_Output_ML": int((~result["has_ml_output"]).sum()),
            "Coverage_ML": float(result["has_ml_output"].mean()),
        }
        metric.update(calculate_metrics(y_true, y_pred, y_score))
        metrics_rows.append(metric)

        # ----------------------------------------------------
        # 4. Output per percobaan
        # ----------------------------------------------------
        preferred_cols = [
            "Percobaan",
            "script_path",
            "scenario",
            "actual_class",
            "predicted_class",
            "confusion_result",
            "correct",
            "has_ml_output",
            "score_for_eval",
            "max_probability",
            "mean_probability",
            "min_probability",
            "alert_count",
            "verdicts",
            "observed_path",
        ]

        result[preferred_cols].to_csv(
            trial_dir / "01_detail_582_semua_skrip.csv",
            index=False,
            encoding="utf-8-sig",
        )

        # Pisahkan per kategori confusion matrix.
        result[result["confusion_result"] == "TP"][
            preferred_cols
        ].to_csv(
            trial_dir / "02_TP_true_positive.csv",
            index=False,
            encoding="utf-8-sig",
        )

        result[result["confusion_result"] == "TN"][
            preferred_cols
        ].to_csv(
            trial_dir / "03_TN_true_negative.csv",
            index=False,
            encoding="utf-8-sig",
        )

        result[result["confusion_result"] == "FP"][
            preferred_cols
        ].to_csv(
            trial_dir / "04_FP_false_positive.csv",
            index=False,
            encoding="utf-8-sig",
        )

        result[result["confusion_result"] == "FN"][
            preferred_cols
        ].to_csv(
            trial_dir / "05_FN_false_negative.csv",
            index=False,
            encoding="utf-8-sig",
        )

        result[~result["has_ml_output"]][
            preferred_cols
        ].to_csv(
            trial_dir / "06_tanpa_output_ml.csv",
            index=False,
            encoding="utf-8-sig",
        )

        pd.DataFrame([metric]).to_csv(
            trial_dir / "07_metrik_percobaan.csv",
            index=False,
            encoding="utf-8-sig",
        )

        # Ringkasan jumlah TP/TN/FP/FN per skenario.
        scenario_cm = (
            result.groupby(
                ["scenario", "confusion_result"],
                as_index=False,
            )
            .size()
            .rename(columns={"size": "jumlah"})
        )
        scenario_cm.to_csv(
            trial_dir / "08_confusion_matrix_per_skenario.csv",
            index=False,
            encoding="utf-8-sig",
        )

        detail_frames.append(result)

    # --------------------------------------------------------
    # 5. Ringkasan 5 percobaan
    # --------------------------------------------------------
    metrics_df = pd.DataFrame(metrics_rows)
    metrics_df.to_csv(
        args.output_dir / "01_metrik_5_percobaan.csv",
        index=False,
        encoding="utf-8-sig",
    )

    metric_columns = [
        "Coverage_ML",
        "Accuracy",
        "Precision",
        "Recall",
        "Specificity",
        "F1_Score",
        "FPR",
        "FNR",
        "NPV",
        "Balanced_Accuracy",
        "MCC",
        "ROC_AUC",
        "PR_AUC",
    ]

    average_rows = []
    for metric_name in metric_columns:
        values = metrics_df[metric_name]
        average_rows.append({
            "Metric": metric_name,
            "Mean": float(values.mean()),
            "Std_Dev": float(values.std(ddof=1)),
            "Min": float(values.min()),
            "Max": float(values.max()),
        })

    pd.DataFrame(average_rows).to_csv(
        args.output_dir / "02_rata_rata_5_percobaan.csv",
        index=False,
        encoding="utf-8-sig",
    )

    all_detail = pd.concat(
        detail_frames,
        ignore_index=True,
        sort=False,
    )

    all_detail.to_csv(
        args.output_dir / "03_detail_582_x_5_percobaan.csv",
        index=False,
        encoding="utf-8-sig",
    )

    # --------------------------------------------------------
    # 6. Analisis konsistensi per skrip antar percobaan
    # --------------------------------------------------------
    consistency_rows = []

    for path_key, group in all_detail.groupby("_path_key"):
        group = group.sort_values("Percobaan")

        predictions = group["predicted_class"].tolist()
        confusion = group["confusion_result"].tolist()
        scores = group["score_for_eval"].tolist()
        outputs = group["has_ml_output"].tolist()

        unique_predictions = set(predictions)
        unique_confusion = set(confusion)
        unique_outputs = set(outputs)

        consistency_rows.append({
            "script_path": group["script_path"].iloc[0],
            "scenario": group["scenario"].iloc[0],
            "actual_class": group["actual_class"].iloc[0],

            "Pred_11": predictions[0],
            "Pred_12": predictions[1],
            "Pred_13": predictions[2],
            "Pred_14": predictions[3],
            "Pred_15": predictions[4],

            "CM_11": confusion[0],
            "CM_12": confusion[1],
            "CM_13": confusion[2],
            "CM_14": confusion[3],
            "CM_15": confusion[4],

            "Score_11": scores[0],
            "Score_12": scores[1],
            "Score_13": scores[2],
            "Score_14": scores[3],
            "Score_15": scores[4],

            "OutputML_11": outputs[0],
            "OutputML_12": outputs[1],
            "OutputML_13": outputs[2],
            "OutputML_14": outputs[3],
            "OutputML_15": outputs[4],

            "Prediksi_Konsisten": len(unique_predictions) == 1,
            "Confusion_Konsisten": len(unique_confusion) == 1,
            "OutputML_Konsisten": len(unique_outputs) == 1,

            "Jumlah_Prediksi_Malicious": predictions.count("malicious"),
            "Jumlah_Prediksi_Benign": predictions.count("benign"),

            "Score_Mean": float(np.mean(scores)),
            "Score_Std": float(np.std(scores, ddof=1)),
            "Score_Min": float(np.min(scores)),
            "Score_Max": float(np.max(scores)),
        })

    consistency_df = pd.DataFrame(consistency_rows)

    consistency_df.to_csv(
        args.output_dir / "04_analisis_konsistensi_per_skrip.csv",
        index=False,
        encoding="utf-8-sig",
    )

    inconsistent_prediction = consistency_df[
        ~consistency_df["Prediksi_Konsisten"]
    ].copy()

    inconsistent_prediction.to_csv(
        args.output_dir / "05_skrip_prediksi_tidak_konsisten.csv",
        index=False,
        encoding="utf-8-sig",
    )

    inconsistent_output = consistency_df[
        ~consistency_df["OutputML_Konsisten"]
    ].copy()

    inconsistent_output.to_csv(
        args.output_dir / "06_skrip_output_ml_tidak_konsisten.csv",
        index=False,
        encoding="utf-8-sig",
    )

    # --------------------------------------------------------
    # 7. Ringkasan perubahan confusion matrix per skrip
    # --------------------------------------------------------
    transition_rows = []

    for _, row in consistency_df.iterrows():
        cm_sequence = [
            row["CM_11"],
            row["CM_12"],
            row["CM_13"],
            row["CM_14"],
            row["CM_15"],
        ]

        transition_rows.append({
            "script_path": row["script_path"],
            "scenario": row["scenario"],
            "actual_class": row["actual_class"],
            "Urutan_CM": " -> ".join(cm_sequence),
            "Berubah_CM": len(set(cm_sequence)) > 1,
            "Jumlah_Perubahan": sum(
                cm_sequence[i] != cm_sequence[i - 1]
                for i in range(1, len(cm_sequence))
            ),
        })

    transition_df = pd.DataFrame(transition_rows)

    transition_df[
        transition_df["Berubah_CM"]
    ].to_csv(
        args.output_dir / "07_skrip_confusion_matrix_berubah.csv",
        index=False,
        encoding="utf-8-sig",
    )

    # --------------------------------------------------------
    # 8. Ringkasan teks
    # --------------------------------------------------------
    lines = [
        "RINGKASAN EVALUASI FIXED 582 - 5 PERCOBAAN",
        "",
        "Setiap percobaan dievaluasi pada 582 path yang sama.",
        f"Threshold malicious: {args.threshold}",
        "",
        "File input:",
    ]

    for trial, file_path in zip(args.trial_labels, files):
        lines.append(f"- Trial {trial}: {file_path.name}")

    lines.extend([
        "",
        "Metrik:",
    ])

    for _, r in metrics_df.iterrows():
        lines.append(
            f"- Trial {r['Percobaan']}: "
            f"TP={r['TP']}, TN={r['TN']}, FP={r['FP']}, FN={r['FN']}, "
            f"Accuracy={r['Accuracy']:.6f}, "
            f"Precision={r['Precision']:.6f}, "
            f"Recall={r['Recall']:.6f}, "
            f"F1={r['F1_Score']:.6f}"
        )

    lines.extend([
        "",
        f"Skrip dengan prediksi tidak konsisten: {len(inconsistent_prediction)}",
        f"Skrip dengan ketersediaan output ML tidak konsisten: {len(inconsistent_output)}",
        f"Skrip dengan kategori confusion matrix berubah: "
        f"{int(transition_df['Berubah_CM'].sum())}",
    ])

    (
        args.output_dir / "08_ringkasan.txt"
    ).write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    # --------------------------------------------------------
    # Console
    # --------------------------------------------------------
    print("\nMetrik per percobaan:")
    print(
        metrics_df[
            [
                "Percobaan",
                "Dengan_Output_ML",
                "Tanpa_Output_ML",
                "TN", "FP", "FN", "TP",
                "Accuracy",
                "Precision",
                "Recall",
                "F1_Score",
            ]
        ].to_string(index=False)
    )

    print(
        f"\nPrediksi tidak konsisten antar percobaan: "
        f"{len(inconsistent_prediction)} skrip"
    )
    print(
        f"Output ML tidak konsisten antar percobaan: "
        f"{len(inconsistent_output)} skrip"
    )
    print(
        f"Kategori TP/TN/FP/FN berubah antar percobaan: "
        f"{int(transition_df['Berubah_CM'].sum())} skrip"
    )

    if len(inconsistent_prediction) > 0:
        print("\nContoh skrip dengan prediksi tidak konsisten:")
        print(
            inconsistent_prediction[
                [
                    "script_path",
                    "actual_class",
                    "Pred_11",
                    "Pred_12",
                    "Pred_13",
                    "Pred_14",
                    "Pred_15",
                ]
            ].head(20).to_string(index=False)
        )


if __name__ == "__main__":
    main()
