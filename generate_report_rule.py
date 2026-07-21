"""
Generator Log & Report Evaluasi Rule-Based Wazuh (Event ID 4104)
Menangani fragmentasi skrip, menyamakan format JSON dengan ML, dan membuat laporan CSV per skenario.
"""

import json
import os
import csv
from datetime import datetime

# =====================================================================
# KONFIGURASI PATH & THRESHOLD
# =====================================================================
SOURCE_LOG = "log/alerts.json"
OUTPUT_JSON = "log/custom_rule_alerts.json"
REPORT_DIR = "reports_rule_based"

# Threshold Rule-Based: Level 6 ke atas = Malicious
MALICIOUS_THRESHOLD = 6
# =====================================================================

def get_scenario_and_label(path):
    """Menentukan Skenario dan True Label berdasarkan Path file .ps1"""
    path_lower = path.lower()
    
    if "benign" in path_lower:
        return "Benign", "Benign"
    elif "ascii_encoding" in path_lower:
        return "ASCII_Encoding", "Malicious"
    elif "string_concatenation" in path_lower:
        return "String_Concatenation", "Malicious"
    elif "string_reordering" in path_lower:
        return "String_Reordering", "Malicious"
    elif "token_manipulation" in path_lower:
        return "Token_Manipulation", "Malicious"
    elif "malicious" in path_lower:
        return "Malicious_Standard", "Malicious"
    else:
        return "Unknown", "Unknown"

def evaluate_prediction(true_label, predicted_label):
    """Menentukan TP, TN, FP, FN"""
    if true_label == "Malicious" and predicted_label == "Malicious":
        return "TP"
    elif true_label == "Benign" and predicted_label == "Benign":
        return "TN"
    elif true_label == "Benign" and predicted_label == "Malicious":
        return "FP"
    elif true_label == "Malicious" and predicted_label == "Benign":
        return "FN"
    return "Unknown"

def process_and_generate_report():
    print(f"[*] Membaca log mentah Wazuh: {SOURCE_LOG}")
    
    if not os.path.exists(SOURCE_LOG):
        print(f"[ERROR] File log tidak ditemukan: {SOURCE_LOG}")
        return

    # Pastikan folder report tersedia
    if not os.path.exists(REPORT_DIR):
        os.makedirs(REPORT_DIR)

    script_blocks = {}
    
    # ---------------------------------------------------------
    # FASE 1: PEMBACAAN LOG & PENANGANAN FRAGMENTASI
    # ---------------------------------------------------------
    with open(SOURCE_LOG, 'r', encoding='utf-8') as f_in:
        for line in f_in:
            if not line.strip(): continue
            try:
                alert = json.loads(line)
                win_data = alert.get("data", {}).get("win", {})
                system_data = win_data.get("system", {})
                event_id = str(system_data.get("eventID", system_data.get("eventid", "")))

                if event_id == "4104":
                    ev_data = win_data.get("eventdata", {})
                    script_id = ev_data.get("ScriptBlockId", ev_data.get("scriptBlockId", "Unknown"))
                    msg_num = int(ev_data.get("MessageNumber", ev_data.get("messageNumber", 1)))
                    msg_total = int(ev_data.get("MessageTotal", ev_data.get("messageTotal", 1)))
                    script_path = ev_data.get("Path", ev_data.get("path", "In-Memory"))
                    script_text = ev_data.get("ScriptBlockText", ev_data.get("scriptBlockText", ""))
                    
                    rule_obj = alert.get("rule", {})
                    rule_level = int(rule_obj.get("level", 0))
                    rule_id = str(rule_obj.get("id", ""))
                    rule_desc = rule_obj.get("description", "")
                    
                    if script_id not in script_blocks:
                        script_blocks[script_id] = {
                            "timestamp": alert.get("timestamp", ""),
                            "unique_id": alert.get("id", ""),
                            "agent_name": alert.get("agent", {}).get("name", "Unknown"),
                            "script_path": script_path,
                            "msg_total": msg_total,
                            "max_rule_level": rule_level,
                            "best_rule_info": f"Rule {rule_id}: {rule_desc}",
                            "parts": {}
                        }
                    
                    # Update rule level jika ada yang lebih tinggi di fragment lain
                    if rule_level > script_blocks[script_id]["max_rule_level"]:
                        script_blocks[script_id]["max_rule_level"] = rule_level
                        script_blocks[script_id]["best_rule_info"] = f"Rule {rule_id}: {rule_desc}"
                        
                    script_blocks[script_id]["parts"][msg_num] = script_text
            except Exception:
                continue

    # ---------------------------------------------------------
    # FASE 2: EVALUASI, PENULISAN JSON & CSV PER SKENARIO
    # ---------------------------------------------------------
    scenario_data = {
        "Benign": [], "Malicious_Standard": [], "ASCII_Encoding": [],
        "String_Concatenation": [], "String_Reordering": [], "Token_Manipulation": []
    }
    
    summary_metrics = {}
    json_count = 0

    with open(OUTPUT_JSON, 'w', encoding='utf-8') as f_json:
        for script_id, data in script_blocks.items():
            # Merakit ulang teks skrip
            full_text = "".join(data["parts"].get(i, "") for i in range(1, data["msg_total"] + 1))
            
            # Evaluasi Logika
            verdict = "Malicious" if data["max_rule_level"] >= MALICIOUS_THRESHOLD else "Benign"
            scenario, true_label = get_scenario_and_label(data["script_path"])
            status = evaluate_prediction(true_label, verdict)
            
            # Format JSON (Sama persis dengan ML)
            json_log = {
                "rule_scan_time"  : data["timestamp"],
                "script_path"     : data["script_path"],
                "integration"     : "wazuh-default-rules",
                "unique_id"       : data["unique_id"],
                "script_block_id" : script_id,
                "agent_name"      : data["agent_name"],
                "rule_verdict"    : verdict,
                "rule_level"      : data["max_rule_level"],
                "rule_info"       : data["best_rule_info"],
                "script_length"   : len(full_text),
                "is_fragmented"   : data["msg_total"] > 1,
                "latency_ms"      : 0.0,
                "script_content"  : full_text
            }
            f_json.write(json.dumps(json_log) + "\n")
            json_count += 1
            
            # Simpan data ke memori untuk laporan CSV
            if scenario in scenario_data:
                scenario_data[scenario].append([
                    data["timestamp"], script_id, data["script_path"], 
                    data["max_rule_level"], verdict, true_label, status, data["best_rule_info"]
                ])

    # ---------------------------------------------------------
    # FASE 3: CETAK FILE CSV
    # ---------------------------------------------------------
    csv_headers = ["Timestamp", "ScriptBlockId", "Script_Path", "Max_Rule_Level", "Wazuh_Verdict", "True_Label", "Status_Evaluasi", "Rule_Info"]
    
    print(f"\n[*] Membuat laporan CSV di dalam folder: {REPORT_DIR}")
    
    # Cetak CSV per Skenario dan hitung matrix
    for scenario, rows in scenario_data.items():
        if not rows: continue
        
        tp = sum(1 for r in rows if r[6] == "TP")
        tn = sum(1 for r in rows if r[6] == "TN")
        fp = sum(1 for r in rows if r[6] == "FP")
        fn = sum(1 for r in rows if r[6] == "FN")
        total = tp + tn + fp + fn
        
        accuracy = ((tp + tn) / total * 100) if total > 0 else 0.0
        
        summary_metrics[scenario] = {
            "Total_Data": total, "TP": tp, "TN": tn, "FP": fp, "FN": fn, "Accuracy": round(accuracy, 2)
        }
        
        csv_file = os.path.join(REPORT_DIR, f"report_rule_{scenario}.csv")
        with open(csv_file, 'w', newline='', encoding='utf-8') as f_csv:
            writer = csv.writer(f_csv)
            writer.writerow(csv_headers)
            writer.writerows(rows)
            
    # Cetak Rangkuman (Summary)
    summary_file = os.path.join(REPORT_DIR, "summary_rule_based.csv")
    with open(summary_file, 'w', newline='', encoding='utf-8') as f_sum:
        writer = csv.writer(f_sum)
        writer.writerow(["Skenario", "Total_Data", "TP", "TN", "FP", "FN", "Accuracy_Percent"])
        for scenario, metrics in summary_metrics.items():
            writer.writerow([
                scenario, metrics["Total_Data"], metrics["TP"], metrics["TN"], 
                metrics["FP"], metrics["FN"], metrics["Accuracy"]
            ])

    print("\n[====== HASIL EKSEKUSI ======]")
    print(f"1. Flat JSON ML-Style    : {OUTPUT_JSON} ({json_count} skrip)")
    print(f"2. CSV Detail Skenario   : {REPORT_DIR}/report_rule_[skenario].csv")
    print(f"3. CSV Ringkasan Matriks : {summary_file}")
    print("[==============================] \n")

if __name__ == "__main__":
    process_and_generate_report()