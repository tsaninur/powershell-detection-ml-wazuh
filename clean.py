import os
import re
import shutil
import hashlib
from datetime import datetime
from pathlib import Path

# Ekstensi dan urutan encoding sesuai standar pembacaan
ENCODING_ORDER = ["utf-8", "utf-16", "cp1252", "latin-1"]

def read_file_multi_encoding(file_path: Path) -> str:
    """Membaca berkas dengan penanganan multi-encoding otomatis."""
    for enc in ENCODING_ORDER:
        try:
            return file_path.read_text(encoding=enc)
        except (UnicodeDecodeError, OSError):
            continue
    return ""

def buat_folder_output(folder_path: Path):
    """Membuat folder output jika belum ada."""
    if not folder_path.exists():
        folder_path.mkdir(parents=True, exist_ok=True)
        print(f"[+] Folder dibuat: {folder_path.resolve()}")

def jalankan_pembersihan_dan_salin(folder_sumber, folder_tujuan, file_output_txt):
    print("=" * 85)
    print("      EKSEKUSI PEMBERSIHAN DAN PENYALINAN DATASET POWERSHELL (PREPARATION)     ")
    print("=" * 85)

    # Inisialisasi statistik global
    stats = {
        "malicious": {"awal": 0, "kosong": 0, "komentar": 0, "noise": 0, "duplikat": 0, "bersih": 0},
        "benign": {"awal": 0, "kosong": 0, "komentar": 0, "noise": 0, "duplikat": 0, "bersih": 0}
    }

    # Variabel seen_hashes bersifat GLOBAL untuk mencegah kebocoran data antar kelas.
    # Jika ada skrip di 'benign' yang isinya sama persis dengan 'malicious', 
    # skrip tersebut akan langsung dibuang sebagai duplikat.
    seen_hashes = {}
    log_eliminasi_lines = []

    # Looping untuk memproses setiap folder sumber
    for folder_str in folder_sumber:
        source_path = Path(folder_str)
        if not source_path.exists():
            print(f"[!] Folder sumber {folder_str} tidak ditemukan, dilewati.")
            continue

        kategori = "malicious" if "malicious" in source_path.name.lower() else "benign"
        target_folder = Path(folder_tujuan) / kategori
        buat_folder_output(target_folder)
        
        print(f"[*] Memindai dan memfilter berkas dari: {source_path.resolve()}")
        files = sorted(list(source_path.glob("*.ps1")))
        stats[kategori]["awal"] = len(files)

        for file_path in files:
            raw_content = read_file_multi_encoding(file_path)
            display_name = f"{source_path.name}/{file_path.name}"
            waktu_sekarang = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # --- VALIDASI 1: Pembersihan Null Bytes ---
            # Menghapus karakter \x00 yang sering dipakai malware untuk padding
            raw_content_safe = raw_content.replace('\x00', '')

            # Kriteria 1: Berkas Kosong Murni
            if not raw_content_safe.strip():
                log_line = f"[{waktu_sekarang}] [DIELIMINASI] -> {display_name:<30} | Alasan: Berkas Kosong Murni / Null Bytes"
                print(log_line)
                log_eliminasi_lines.append(log_line)
                stats[kategori]["kosong"] += 1
                continue

            # --- VALIDASI 2: Proses Pembersihan Komentar (Mempertahankan Baris Baru) ---
            content_no_comment = re.sub(r'#.*$', '', raw_content_safe, flags=re.MULTILINE)
            content_no_comment = re.sub(r'<#.*?#>', '', content_no_comment, flags=re.DOTALL)
            
            baris_bersih = [baris.strip() for baris in content_no_comment.splitlines() if baris.strip()]
            # Konversi ke satu baris tunggal dengan separator titik koma
            # agar konsisten dengan format Script Block Logging
            cleaned_content = "; ".join(baris_bersih)

            # Kriteria 2: Hanya Komentar (Setelah dibersihkan ternyata isinya kosong)
            if not cleaned_content:
                log_line = f"[{waktu_sekarang}] [DIELIMINASI] -> {display_name:<30} | Alasan: Hanya Berisi Teks Komentar"
                print(log_line)
                log_eliminasi_lines.append(log_line)
                stats[kategori]["komentar"] += 1
                continue

            # Kriteria 3: Noise / Terlalu Pendek (Misal cuma berisi huruf "A")
            if len(cleaned_content) <= 3:
                log_line = f"[{waktu_sekarang}] [DIELIMINASI] -> {display_name:<30} | Alasan: Noise / Terlalu Pendek (Isi: '{cleaned_content}')"
                print(log_line)
                log_eliminasi_lines.append(log_line)
                stats[kategori]["noise"] += 1
                continue

            # --- VALIDASI 3: Pengecekan Duplikasi Silang (Hash MD5) ---
            # Diubah menjadi lowercase agar perbedaan huruf besar/kecil tidak dianggap sebagai file baru
            content_lower = cleaned_content.lower()
            content_hash = hashlib.md5(content_lower.encode('utf-8')).hexdigest()

            if content_hash in seen_hashes:
                log_line = f"[{waktu_sekarang}] [DIELIMINASI] -> {display_name:<30} | Alasan: Duplikat (Identik dg {seen_hashes[content_hash]})"
                print(log_line)
                log_eliminasi_lines.append(log_line)
                stats[kategori]["duplikat"] += 1
                continue
            else:
                # --- VALIDASI 4: Atomic Write (Penyimpanan Aman) ---
                output_file_path = target_folder / file_path.name
                try:
                    # Tulis file ke disk
                    output_file_path.write_text(cleaned_content, encoding="utf-8")
                    
                    # [PENTING] Hanya daftarkan hash dan hitung 'bersih' JIKA penulisan BERHASIL
                    seen_hashes[content_hash] = display_name
                    stats[kategori]["bersih"] += 1
                    
                except Exception as e:
                    # Jika gagal (misal diblokir antivirus), catat di terminal, tapi JANGAN hitung sebagai dataset bersih
                    log_line = f"[{waktu_sekarang}] [GAGAL TULIS] -> {display_name:<30} | Alasan: Error System / Diblokir OS -> {e}"
                    print(log_line)
                    log_eliminasi_lines.append(log_line)
                    # File ini diabaikan dan tidak masuk statistik 'bersih'

        print("-" * 85)

    m_tereliminasi = stats["malicious"]["kosong"] + stats["malicious"]["komentar"] + stats["malicious"]["noise"] + stats["malicious"]["duplikat"]
    b_tereliminasi = stats["benign"]["kosong"] + stats["benign"]["komentar"] + stats["benign"]["noise"] + stats["benign"]["duplikat"]
    total_awal_all = stats["malicious"]["awal"] + stats["benign"]["awal"]
    total_bersih_all = stats["malicious"]["bersih"] + stats["benign"]["bersih"]
    total_eliminasi_all = m_tereliminasi + b_tereliminasi

    waktu_selesai = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Cetak Ringkasan
    print("\n" + "=" * 85)
    print("                REKAPITULASI GABUNGAN HASIL PEMBERSIHAN & PENYALINAN         ")
    print("=" * 85)
    print(f" TOTAL BERKAS MENTAH (SUMBER) : {total_awal_all} Berkas [Malicious: {stats['malicious']['awal']} | Benign: {stats['benign']['awal']}]")
    print(f" TOTAL ELIMINASI (NOISE)      : {total_eliminasi_all} Berkas")
    print(f" TOTAL BERKAS BERSIH (OUTPUT) : {total_bersih_all} Berkas [Malicious: {stats['malicious']['bersih']} | Benign: {stats['benign']['bersih']}]")
    print(f" FOLDER OUTPUT                : {Path(folder_tujuan).resolve()}")
    print(f" WAKTU SELESAI EKSEKUSI       : {waktu_selesai}")
    print("================================================================================")

    # --------------------------------------------------------------------------------
    # PROSES EKSPOR HASIL KE FILE .TXT (LAPORAN AUDIT)
    # --------------------------------------------------------------------------------
    with open(file_output_txt, "w", encoding="utf-8") as f:
        f.write("=================================================================================\n")
        f.write("         LAPORAN RIWAYAT DAN REKAPITULASI PEMBERSIHAN DATASET (DATA PREPARATION) \n")
        f.write(f"         WAKTU EKSEKUSI: {waktu_selesai}\n")
        f.write("=================================================================================\n\n")
        
        f.write("--- 1. RINGKASAN PERBANDINGAN SEBELUM DAN SESUDAH PEMBERSIHAN ---\n")
        f.write(f" * KATEGORI MALICIOUS :\n")
        f.write(f"   - Jumlah Sumber (Mentah)            : {stats['malicious']['awal']} Berkas\n")
        f.write(f"   - Jumlah Output (Bersih)            : {stats['malicious']['bersih']} Berkas\n")
        f.write(f"   - Total Berkas Dieliminasi          : {m_tereliminasi} Berkas\n")
        f.write(f"     [Rincian -> Kosong: {stats['malicious']['kosong']}, Hanya Komen: {stats['malicious']['komentar']}, Noise: {stats['malicious']['noise']}, Duplikat: {stats['malicious']['duplikat']}]\n\n")
        
        f.write(f" * KATEGORI BENIGN :\n")
        f.write(f"   - Jumlah Sumber (Mentah)            : {stats['benign']['awal']} Berkas\n")
        f.write(f"   - Jumlah Output (Bersih)            : {stats['benign']['bersih']} Berkas\n")
        f.write(f"   - Total Berkas Dieliminasi          : {b_tereliminasi} Berkas\n")
        f.write(f"     [Rincian -> Kosong: {stats['benign']['kosong']}, Hanya Komen: {stats['benign']['komentar']}, Noise: {stats['benign']['noise']}, Duplikat: {stats['benign']['duplikat']}]\n\n")
        
        f.write("---------------------------------------------------------------------------------\n")
        f.write(f" TOTAL DATASET MENTAH (KUMULATIF)           : {total_awal_all} Berkas\n")
        f.write(f" TOTAL DATASET BERSIH DI FOLDER 'mpsd_clean': {total_bersih_all} Berkas\n")
        f.write("=================================================================================\n\n")
        
        f.write("--- 2. LOG DETAIL PROSES ELIMINASI BERKAS SAMPAH ---\n")
        if log_eliminasi_lines:
            for line in log_eliminasi_lines:
                f.write(f"{line}\n")
        else:
            f.write("[INFO] Tidak ada berkas sampah yang terdeteksi untuk dieliminasi.\n")
            
    print(f"\n[+] [{waktu_selesai}] Berhasil! File laporan audit telah disimpan di: {Path(file_output_txt).resolve()}")

if __name__ == "__main__":
    folder_sumber_list = [
        "mpsd/malicious",
        "mpsd/benign"
    ]
    folder_tujuan = "mpsd_clean"
    file_laporan_akhir = "laporan_pembersihan_dataset.txt"
    
    buat_folder_output(Path(folder_tujuan))
    jalankan_pembersihan_dan_salin(folder_sumber_list, folder_tujuan, file_laporan_akhir)