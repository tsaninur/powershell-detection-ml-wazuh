"""
Dataset Splitter — Tahap 2: Pembagian Dataset (80/20 Stratified Split)
Skripsi: Deteksi Fileless Malware PowerShell berbasis ML pada SIEM Wazuh

Pipeline:
    output/dataset_clean/
        ├── benign/
        └── malicious/
            ↓ load_data() → split_80_20() → save_scripts()
    output/data_spliting/
        ├── train_set/
        │   ├── benign/
        │   └── malicious/
        └── test_set/
            ├── benign/
            └── malicious/
"""

import sys
from pathlib import Path
from typing import Tuple
from datetime import datetime

import pandas as pd
from sklearn.model_selection import train_test_split


RANDOM_STATE = 42
TEST_SIZE = 0.20
ENCODING_ORDER = ["utf-8", "utf-16", "cp1252", "latin-1"]
LABEL_BENIGN = "benign"
LABEL_MALICIOUS = "malicious"


class DatasetSplitter:
    """Membagi dataset MPSD (.ps1) secara stratified menjadi set latih dan uji."""

    def __init__(self, random_state: int = RANDOM_STATE) -> None:
        self.random_state = random_state

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _read_file(self, filepath: Path) -> str | None:
        """Membaca file teks dengan fallback encoding. Mengembalikan None jika gagal."""
        for enc in ENCODING_ORDER:
            try:
                return filepath.read_text(encoding=enc)
            except UnicodeDecodeError:
                continue
            except OSError:
                return None
        print(f"  [SKIP] Tidak dapat membaca: '{filepath.name}'")
        return None

    def _load_folder(self, folder: Path, label: str) -> list[dict]:
        """Memuat semua file dari satu folder dan mengembalikan list of dict."""
        if not folder.exists():
            raise FileNotFoundError(f"Sub-folder tidak ditemukan: '{folder}'")

        records = []
        for fp in sorted(folder.iterdir()):
            if not fp.is_file():
                continue
            content = self._read_file(fp)
            if content is not None:
                records.append({
                    "filename": fp.name,
                    "script": content,
                    "label": label,
                })
        return records

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def load_data(self, clean_dir_path: str | Path) -> pd.DataFrame:
        """
        Memuat seluruh skrip dari sub-folder benign dan malicious.

        Args:
            clean_dir_path: Path ke direktori dataset bersih yang berisi
                            sub-folder 'benign' dan 'malicious'.

        Returns:
            DataFrame dengan kolom ['filename', 'script', 'label'].
        """
        clean_dir = Path(clean_dir_path)
        if not clean_dir.is_dir():
            raise FileNotFoundError(f"Direktori tidak ditemukan: '{clean_dir}'")

        benign_records = self._load_folder(clean_dir / LABEL_BENIGN, LABEL_BENIGN)
        malicious_records = self._load_folder(clean_dir / LABEL_MALICIOUS, LABEL_MALICIOUS)

        df = pd.DataFrame(benign_records + malicious_records)

        print(f"Data dimuat   : {len(df):,} file total")
        print(f"  benign      : {(df['label'] == LABEL_BENIGN).sum():,}")
        print(f"  malicious   : {(df['label'] == LABEL_MALICIOUS).sum():,}")

        return df

    def split_80_20(
        self, df: pd.DataFrame
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Membagi DataFrame menjadi 80% train dan 20% test secara stratified.

        Args:
            df: DataFrame dengan kolom 'script' dan 'label'.

        Returns:
            Tuple (df_train, df_test) dengan indeks yang sudah di-reset.
        """
        df_train, df_test = train_test_split(
            df,
            test_size=TEST_SIZE,
            random_state=self.random_state,
            stratify=df["label"],
        )

        df_train = df_train.reset_index(drop=True)
        df_test = df_test.reset_index(drop=True)

        return df_train, df_test

    def save_scripts(self, df: pd.DataFrame, output_dir: str | Path) -> None:
        """
        Menyimpan setiap skrip ke file .ps1 di dalam sub-folder sesuai labelnya.

        Struktur output:
            output_dir/
            ├── benign/
            └── malicious/

        Args:
            df         : DataFrame dengan kolom ['filename', 'script', 'label'].
            output_dir : Direktori tujuan penyimpanan.
        """
        output_dir = Path(output_dir)

        for label in (LABEL_BENIGN, LABEL_MALICIOUS):
            (output_dir / label).mkdir(parents=True, exist_ok=True)

        n_saved = 0
        for _, row in df.iterrows():
            dest_folder = output_dir / row["label"]

            original = Path(row["filename"])
            filename = original.stem + ".ps1"
            dest_path = dest_folder / filename

            # Tangani tabrakan nama dengan sufiks numerik
            counter = 1
            while dest_path.exists():
                dest_path = dest_folder / f"{original.stem}_{counter}.ps1"
                counter += 1

            dest_path.write_text(row["script"], encoding="utf-8")
            n_saved += 1

        print(f"  Disimpan {n_saved:,} file ke: '{output_dir}'")

def write_log(log_path: Path, df_train: pd.DataFrame, df_test: pd.DataFrame):
    """Fungsi untuk menulis log audit pembagian dataset dengan timestamp"""
    waktu_eksekusi = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_data = len(df_train) + len(df_test)
    
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("=================================================================================\n")
        f.write("         LAPORAN REKAPITULASI PEMBAGIAN DATASET (STRATIFIED 80:20) \n")
        f.write(f"         WAKTU EKSEKUSI : {waktu_eksekusi}\n")
        f.write(f"         RANDOM STATE   : {RANDOM_STATE}\n")
        f.write(f"         FOLDER OUTPUT  : {log_path.parent.resolve()}\n")
        f.write("=================================================================================\n\n")
        
        f.write(f"--- TOTAL DATA BERSIH: {total_data:,} Berkas ---\n\n")
        
        f.write(f"1. DATA PELATIHAN (TRAIN SET) - 80%\n")
        f.write(f"   - Total Berkas  : {len(df_train):,}\n")
        f.write(f"   - Malicious     : {(df_train['label']==LABEL_MALICIOUS).sum():,}\n")
        f.write(f"   - Benign        : {(df_train['label']==LABEL_BENIGN).sum():,}\n\n")
        
        f.write(f"2. DATA PENGUJIAN (TEST SET) - 20%\n")
        f.write(f"   - Total Berkas  : {len(df_test):,}\n")
        f.write(f"   - Malicious     : {(df_test['label']==LABEL_MALICIOUS).sum():,}\n")
        f.write(f"   - Benign        : {(df_test['label']==LABEL_BENIGN).sum():,}\n\n")
        
        f.write("=================================================================================\n")
        f.write("[INFO] Data berhasil didistribusikan ke masing-masing folder dengan metode Stratified Split.\n")


if __name__ == "__main__":
    INPUT_DIR = Path(r"mpsd_clean")
    TRAIN_OUT  = Path(r"data_spliting\train_set")
    TEST_OUT   = Path(r"data_spliting\test_set")
    LOG_FILE   = Path(r"data_spliting\laporan_pembagian_data_80_20.txt")

    try:
        splitter = DatasetSplitter(random_state=RANDOM_STATE)

        # 1. Muat data bersih
        df = splitter.load_data(INPUT_DIR)

        # 2. Split 80/20 stratified
        df_train, df_test = splitter.split_80_20(df)

        # 3. Simpan ke direktori output masing-masing
        print(f"\nMenyimpan train set ({len(df_train):,} file)...")
        splitter.save_scripts(df_train, TRAIN_OUT)

        print(f"Menyimpan test set  ({len(df_test):,} file)...")
        splitter.save_scripts(df_test, TEST_OUT)
        
        # 4. Tulis file log
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        write_log(LOG_FILE, df_train, df_test)

        # 5. Ringkasan akhir
        print(f"\n{'='*50}")
        print(f"Split selesai (random_state={RANDOM_STATE}):")
        print(
            f"  Train : {len(df_train):,} file "
            f"(benign={(df_train['label']==LABEL_BENIGN).sum():,}, "
            f"malicious={(df_train['label']==LABEL_MALICIOUS).sum():,})"
        )
        print(
            f"  Test  : {len(df_test):,} file "
            f"(benign={(df_test['label']==LABEL_BENIGN).sum():,}, "
            f"malicious={(df_test['label']==LABEL_MALICIOUS).sum():,})"
        )
        print(f"Log disimpan di : {LOG_FILE.resolve()}")
        print(f"waktu eksekusi   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*50}")

    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}")
        sys.exit(1)