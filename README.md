# powershell-detection-ml-wazuh
Sistem deteksi fileless malware PowerShell berbasis Machine Learning (Random Forest, XGBoost, LightGBM) yang diintegrasikan pada SIEM Wazuh. Repositori ini mencakup pipeline lengkap mulai dari data preparation, ekstraksi fitur (Statistik, Leksikal, AST), teknik obfuskasi, hingga integrasi skrip kustom pada Wazuh.

# Deteksi Fileless Malware PowerShell berbasis ML pada SIEM Wazuh

Repositori ini berisi keseluruhan *pipeline* kode untuk "Deteksi PowerShell berbasis ML pada SIEM Wazuh"[cite: 2]. Sistem ini dirancang untuk mendeteksi eksekusi skrip berbahaya dari log PowerShell (Event ID 4104) dengan mengekstrak fitur statistik, leksikal, dan *Abstract Syntax Tree* (AST)[cite: 9]. Model Machine Learning dievaluasi kinerjanya dalam menghadapi berbagai teknik obfuskasi dibandingkan dengan metode deteksi *Rule-Based* bawaan Wazuh[cite: 3, 6].

## Struktur Direktori

Berdasarkan referensi file image_e16207.png, berikut adalah struktur utama dari repositori ini:

* **`__pycache__/`**: Folder *cache* Python.
* **`data_spliting/`**: Folder berisi hasil pembagian dataset menjadi *train set* dan *test set*.
* **`hasil_ekstraksi/`**: Folder tempat menyimpan file CSV berisi fitur yang telah diekstrak dari skrip.
* **`integrasi wazuh/`**: Skrip dan konfigurasi untuk menghubungkan model ML dengan agen/server Wazuh.
* **`mpsd/`**: Folder dataset mentah yang berisi kategori *malicious* dan *benign*.
* **`mpsd_clean/`**: Folder output untuk dataset yang telah dibersihkan dari *noise* dan duplikat.
* **`output/`**: Menyimpan model terlatih (`.joblib`), grafik evaluasi, dan metrik.
* **`reports_ml/`** & **`reports_rule_based/`**: Folder untuk menyimpan laporan perbandingan hasil evaluasi sistem ML dan *Rule-Based*.
* **`venv/`**: *Virtual environment* Python.

## Pipeline Repositori

Proses deteksi dan pemodelan dibagi menjadi beberapa tahapan skrip utama:

### 1. Data Preparation (`clean.py`)
Skrip ini memindai folder dataset mentah dan melakukan pembersihan otomatis[cite: 1].
* Menghapus *null bytes* (`\x00`) yang sering digunakan untuk *padding* malware[cite: 1].
* Membersihkan komentar teks murni (`#` atau `<# #>`)[cite: 1].
* Mengeliminasi file kosong, file yang terlalu pendek (*noise*), dan melakukan pengecekan duplikasi silang menggunakan *Hash* MD5[cite: 1].

<img width="970" height="230" alt="cleaning2" src="https://github.com/user-attachments/assets/65c5f8b3-0bcd-482f-aac8-1924fc4f2336" />

### 2. Pembagian Dataset (`data spliting.py`)
Membagi dataset yang telah bersih (`mpsd_clean`) menjadi data pelatihan (80%) dan data pengujian (20%)[cite: 2].
* Menggunakan metode *Stratified Split* untuk memastikan proporsi label *benign* dan *malicious* tetap seimbang di kedua set[cite: 2].

<img width="1005" height="313" alt="splitting" src="https://github.com/user-attachments/assets/92d96b25-efc5-4ba2-ac59-75cb41b5f83d" />

### 3. Augmentasi Obfuskasi (`obfuscation.ps1`)
Melakukan augmentasi pada dataset menggunakan modul `Invoke-Obfuscation` untuk menguji ketahanan model[cite: 8].
* Menerapkan 4 teknik obfuskasi: *Token Manipulation*, *ASCII Encoding*, *String Concatenation*, dan *String Reordering*[cite: 8].

<img width="664" height="268" alt="obf3" src="https://github.com/user-attachments/assets/27af7a20-d62a-4129-9b6b-f21dd429d9fc" />

### 4. Ekstraksi Fitur (`feature extraction.ipynb`)
Mengekstrak tiga jenis fitur dari skrip PowerShell untuk dijadikan input Machine Learning:
* **Statistik & Leksikal**: Menghitung panjang skrip, jumlah baris, karakter khusus (seperti `$`, `^`, `%`), dan kemunculan *keyword* spesifik PowerShell (seperti `Invoke-Expression`, `Net.WebClient`)[cite: 4, 9].
* **AST (Abstract Syntax Tree)**: Menggunakan `pwsh` untuk melakukan *parsing* skrip dan mengekstrak 11 node AST target (seperti `CommandAst`, `PipelineAst`) secara dinamis[cite: 4, 9].

<img width="783" height="499" alt="fitur1" src="https://github.com/user-attachments/assets/ae64b39e-a837-429b-bee1-3ba69452db42" />
<img width="759" height="496" alt="fitur2" src="https://github.com/user-attachments/assets/700daa3f-824a-4b86-b2d1-e35f54de2f9a" />

### 5. Pemodelan Machine Learning (`modeling.ipynb`)
Melatih algoritma Machine Learning menggunakan data dasar (murni) dan data augmentasi (obfuskasi).
* Menggunakan tiga arsitektur model: **Random Forest**, **XGBoost**, dan **LightGBM**[cite: 7].
* Menerapkan pengujian *5-Fold Cross Validation* untuk memastikan tidak terjadi *overfitting*[cite: 7].
* Mengekspor model terbaik dalam format `.joblib`[cite: 7].

<img width="512" height="505" alt="model1" src="https://github.com/user-attachments/assets/46d20425-413d-4f04-a60e-ecbfcf30d339" />
<img width="935" height="339" alt="model2" src="https://github.com/user-attachments/assets/7f61cef2-1c42-4233-bae1-2f10ad958384" />

### 6. Evaluasi Model (`evaluate.ipynb`)
Menguji kinerja deteksi model terhadap set pengujian murni dan yang terobfuskasi.
* Menghitung metrik performa komprehensif: *Accuracy, Precision, Recall, F1-Score, False Positive Rate (FPR), False Negative Rate (FNR), ROC AUC*, dan *PR AUC*[cite: 3].
* Mengekspor matriks hasil evaluasi ke dalam format CSV dan menghasilkan visualisasi grafik lanskap[cite: 3].
  
<img width="1125" height="524" alt="eval1" src="https://github.com/user-attachments/assets/331b5b39-188a-495d-9f9d-aa1fe073627b" />

### 7. Integrasi Wazuh (`custom-ps-ml.py`)
Skrip integrasi kustom yang dijalankan oleh Wazuh saat Rule 100010 (Event ID 4104) terpicu[cite: 9].
* Bertindak sebagai *Gatekeeper* dengan menolak log yang terfragmentasi atau terlalu pendek (< 50 karakter)[cite: 9].
* Menangani eksekusi *Fileless* (skrip yang berjalan di memori tanpa path file)[cite: 9].
* Melakukan ekstraksi fitur secara hibrida, memuat model `.joblib` terbaru, dan memberikan prediksi akhir (*malicious* atau *benign*) beserta nilai probabilitasnya[cite: 9].

<img width="952" height="640" alt="alerts2" src="https://github.com/user-attachments/assets/ee97f2f2-0596-422f-98fe-592a810a0d00" />

### 8. Laporan Evaluasi Terpadu (`generate_ml_report.py` & `generate_report_rule.py`)
* Membaca log *alerts* JSON dari Wazuh untuk membandingkan kinerja deteksi Machine Learning dengan deteksi heuristik (*Rule-Based* level 6 ke atas)[cite: 5, 6].
* Menghitung status deteksi (TP, TN, FP, FN) dan latensi klasifikasi[cite: 5].

<img width="1154" height="154" alt="image" src="https://github.com/user-attachments/assets/3bca6da4-b543-4fff-bbe7-9d49505cbf48" />
<img width="444" height="139" alt="image" src="https://github.com/user-attachments/assets/b1dddefa-b726-4615-9051-f7c075107e85" />


