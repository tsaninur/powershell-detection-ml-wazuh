<#
.SYNOPSIS
    Skrip Pengujian Otomatis PowerShell - Versi Optimized
.DESCRIPTION
    Mengeksekusi sampel .ps1 untuk memicu Event ID 4104 (Script Block Logging),
    lalu me-kill proses agar tidak ada payload yang benar-benar berjalan tuntas.

    Optimasi dibanding versi lama:
      - Timing dipertahankan (800ms hidup + 2s jeda) demi keandalan Wazuh
      - taskkill diganti Stop-Process (native, tanpa spawn proses baru = lebih cepat)
      - Pencatatan hasil ke CSV: SUKSES / GAGAL per file (audit tanpa celah)
      - Verifikasi akhir: memastikan jumlah baris CSV == jumlah file (0 terlewat)
      - Resume aman berbasis CSV (bukan 1 baris terakhir), sehingga jika skrip
        berhenti di tengah, file yang sudah diproses tidak diulang
#>

# =====================================================================
# KONFIGURASI
# =====================================================================
$basePath        = "C:\TA\project-ta\data_spliting"
$currentScenario = "malicious"

# Timing (JANGAN diubah - menjaga keandalan penangkapan log Wazuh)
$ExecLifetimeMs  = 800    # lama proses dibiarkan hidup sebelum di-kill
$AntiFloodSec    = 2      # jeda antar file agar Wazuh tidak overload

$targetDir = switch ($currentScenario) {
    "benign"               { "$basePath\test_set\benign" }
    "malicious"            { "$basePath\test_set\malicious" }
    "ASCII_Encoding"       { "$basePath\test_set_obf\ASCII_Encoding\malicious" }
    "String_Concatenation" { "$basePath\test_set_obf\String_Concatenation\malicious" }
    "String_Reordering"    { "$basePath\test_set_obf\String_Reordering\malicious" }
    "Token_Manipulation"   { "$basePath\test_set_obf\Token_Manipulation\malicious" }
    Default                { throw "Skenario tidak dikenal!" }
}

# File CSV hasil (audit sukses/gagal). Kolom: Index,FileName,Status,Timestamp
$resultCsv = "$basePath\hasil_uji_$currentScenario.csv"

# =====================================================================
# VALIDASI AWAL
# =====================================================================
if (!(Test-Path $targetDir)) {
    Write-Host "[ERROR] Folder tidak ditemukan: $targetDir" -ForegroundColor Red
    exit 1
}

$files = Get-ChildItem -Path $targetDir -Filter "*.ps1" | Sort-Object Name
$totalFiles = $files.Count

if ($totalFiles -eq 0) {
    Write-Host "[!] Tidak ada file .ps1 di folder." -ForegroundColor Yellow
    exit 0
}

# =====================================================================
# RESUME AMAN BERBASIS CSV
# Muat daftar file yang SUDAH diproses (apa pun statusnya) agar tidak diulang.
# =====================================================================
$processed = @{}
if (Test-Path $resultCsv) {
    try {
        Import-Csv $resultCsv | ForEach-Object { $processed[$_.FileName] = $_.Status }
        Write-Host "[i] Melanjutkan sesi. $($processed.Count) file sudah tercatat sebelumnya." -ForegroundColor DarkGray
    } catch {
        Write-Host "[!] CSV lama korup, memulai dari awal." -ForegroundColor Yellow
        $processed = @{}
    }
} else {
    # Tulis header CSV baru
    "Index,FileName,Status,Timestamp" | Out-File $resultCsv -Encoding utf8
}

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " MODE PENGUJIAN : $currentScenario"                    -ForegroundColor Cyan
Write-Host " Lokasi         : $targetDir"                          -ForegroundColor Cyan
Write-Host " Total File     : $totalFiles"                         -ForegroundColor Cyan
Write-Host " Sudah diproses : $($processed.Count)"                 -ForegroundColor Cyan
Write-Host " CSV Hasil      : $resultCsv"                          -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

# =====================================================================
# LOOP UTAMA
# =====================================================================
$currentIndex = 0
$countSuccess = 0
$countFailed  = 0
$countSkipped = 0

foreach ($file in $files) {
    $currentIndex++
    $pct = [math]::Round(($currentIndex / $totalFiles) * 100)
    Write-Progress -Activity "Skenario: $currentScenario" `
                   -Status "File $currentIndex dari $totalFiles ($pct%)" `
                   -PercentComplete $pct -CurrentOperation $file.Name

    # Lewati file yang sudah pernah diproses (resume)
    if ($processed.ContainsKey($file.Name)) {
        $countSkipped++
        continue
    }

    Write-Host "[$currentIndex/$totalFiles] Mengeksekusi -> $($file.Name)" -ForegroundColor Yellow

    $status = "SUKSES"
    try {
        $proc = Start-Process -FilePath "powershell.exe" `
            -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$($file.FullName)`"" `
            -PassThru -ErrorAction Stop

        # Biarkan hidup sejenak agar Event ID 4104 tercatat
        Start-Sleep -Milliseconds $ExecLifetimeMs

        # Kill native (lebih cepat dari spawn taskkill.exe), berikut child process
        if (!$proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
        $countSuccess++
    } catch {
        Write-Host "  [!] Gagal: $($file.Name) - $($_.Exception.Message)" -ForegroundColor Red
        $status = "GAGAL"
        $countFailed++
    }

    # Catat hasil ke CSV SEGERA (append) agar tidak ada celah bila skrip berhenti
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$currentIndex,`"$($file.Name)`",$status,$ts" | Out-File $resultCsv -Append -Encoding utf8

    # Jeda anti-flooding Wazuh (dipertahankan)
    Start-Sleep -Seconds $AntiFloodSec
}

Write-Progress -Activity "Skenario: $currentScenario" -Completed

# =====================================================================
# VERIFIKASI AKHIR - pastikan TIDAK ADA yang terlewat
# =====================================================================
$recorded = (Import-Csv $resultCsv)
$recordedNames = $recorded | Select-Object -ExpandProperty FileName -Unique
$missing = $files | Where-Object { $recordedNames -notcontains $_.Name }

Write-Host "`n======================================================" -ForegroundColor Green
Write-Host " SELESAI - Skenario $currentScenario"                    -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Green
Write-Host " Total file        : $totalFiles"
Write-Host " Sukses (sesi ini) : $countSuccess" -ForegroundColor Green
Write-Host " Gagal  (sesi ini) : $countFailed"  -ForegroundColor $(if($countFailed){'Red'}else{'Green'})
Write-Host " Dilewati (resume) : $countSkipped" -ForegroundColor DarkGray
Write-Host " Tercatat di CSV   : $($recordedNames.Count)"

if ($missing.Count -eq 0) {
    Write-Host " [OK] Semua file tercatat. Tidak ada yang terlewat." -ForegroundColor Green
} else {
    Write-Host " [!] $($missing.Count) file BELUM tercatat:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "     - $($_.Name)" -ForegroundColor Red }
    Write-Host " Jalankan ulang skrip ini untuk memproses sisa file (resume otomatis)." -ForegroundColor Yellow
}

# Laporan daftar GAGAL (bila ada) agar mudah di-retry manual
$failedList = $recorded | Where-Object { $_.Status -eq "GAGAL" }
if ($failedList) {
    Write-Host "`n [!] Daftar file berstatus GAGAL:" -ForegroundColor Red
    $failedList | ForEach-Object { Write-Host "     - $($_.FileName)" -ForegroundColor Red }
}