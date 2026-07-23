<#
.SYNOPSIS
    Pengukuran Latensi Deteksi Rule-Based Wazuh - Sisi Windows (Endpoint)
    VERSI CEPAT: menggabungkan timing dari uji_otomatis_rule.ps1 (500ms
    exec + 250ms jeda + -NoProfile) dengan pencatatan T_PreExec presisi
    tinggi untuk pengukuran latensi.
.DESCRIPTION
    Mengeksekusi sampel skrip .ps1 sambil mencatat timestamp presisi tinggi
    SEBELUM eksekusi dimulai. Timestamp ini nantinya dicocokkan dengan
    timestamp alert Wazuh (via generate_report_rule.py) untuk menghitung
    latensi end-to-end: eksekusi skrip -> Event Log -> Agent -> Manager ->
    rule engine -> alert muncul.

    PERUBAHAN TIMING (dari versi sebelumnya):
        ExecLifetimeMs : 800ms -> 500ms  (disamakan dengan uji_otomatis_rule.ps1)
        AntiFloodMs    : 1000ms/2000ms -> 250ms (disamakan)
        Argumen        : ditambah -NonInteractive -NoProfile
                         (menghilangkan overhead pemuatan PowerShell profile)

    PERINGATAN PENTING: file latency_probe_<skenario>.csv SELALU ditimpa
    bersih setiap kali skrip dijalankan untuk skenario tersebut (bukan
    di-resume). Pastikan proses tidak terputus di tengah jalan.

.PARAMETER Scenario
    Satu atau beberapa nama skenario yang ingin diuji. Jika tidak diisi,
    SELURUH enam skenario akan dijalankan berurutan secara otomatis.

.EXAMPLE
    .\latency_probe_tester.ps1
.EXAMPLE
    .\latency_probe_tester.ps1 -Scenario ASCII_Encoding
.EXAMPLE
    .\latency_probe_tester.ps1 -Scenario String_Concatenation,String_Reordering,Token_Manipulation
#>

param(
    [string[]]$Scenario = @()
)

# =====================================================================
# KONFIGURASI GLOBAL (disamakan dengan uji_otomatis_rule.ps1 agar cepat)
# =====================================================================
$basePath       = "C:\TA\project-ta\data_spliting"
$ExecLifetimeMs = 500
$AntiFloodMs    = 250

$AllScenarios = @(
     "benign", "malicious", "ASCII_Encoding", "String_Concatenation", "String_Reordering", "Token_Manipulation"
)

$FolderMap = @{
    "benign"               = "$basePath\test_set\benign"
    "malicious"            = "$basePath\test_set\malicious"
    "ASCII_Encoding"       = "$basePath\test_set_obf\ASCII_Encoding\malicious"
    "String_Concatenation" = "$basePath\test_set_obf\String_Concatenation\malicious"
    "String_Reordering"    = "$basePath\test_set_obf\String_Reordering\malicious"
    "Token_Manipulation"   = "$basePath\test_set_obf\Token_Manipulation\malicious"
}

# =====================================================================
# TENTUKAN SKENARIO YANG AKAN DIJALANKAN
# =====================================================================
if ($Scenario.Count -eq 0) {
    $ScenariosToRun = $AllScenarios
    Write-Host "[i] Tidak ada skenario spesifik dipilih -> menjalankan SEMUA skenario." -ForegroundColor DarkCyan
} else {
    $invalid = $Scenario | Where-Object { $_ -notin $AllScenarios }
    if ($invalid.Count -gt 0) {
        Write-Host "[ERROR] Skenario tidak dikenal: $($invalid -join ', ')" -ForegroundColor Red
        Write-Host "        Pilihan valid: $($AllScenarios -join ', ')" -ForegroundColor Yellow
        exit 1
    }
    $ScenariosToRun = $Scenario
}

$RunTimestampStart = Get-Date
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " PROBE LATENSI RULE-BASED (VERSI CEPAT) - MULAI"       -ForegroundColor Cyan
Write-Host " Waktu Mulai    : $($RunTimestampStart.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
Write-Host " Timing         : ${ExecLifetimeMs}ms exec + ${AntiFloodMs}ms jeda (-NoProfile)" -ForegroundColor Cyan
Write-Host " Jumlah Skenario: $($ScenariosToRun.Count) -> $($ScenariosToRun -join ', ')" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

$GlobalSummary = @()
$GlobalTotalFiles   = 0
$GlobalTotalSuccess = 0
$GlobalTotalFailed  = 0

# =====================================================================
# LOOP UNTUK SETIAP SKENARIO YANG DIPILIH
# =====================================================================
foreach ($currentScenario in $ScenariosToRun) {

    $scenarioStart = Get-Date
    $targetDir = $FolderMap[$currentScenario]
    $probeCsv  = "$basePath\latency_probe_$currentScenario.csv"

    Write-Host ""
    Write-Host "------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host " Skenario: $currentScenario"                              -ForegroundColor White
    Write-Host " Mulai    : $($scenarioStart.ToString('yyyy-MM-dd HH:mm:ss.fff'))" -ForegroundColor DarkGray
    Write-Host "------------------------------------------------------" -ForegroundColor DarkGray

    if (!(Test-Path $targetDir)) {
        Write-Host "[ERROR] Folder tidak ditemukan: $targetDir" -ForegroundColor Red
        $GlobalSummary += [PSCustomObject]@{
            Skenario = $currentScenario; TotalFile = 0; Sukses = 0; Gagal = 0
            Mulai = $scenarioStart; Selesai = (Get-Date); DurasiDetik = 0
        }
        continue
    }

    $files = Get-ChildItem -Path $targetDir -Filter "*.ps1" | Sort-Object Name
    $totalFiles = $files.Count

    if ($totalFiles -eq 0) {
        Write-Host "[!] Tidak ada file .ps1 ditemukan di folder ini." -ForegroundColor Yellow
        $GlobalSummary += [PSCustomObject]@{
            Skenario = $currentScenario; TotalFile = 0; Sukses = 0; Gagal = 0
            Mulai = $scenarioStart; Selesai = (Get-Date); DurasiDetik = 0
        }
        continue
    }

    # File probe SELALU ditimpa bersih (bukan resume) - lihat peringatan di DESCRIPTION
    "FileName,T_PreExec_ISO" | Out-File $probeCsv -Encoding utf8

    Write-Host " Total File : $totalFiles"  -ForegroundColor Cyan
    Write-Host " Output     : $probeCsv"    -ForegroundColor Cyan

    $currentIndex  = 0
    $countSuccess  = 0
    $countFailed   = 0

    foreach ($file in $files) {
        $currentIndex++
        $pct = [math]::Round(($currentIndex / $totalFiles) * 100)
        Write-Progress -Activity "Probe Latensi: $currentScenario" `
                       -Status "File $currentIndex dari $totalFiles ($pct%)" `
                       -PercentComplete $pct -CurrentOperation $file.Name

        try {
            # -- TITIK PENGUKURAN KRUSIAL --------------------------------
            # Dicatat TEPAT SEBELUM proses dimulai, presisi hingga 100-ns.
            $tPreExec = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffffffK")
            # -------------------------------------------------------------

            # -NonInteractive -NoProfile: menghilangkan overhead pemuatan
            # PowerShell profile, konsisten dengan uji_otomatis_rule.ps1
            $arguments = "-NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"$($file.FullName)`""
            $proc = Start-Process -FilePath "powershell.exe" `
                -ArgumentList $arguments -WindowStyle Hidden -PassThru -ErrorAction Stop

            Start-Sleep -Milliseconds $ExecLifetimeMs

            if (!$proc.HasExited) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            }

            "$($file.Name),$tPreExec" | Out-File $probeCsv -Append -Encoding utf8
            Write-Host "[$currentIndex/$totalFiles] $($file.Name) -> T_PreExec=$tPreExec" -ForegroundColor Yellow
            $countSuccess++

        } catch {
            Write-Host "  [!] Gagal memproses $($file.Name): $_" -ForegroundColor Red
            $countFailed++
        }

        Start-Sleep -Milliseconds $AntiFloodMs
    }

    Write-Progress -Activity "Probe Latensi: $currentScenario" -Completed

    $scenarioEnd      = Get-Date
    $scenarioDuration = ($scenarioEnd - $scenarioStart)

    Write-Host " Selesai  : $($scenarioEnd.ToString('yyyy-MM-dd HH:mm:ss.fff'))" -ForegroundColor DarkGray
    Write-Host " Durasi   : $($scenarioDuration.ToString('hh\:mm\:ss'))"        -ForegroundColor DarkGray
    Write-Host " Sukses=$countSuccess  Gagal=$countFailed"                     -ForegroundColor Green

    $GlobalSummary += [PSCustomObject]@{
        Skenario    = $currentScenario
        TotalFile   = $totalFiles
        Sukses      = $countSuccess
        Gagal       = $countFailed
        Mulai       = $scenarioStart
        Selesai     = $scenarioEnd
        DurasiDetik = [math]::Round($scenarioDuration.TotalSeconds, 1)
    }

    $GlobalTotalFiles   += $totalFiles
    $GlobalTotalSuccess += $countSuccess
    $GlobalTotalFailed  += $countFailed
}

# =====================================================================
# RINGKASAN AKHIR SELURUH SESI PENGUJIAN
# =====================================================================
$RunTimestampEnd  = Get-Date
$TotalDuration    = ($RunTimestampEnd - $RunTimestampStart)

Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " RINGKASAN SESI PENGUJIAN"                                -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " Waktu Mulai    : $($RunTimestampStart.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host " Waktu Selesai  : $($RunTimestampEnd.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host " Total Durasi   : $($TotalDuration.ToString('hh\:mm\:ss')) ($([math]::Round($TotalDuration.TotalMinutes,1)) menit)"
Write-Host " Total Skenario : $($ScenariosToRun.Count)"
Write-Host " Total File     : $GlobalTotalFiles"
Write-Host " Total Sukses   : $GlobalTotalSuccess" -ForegroundColor Green
Write-Host " Total Gagal    : $GlobalTotalFailed"  -ForegroundColor $(if($GlobalTotalFailed -gt 0){'Red'}else{'Green'})
Write-Host "------------------------------------------------------"
Write-Host " Rincian per Skenario:"
$GlobalSummary | ForEach-Object {
    Write-Host ("   {0,-22} File={1,-5} Sukses={2,-5} Gagal={3,-4} Durasi={4}s" -f `
        $_.Skenario, $_.TotalFile, $_.Sukses, $_.Gagal, $_.DurasiDetik)
}
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[OK] Seluruh probe selesai. File CSV tersimpan di: $basePath\latency_probe_<skenario>.csv" -ForegroundColor Green