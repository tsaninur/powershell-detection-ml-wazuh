<#
.SYNOPSIS
    Batch obfuscation of PowerShell scripts using Invoke-Obfuscation with exhaustive techniques.
.DESCRIPTION
    Processes all .ps1 files, applying ALL FOUR obfuscation techniques.
    Executes sequentially by technique (completes all files for technique A before moving to B).
    Includes a progress bar (Terminal output disabled for speed) and outputs a detailed log document.
#>

$modulePath = ".\Invoke-Obfuscation\Invoke-Obfuscation.psd1"
if (-not (Test-Path $modulePath)) {
    Write-Host "[ERROR] Module not found at $modulePath" -ForegroundColor Red
    exit 1
}
Import-Module $modulePath -Force

# --- BAGIAN YANG DIUBAH: MENYESUAIKAN 4 TEKNIK FINAL ---
$techniques = @(
    @{ Name = "Token_Manipulation";    Command = "Token\Command\1" }, 
    @{ Name = "ASCII_Encoding";        Command = "Encoding\1" },
    @{ Name = "String_Concatenation";  Command = "String\1" },
    @{ Name = "String_Reordering";     Command = "String\2" }
)
# -------------------------------------------------------

$global:stats = @{
    total_success = 0
    total_failed = 0
    failed_files = @()
    technique_counts = @{}
    technique_times = @{}
}
foreach ($t in $techniques) { 
    $global:stats.technique_counts[$t.Name] = 0 
    $global:stats.technique_times[$t.Name] = [timespan]::Zero
}

function Process-Folder {
    param(
        [string]$InputDir,
        [string]$BaseOutputDir
    )

    if (-not (Test-Path $InputDir)) {
        Write-Host "[SKIP] $InputDir not found" -ForegroundColor Yellow
        return
    }

    $files = Get-ChildItem -Path $InputDir -Filter "*.ps1" -File
    $total = $files.Count
    if ($total -eq 0) {
        Write-Host "[SKIP] No .ps1 files in $InputDir" -ForegroundColor Yellow
        return
    }

    if (-not (Test-Path $BaseOutputDir)) { New-Item -ItemType Directory -Path $BaseOutputDir -Force | Out-Null }
    $logFile = Join-Path $BaseOutputDir "detailed_obfuscation_log.txt"
    "--- DETAILED OBFUSCATION LOG (Folder: $InputDir) ---`n" | Out-File -FilePath $logFile -Encoding UTF8 -Force

    Write-Host "`nProcessing $total files from: $InputDir" -ForegroundColor Cyan

    foreach ($tech in $techniques) {
        $techName = $tech.Name
        $techCmd = $tech.Command

        Write-Host "-> Memulai teknik: $techName" -ForegroundColor Yellow

        $outDir = Join-Path -Path $BaseOutputDir -ChildPath $techName
        $outDir = Join-Path -Path $outDir -ChildPath "malicious"
        
        if (-not (Test-Path $outDir)) {
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        }

        for ($i = 0; $i -lt $total; $i++) {
            $file = $files[$i]
            $outFile = Join-Path -Path $outDir -ChildPath $file.Name

            # Menampilkan Loading Bar
            $percent = [math]::Round((($i + 1) / $total) * 100)
            Write-Progress -Activity "Obfuscating: $techName" -Status "Memproses file $($i + 1) dari $($total): $($file.Name)" -PercentComplete $percent

            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

            try {
                Invoke-Obfuscation -ScriptPath $file.FullName -Command $techCmd -Quiet |
                    Out-File -FilePath $outFile -Encoding UTF8 -Force
                
                $sw.Stop()
                $timeStr = $sw.Elapsed.TotalSeconds.ToString("0.00")
                $global:stats.technique_times[$techName] += $sw.Elapsed
                $global:stats.total_success++
                $global:stats.technique_counts[$techName]++

                $logLine = "[$timestamp] [SUCCESS] Tech: $($techName.PadRight(26)) | Time: ${timeStr}s | File: $($file.Name)"
                Add-Content -Path $logFile -Value $logLine
            }
            catch {
                $sw.Stop()
                $timeStr = $sw.Elapsed.TotalSeconds.ToString("0.00")
                $global:stats.technique_times[$techName] += $sw.Elapsed
                $global:stats.total_failed++
                $global:stats.failed_files += "$($file.FullName) (Failed on: $techName)"

                $logLine = "[$timestamp] [FAILED]  Tech: $($techName.PadRight(26)) | Time: ${timeStr}s | File: $($file.Name)"
                Add-Content -Path $logFile -Value $logLine
            }
        }
        
              Write-Progress -Activity "Obfuscating: $techName" -Completed
 
        # --- PEMBERSIHAN FILE GAGAL (KOSONG / 0 BYTE) ---
        $emptyFiles = Get-ChildItem -Path $outDir -Filter "*.ps1" -File | Where-Object { $_.Length -eq 0 }
        $emptyCount = ($emptyFiles | Measure-Object).Count
        if ($emptyCount -gt 0) {
            foreach ($ef in $emptyFiles) {
                Remove-Item -Path $ef.FullName -Force
                $logLine = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [CLEANED] Tech: $($techName.PadRight(26)) | File kosong dihapus: $($ef.Name)"
                Add-Content -Path $logFile -Value $logLine
            }
            Write-Host "   [CLEANUP] $emptyCount file kosong (gagal obfuskasi) dihapus dari $techName" -ForegroundColor Magenta
        }
        # ------------------------------------------------
        Write-Host "   Selesai teknik: $techName`n" -ForegroundColor Green
    }
}

# Main execution
Write-Host "="*60 -ForegroundColor White
Write-Host "BATCH OBFUSCATION (4 CORE TECHNIQUES APPLIED SEQUENTIALLY)" -ForegroundColor White
Write-Host "="*60 -ForegroundColor White

# --- BAGIAN YANG DIUBAH: MENYESUAIKAN PATH DENGAN SKRIP PYTHON SEBELUMNYA ---
$basePath = "project-ta\data_spliting"
# -----------------------------------------------------------------------------

Process-Folder -InputDir (Join-Path $basePath "train_set\malicious") -BaseOutputDir (Join-Path $basePath "train_set_obf")
Process-Folder -InputDir (Join-Path $basePath "test_set\malicious") -BaseOutputDir (Join-Path $basePath "test_set_obf")

Write-Host "`n" + "="*60 -ForegroundColor Cyan
Write-Host "FINAL STATISTICS" -ForegroundColor Cyan
Write-Host "="*60 -ForegroundColor Cyan
Write-Host "Total successful obfuscations : $($global:stats.total_success)" -ForegroundColor Green
Write-Host "Total failed obfuscations     : $($global:stats.total_failed)" -ForegroundColor Red

Write-Host "`nSuccess and Time per technique:" -ForegroundColor Yellow
foreach ($t in $techniques) {
    $count = $global:stats.technique_counts[$t.Name]
    $timeStr = $global:stats.technique_times[$t.Name].ToString("hh\:mm\:ss\.ff")
    Write-Host "  $($t.Name.PadRight(26)) : $count successful | Time: $timeStr"
}

if ($global:stats.total_failed -gt 0) {
    Write-Host "`nFailed files & techniques:" -ForegroundColor Red
    foreach ($f in $global:stats.failed_files) {
        Write-Host "  $f" -ForegroundColor Red
    }
}

Write-Host "`nAll done!" -ForegroundColor Green

$reportPath = Join-Path $basePath "obfuscation_summary_report.txt"
$reportContent = @()

$reportContent += "="*60
$reportContent += "LAPORAN HASIL AUGMENTASI OBFUSKASI"
$reportContent += "="*60
$reportContent += "Waktu Selesai           : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$reportContent += "Total Obfuskasi Berhasil: $($global:stats.total_success)"
$reportContent += "Total Obfuskasi Gagal   : $($global:stats.total_failed)"
$reportContent += ""
$reportContent += "--- DETAIL PER TEKNIK ---"

foreach ($t in $techniques) {
    $name = $t.Name
    $count = $global:stats.technique_counts[$name]
    $timeStr = $global:stats.technique_times[$name].ToString("hh\:mm\:ss\.ff")
    $reportContent += "- $($name.PadRight(26)) : $count Berhasil | Waktu Total: $timeStr"
}

if ($global:stats.total_failed -gt 0) {
    $reportContent += "`n--- DAFTAR FILE GAGAL ---"
    foreach ($f in $global:stats.failed_files) {
        $reportContent += $f
    }
}

$reportContent | Out-File -FilePath $reportPath -Encoding UTF8 -Force
Write-Host "`n[INFO] Laporan summary tersimpan di: $reportPath" -ForegroundColor Magenta
Write-Host "[INFO] Log detail (per file) tersimpan di folder masing-masing dataset (detailed_obfuscation_log.txt)" -ForegroundColor Magenta