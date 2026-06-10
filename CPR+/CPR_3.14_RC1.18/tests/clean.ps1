$file = 'C:\ProgramData\WhiteWalker\WW_main.ps1'
(Get-Content $file -Raw -Encoding UTF8) -replace '\u00A0',' ' | Set-Content $file -Encoding UTF8
 
