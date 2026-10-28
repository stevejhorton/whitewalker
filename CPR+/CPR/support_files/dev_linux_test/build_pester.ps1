# Assembles an importable Pester module from the Pester SOURCE checkout (what build.ps1 -Inline does, minus dotnet).
# The C# sources are compiled in memory with Add-Type when the module loads, instead of loading Pester.dll.
$home_  = if ($env:CPR_DEV_HOME) { $env:CPR_DEV_HOME } else { Join-Path $HOME '.cpr-dev' }
$ver    = if ($env:PESTER_VER) { $env:PESTER_VER } else { '5.6.1' }
$repo   = Join-Path $home_ 'pester-src'
$out    = Join-Path $home_ "mods/Pester/$ver"
New-Item -ItemType Directory -Force -Path $out | Out-Null

$cs = (Get-ChildItem "$repo/src/csharp/Pester" -Filter *.cs -Recurse | ForEach-Object { "'$($_.FullName)'" }) -join ','
$order = @("$repo/src/functions/Pester.SafeCommands.ps1","$repo/src/Pester.Types.ps1","$repo/src/Pester.State.ps1",
  "$repo/src/Pester.Utility.ps1","$repo/src/Pester.Runtime.ps1","$repo/src/TypeClass.ps1","$repo/src/Format.ps1",
  "$repo/src/Pester.RSpec.ps1","$repo/src/Main.ps1","$repo/src/functions/assertions/*","$repo/src/functions/*","$repo/src/Module.ps1")
$files = Get-ChildItem $order -File | Select-Object -Unique
$sb = [System.Text.StringBuilder]::new()
foreach ($f in $files) {
  $skip = $false
  $null = $sb.AppendLine("# file $($f.FullName)")
  foreach ($l in (Get-Content $f)) {
    if ($l -match '^.*#\s*PESTER_BUILD') { $skip = $true }
    if (-not $skip) {
      if ($f.Name -eq 'Pester.Types.ps1' -and $l -match "Add-Type'\] -Path \`$path") {
        $null = $sb.AppendLine("    if (-not ('PesterConfiguration' -as [type])) { & `$SafeCommands['Add-Type'] -Path @($cs) }")
      } else { $null = $sb.AppendLine($l) }
    }
    if ($l -match '^.*#\s*end\s*PESTER_BUILD') { $skip = $false }
  }
}
$sb.ToString() | Set-Content (Join-Path $out 'Pester.psm1') -Encoding UTF8
foreach ($n in 'Pester.psd1','Pester.Format.ps1xml','Pester.ps1') { Copy-Item "$repo/src/$n" $out -Force }
Copy-Item "$repo/src/en-US" $out -Recurse -Force
if (Test-Path "$repo/src/schemas") { Copy-Item "$repo/src/schemas" $out -Recurse -Force }
# the generated PesterConfiguration.Format.ps1xml needs dotnet to build; drop it from the manifest
(Get-Content "$out/Pester.psd1" -Raw) -replace ", 'PesterConfiguration.Format.ps1xml'", '' | Set-Content "$out/Pester.psd1" -Encoding UTF8
"built Pester $ver from $($files.Count) files into $out"
