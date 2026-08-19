$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
python .\run_demo.py
Write-Host ""
Write-Host "Demonstration complete. Open demo_output\02-blocked-change\map.html"

