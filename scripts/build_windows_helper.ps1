$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

& .\.venv\Scripts\python.exe -m pip install pyinstaller
& .\.venv\Scripts\pyinstaller.exe --noconfirm --clean --onefile --console `
  --name "Port-a-Potty-Helper" `
  --collect-submodules checks `
  --collect-submodules dawgwatch `
  port_a_potty_helper.py

Write-Host "Built: $root\dist\Port-a-Potty-Helper.exe"
