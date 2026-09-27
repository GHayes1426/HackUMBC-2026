$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

& .\.venv\Scripts\python.exe -m pip install pyinstaller
& .\.venv\Scripts\pyinstaller.exe --noconfirm --clean --onefile --noconsole `
  --name "Port-a-Potty" `
  --add-data "html;html" `
  --add-data "frontend;frontend" `
  --add-data "sample_data;sample_data" `
  port_a_potty_launcher.py

Write-Host "Built: $root\dist\Port-a-Potty.exe"
