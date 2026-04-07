param(
    [int]$Port = 7860
)

$env:PORT = "$Port"
Write-Host "Starting server on port $Port"
& c:/Users/Keerthipriya/OneDrive/Desktop/openenv/.venv-1/Scripts/python.exe server/app.py
