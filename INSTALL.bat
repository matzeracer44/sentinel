@echo off
:: =============================================
:: SENTINEL - Quick Installer
:: Doppelklick zum Starten der Installation
:: =============================================
echo.
echo   SENTINEL SECURITY SUITE - Installer
echo   =====================================
echo.
echo   Dieses Skript installiert alle Abhaengigkeiten
echo   und baut Sentinel auf Ihrem System.
echo.
echo   Empfohlen: Als Administrator ausfuehren!
echo   (Rechtsklick -^> "Als Administrator ausfuehren")
echo.
pause

:: Fix encoding (UTF-8 BOM) + line endings (LF to CRLF) for PowerShell 5.1
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$f=Join-Path '%~dp0' 'setup.ps1'; $c=[IO.File]::ReadAllText($f,[Text.Encoding]::UTF8); $c=$c.Replace([char]13+[char]10,[string][char]10).Replace([string][char]10,[char]13+[char]10); [IO.File]::WriteAllText($f,$c,[Text.UTF8Encoding]::new($true))"

:: Starte PowerShell Setup-Skript
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1"

echo.
echo   Installation abgeschlossen.
echo   Druecken Sie eine Taste zum Beenden.
pause >nul
