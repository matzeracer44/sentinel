@echo off
:: ═══════════════════════════════════════════
:: SENTINEL — Quick Installer
:: Doppelklick zum Starten der Installation
:: ═══════════════════════════════════════════
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

:: Starte PowerShell Setup-Skript
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1"

echo.
echo   Installation abgeschlossen.
echo   Druecken Sie eine Taste zum Beenden.
pause >nul
