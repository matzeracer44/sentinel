@echo off
setlocal
title ARGUS - Security Scanner
color 0A

echo.
echo  ========================================================
echo     ARGUS - The All-Seeing Security Tool
echo  ========================================================
echo.

:: ------------------------------------------------------------------
:: 1. Python pruefen
:: ------------------------------------------------------------------
python --version >nul 2>&1
if %errorlevel% neq 0 goto need_python
echo  [OK] Python gefunden
goto python_ok

:need_python
echo  [!!] Python nicht gefunden.
echo.
echo  Lade Python 3.12.4 herunter ...
set "PY_URL=https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe"
set "PY_INSTALLER=%TEMP%\python-3.12.4-amd64.exe"
powershell -Command "Invoke-WebRequest -Uri '%PY_URL%' -OutFile '%PY_INSTALLER%'"
if not exist "%PY_INSTALLER%" (
    echo  [FEHLER] Download fehlgeschlagen.
    echo  Bitte manuell installieren: https://www.python.org/downloads/
    echo  WICHTIG: Haken bei "Add Python to PATH" setzen!
    goto fatal
)
echo  Installiere Python 3.12.4 ...
"%PY_INSTALLER%" /quiet InstallAllUsers=0 PrependPath=1 Include_pip=1 Include_test=0
if %errorlevel% neq 0 (
    echo  [FEHLER] Installation fehlgeschlagen.
    echo  Bitte manuell installieren: https://www.python.org/downloads/
    goto fatal
)
set "PATH=%LOCALAPPDATA%\Programs\Python\Python312\;%LOCALAPPDATA%\Programs\Python\Python312\Scripts\;%PATH%"
echo  [OK] Python installiert

:python_ok

:: ------------------------------------------------------------------
:: 2. venv pruefen / erstellen / aktivieren
:: ------------------------------------------------------------------
if not exist "%~dp0venv\Scripts\activate.bat" (
    echo  [..] Erstelle virtuelle Umgebung ...
    python -m venv "%~dp0venv"
    if %errorlevel% neq 0 (
        echo  [WARNUNG] venv fehlgeschlagen - nutze System-Python
        goto skip_venv
    )
    echo  [OK] venv erstellt
)
call "%~dp0venv\Scripts\activate.bat"
echo  [OK] venv aktiviert

:skip_venv

:: ------------------------------------------------------------------
:: 3. Pakete pruefen - schneller Check ob Flask importierbar ist
::    Wenn ja: alles schon installiert, ueberspringen
::    Wenn nein: pip install ausfuehren
:: ------------------------------------------------------------------
python -c "import flask" >nul 2>&1
if %errorlevel% equ 0 (
    echo  [OK] Pakete bereits installiert
    goto packages_ok
)

echo  [..] Pakete werden installiert ...
python -m pip install --upgrade pip --quiet 2>nul
if not exist "%~dp0requirements.txt" (
    echo  [FEHLER] requirements.txt nicht gefunden!
    goto fatal
)
pip install -r "%~dp0requirements.txt" --quiet
if %errorlevel% neq 0 (
    echo  [WARNUNG] Einige Pakete fehlgeschlagen. Versuche einzeln ...
    for /f "usebackq tokens=1 delims==" %%p in ("%~dp0requirements.txt") do (
        pip install %%p --quiet 2>nul
    )
)
echo  [OK] Pakete installiert

:packages_ok

:: ------------------------------------------------------------------
:: 4. Ordner pruefen
:: ------------------------------------------------------------------
if not exist "%~dp0data"   mkdir "%~dp0data"
if not exist "%~dp0logs"   mkdir "%~dp0logs"
if not exist "%~dp0config" mkdir "%~dp0config"

:: ------------------------------------------------------------------
:: 5. .env pruefen
:: ------------------------------------------------------------------
if not exist "%~dp0.env" (
    if exist "%~dp0.env.example" (
        copy "%~dp0.env.example" "%~dp0.env" >nul
        echo  [OK] .env aus Vorlage erstellt
    ) else (
        echo # ARGUS API Keys> "%~dp0.env"
        echo # Trage deine API-Keys ein und starte ARGUS neu.>> "%~dp0.env"
        echo.>> "%~dp0.env"
        echo ARGUS_VIRUSTOTAL_KEY=DEIN_KEY_HIER>> "%~dp0.env"
        echo ARGUS_ABUSEIPDB_KEY=DEIN_KEY_HIER>> "%~dp0.env"
        echo ARGUS_OTX_KEY=DEIN_KEY_HIER>> "%~dp0.env"
        echo ARGUS_IPINFO_TOKEN=DEIN_KEY_HIER>> "%~dp0.env"
        echo ARGUS_SANDBOX_MODE=true>> "%~dp0.env"
        echo  [OK] .env Vorlage erstellt
    )
    echo.
    echo  --------------------------------------------------------
    echo   HINWEIS: Oeffne .env und trage deine API-Keys ein.
    echo   Ohne Keys laeuft ARGUS im Sandbox-Modus.
    echo  --------------------------------------------------------
    echo.
)

:: ------------------------------------------------------------------
:: 6. Schnelltest - kann main.py geladen werden?
:: ------------------------------------------------------------------
if not exist "%~dp0main.py" (
    echo  [FEHLER] main.py nicht gefunden!
    echo  Stelle sicher, dass start.bat im ARGUS-Hauptordner liegt.
    goto fatal
)

python -c "import flask; import requests; import yaml; import dotenv; import dns" >nul 2>&1
if %errorlevel% neq 0 (
    echo  [FEHLER] Kritische Pakete fehlen. Fuehre install.bat aus.
    goto fatal
)

:: ------------------------------------------------------------------
:: 7. ARGUS starten
:: ------------------------------------------------------------------
echo.
echo  ========================================================
echo   Alles bereit. Starte ARGUS ...
echo   Browser oeffnet sich auf http://127.0.0.1:8080
echo   Zum Beenden: Ctrl+C oder Fenster schliessen
echo  ========================================================
echo.

start "" /min cmd /c "timeout /t 3 /nobreak >nul & start http://127.0.0.1:8080"
python "%~dp0main.py" --web
goto end

:fatal
echo.
echo  ========================================================
echo   ARGUS konnte nicht gestartet werden.
echo   Pruefe die Fehlermeldungen oben.
echo  ========================================================
echo.
pause
exit /b 1

:end
endlocal
