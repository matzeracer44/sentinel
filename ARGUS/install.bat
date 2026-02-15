@echo off
setlocal
title ARGUS Installer
color 0A

echo.
echo  ========================================================
echo     ARGUS - The All-Seeing Security Tool
echo     Automatischer Installer
echo  ========================================================
echo.

:: ------------------------------------------------------------------
:: 0. Admin-Check
:: ------------------------------------------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [INFO] Kein Admin-Modus. Falls Fehler auftreten,
    echo         Rechtsklick - Als Administrator ausfuehren.
    echo.
)

:: ------------------------------------------------------------------
:: 1. Python pruefen / installieren
:: ------------------------------------------------------------------
echo  [1/7] Python pruefen ...

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Python nicht gefunden. Starte Download ...
    echo.

    set "PY_URL=https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe"
    set "PY_INSTALLER=%TEMP%\python-3.12.4-amd64.exe"

    echo  Lade Python 3.12.4 herunter ...
    powershell -Command "Invoke-WebRequest -Uri '%PY_URL%' -OutFile '%PY_INSTALLER%'"
    if not exist "%PY_INSTALLER%" (
        echo  [FEHLER] Download fehlgeschlagen.
        echo  Bitte manuell installieren: https://www.python.org/downloads/
        echo  WICHTIG: Haken bei "Add Python to PATH" setzen!
        pause
        exit /b 1
    )

    echo  Installiere Python 3.12.4 ...
    "%PY_INSTALLER%" /quiet InstallAllUsers=0 PrependPath=1 Include_pip=1 Include_test=0
    if %errorlevel% neq 0 (
        echo  [FEHLER] Python-Installation fehlgeschlagen.
        echo  Bitte manuell installieren: https://www.python.org/downloads/
        pause
        exit /b 1
    )

    set "PATH=%LOCALAPPDATA%\Programs\Python\Python312\;%LOCALAPPDATA%\Programs\Python\Python312\Scripts\;%PATH%"
    echo  [OK] Python installiert.
) else (
    python --version
    echo  [OK] Python gefunden.
)
echo.

:: ------------------------------------------------------------------
:: 2. pip aktualisieren
:: ------------------------------------------------------------------
echo  [2/7] pip aktualisieren ...
python -m pip install --upgrade pip --quiet 2>nul
echo  [OK] pip aktuell.
echo.

:: ------------------------------------------------------------------
:: 3. Virtuelle Umgebung
:: ------------------------------------------------------------------
echo  [3/7] Virtuelle Umgebung pruefen ...

if not exist "%~dp0venv" (
    echo  Erstelle venv ...
    python -m venv "%~dp0venv"
    if %errorlevel% neq 0 (
        echo  [WARNUNG] venv konnte nicht erstellt werden. Nutze System-Python.
        goto skip_venv
    )
    echo  [OK] venv erstellt.
) else (
    echo  [OK] venv existiert bereits.
)

call "%~dp0venv\Scripts\activate.bat"
echo  [OK] venv aktiviert.
echo.

:skip_venv

:: ------------------------------------------------------------------
:: 4. Python-Pakete installieren
:: ------------------------------------------------------------------
echo  [4/7] Python-Pakete installieren ...
echo.

if not exist "%~dp0requirements.txt" (
    echo  [FEHLER] requirements.txt nicht gefunden!
    echo  Stelle sicher, dass install.bat im ARGUS-Hauptordner liegt.
    pause
    exit /b 1
)

pip install -r "%~dp0requirements.txt"
if %errorlevel% neq 0 (
    echo.
    echo  [WARNUNG] Einige Pakete fehlgeschlagen. Versuche einzeln ...
    echo.
    for /f "usebackq tokens=1 delims==" %%p in ("%~dp0requirements.txt") do (
        echo  Installiere %%p ...
        pip install %%p --quiet 2>nul
    )
)

echo.
echo  [OK] Python-Pakete installiert.
echo.

:: ------------------------------------------------------------------
:: 5. Ordnerstruktur
:: ------------------------------------------------------------------
echo  [5/7] Ordnerstruktur pruefen ...

if not exist "%~dp0data"   mkdir "%~dp0data"
if not exist "%~dp0logs"   mkdir "%~dp0logs"
if not exist "%~dp0config" mkdir "%~dp0config"

echo  [OK] Ordner: data/, logs/, config/
echo.

:: ------------------------------------------------------------------
:: 6. .env Datei pruefen
:: ------------------------------------------------------------------
echo  [6/7] Konfiguration pruefen ...

if not exist "%~dp0.env" (
    if exist "%~dp0.env.example" (
        echo  Kopiere .env.example nach .env ...
        copy "%~dp0.env.example" "%~dp0.env" >nul
        echo  [OK] .env aus Vorlage erstellt.
    ) else (
        echo  Erstelle .env Vorlage ...
        echo # ARGUS API Keys> "%~dp0.env"
        echo # Trage hier deine API-Keys ein. Danach ARGUS neu starten.>> "%~dp0.env"
        echo.>> "%~dp0.env"
        echo # VirusTotal  https://www.virustotal.com/gui/join-us>> "%~dp0.env"
        echo ARGUS_VIRUSTOTAL_KEY=DEIN_KEY_HIER>> "%~dp0.env"
        echo.>> "%~dp0.env"
        echo # AbuseIPDB  https://www.abuseipdb.com/register>> "%~dp0.env"
        echo ARGUS_ABUSEIPDB_KEY=DEIN_KEY_HIER>> "%~dp0.env"
        echo.>> "%~dp0.env"
        echo # AlienVault OTX  https://otx.alienvault.com/accounts/signup>> "%~dp0.env"
        echo ARGUS_OTX_KEY=DEIN_KEY_HIER>> "%~dp0.env"
        echo.>> "%~dp0.env"
        echo # IPinfo.io  https://ipinfo.io/signup>> "%~dp0.env"
        echo ARGUS_IPINFO_TOKEN=DEIN_KEY_HIER>> "%~dp0.env"
        echo.>> "%~dp0.env"
        echo # Sandbox-Modus  true = keine echten HTTP-Requests>> "%~dp0.env"
        echo ARGUS_SANDBOX_MODE=true>> "%~dp0.env"
        echo  [OK] .env Vorlage erstellt.
    )
    echo.
    echo  --------------------------------------------------------
    echo   WICHTIG: Oeffne .env und trage deine API-Keys ein!
    echo.
    echo   Kostenlose Keys:
    echo     VirusTotal:   virustotal.com/gui/join-us
    echo     AbuseIPDB:    abuseipdb.com/register
    echo     AlienVault:   otx.alienvault.com/accounts/signup
    echo     IPinfo:       ipinfo.io/signup
    echo.
    echo   Ohne Keys funktioniert ARGUS, aber mit weniger Intel.
    echo  --------------------------------------------------------
    echo.
) else (
    echo  [OK] .env vorhanden.
    findstr /C:"DEIN_KEY_HIER" "%~dp0.env" >nul 2>&1
    if %errorlevel% equ 0 (
        echo  [WARNUNG] .env enthaelt noch Platzhalter-Keys.
        echo             Bitte echte API-Keys eintragen.
    )
)
echo.

:: ------------------------------------------------------------------
:: 7. Verifikation
:: ------------------------------------------------------------------
echo  [7/7] Installation verifizieren ...
echo.

set ALL_OK=1

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [FAIL] Python nicht verfuegbar
    set ALL_OK=0
) else (
    echo  [OK] Python gefunden
)

python -c "import flask; print('  [OK] Flask ' + flask.__version__)" 2>nul
if %errorlevel% neq 0 echo  [FAIL] Flask& set ALL_OK=0

python -c "import requests; print('  [OK] Requests ' + requests.__version__)" 2>nul
if %errorlevel% neq 0 echo  [FAIL] Requests& set ALL_OK=0

python -c "import cryptography; print('  [OK] Cryptography')" 2>nul
if %errorlevel% neq 0 echo  [FAIL] Cryptography& set ALL_OK=0

python -c "import yaml; print('  [OK] PyYAML')" 2>nul
if %errorlevel% neq 0 echo  [FAIL] PyYAML& set ALL_OK=0

python -c "import dotenv; print('  [OK] python-dotenv')" 2>nul
if %errorlevel% neq 0 echo  [FAIL] python-dotenv& set ALL_OK=0

python -c "import psutil; print('  [OK] psutil')" 2>nul
if %errorlevel% neq 0 echo  [FAIL] psutil& set ALL_OK=0

python -c "import bs4; print('  [OK] BeautifulSoup')" 2>nul
if %errorlevel% neq 0 echo  [FAIL] BeautifulSoup& set ALL_OK=0

python -c "import dns; print('  [OK] dnspython')" 2>nul
if %errorlevel% neq 0 echo  [FAIL] dnspython& set ALL_OK=0

python -c "import whois; print('  [OK] python-whois')" 2>nul
if %errorlevel% neq 0 echo  [FAIL] python-whois& set ALL_OK=0

python -c "import validators; print('  [OK] validators')" 2>nul
if %errorlevel% neq 0 echo  [FAIL] validators& set ALL_OK=0

if exist "%~dp0config\config.yaml" (
    echo  [OK] config/config.yaml
) else (
    echo  [INFO] config.yaml fehlt - wird beim Start erstellt
)

if exist "%~dp0main.py" (
    echo  [OK] main.py vorhanden
) else (
    echo  [FAIL] main.py nicht gefunden!
    set ALL_OK=0
)

echo.
echo  ========================================================
if not "%ALL_OK%"=="1" goto install_failed

color 0A
echo.
echo   INSTALLATION ERFOLGREICH
echo.
echo   Starte ARGUS mit:
echo     python main.py --web
echo.
echo   Dann oeffne im Browser:
echo     http://127.0.0.1:8080
echo.
echo  ========================================================
echo.
set /p START_NOW=  ARGUS jetzt starten? (j/n): 
if /i not "%START_NOW%"=="j" goto install_done
echo.
echo  Starte ARGUS ...
timeout /t 2 /nobreak >nul
start "" "http://127.0.0.1:8080"
python "%~dp0main.py" --web
goto install_done

:install_failed
color 0C
echo.
echo   INSTALLATION UNVOLLSTAENDIG
echo.
echo   Einige Komponenten fehlen. Pruefe die Meldungen oben.
echo   Bei Problemen: python -m pip install -r requirements.txt
echo.
echo  ========================================================

:install_done
echo.
pause
endlocal
