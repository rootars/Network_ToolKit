@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

set "PYTHON=python"

if exist "venv\Scripts\activate.bat" (
    call "venv\Scripts\activate.bat"
    set "PYTHON=python"
)

echo [*] Bagimliliklar kuruluyor...
"%PYTHON%" -m pip install -q --upgrade pip
"%PYTHON%" -m pip install -q -r requirements-build.txt

if not exist "dist" mkdir dist

echo [*] Nuitka build baslatiliyor...
"%PYTHON%" -m nuitka ^
  --onefile ^
  --follow-imports ^
  --enable-plugin=multiprocessing ^
  --output-dir=dist ^
  --output-filename=rootipv6-netaudit ^
  --remove-output ^
  --lto=yes ^
  --python-flag=-O ^
  --assume-yes-for-downloads ^
  --windows-console-mode=force ^
  --include-package=modules ^
  --include-package=colorama ^
  --include-package-data=colorama ^
  --include-package=dns ^
  --include-package=pysnmp ^
  --include-package=pyasn1 ^
  --include-package=netaddr ^
  --include-package-data=netaddr ^
  main.py

if errorlevel 1 (
    echo [!] Build basarisiz.
    exit /b 1
)

echo [+] Build tamamlandi: dist\rootipv6-netaudit.exe
