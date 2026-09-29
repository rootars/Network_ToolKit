@echo off
setlocal enabledelayedexpansion

set "VERSION=1.0"
set "VERSION_FULL=1.0.0"
set "PLATFORM=windows"
set "BINARY_NAME=rootipv6-netaudit.exe"
set "ZIP_NAME=rootipv6-netaudit-windows-v%VERSION%.zip"
set "PYTHON=python"

cd /d "%~dp0"

echo [*] ROOTIPV6 NetAudit Toolkit - Release Build v%VERSION_FULL%
echo [*] Platform: %PLATFORM%
echo [*] Binary adi: %BINARY_NAME%
echo.

if not exist "README.md" (
    echo [!] HATA: README.md bulunamadi.
    exit /b 1
)
if not exist "LICENSE" (
    echo [!] HATA: LICENSE bulunamadi.
    exit /b 1
)
if not exist "CHANGELOG.md" (
    echo [!] HATA: CHANGELOG.md bulunamadi.
    exit /b 1
)
if not exist "main.py" (
    echo [!] HATA: main.py bulunamadi.
    exit /b 1
)

if exist "venv\Scripts\activate.bat" (
    call "venv\Scripts\activate.bat"
    set "PYTHON=python"
)

where %PYTHON% >nul 2>&1
if errorlevel 1 (
    echo [!] HATA: Python bulunamadi. Python 3 kurun veya venv olusturun.
    exit /b 1
)

echo [*] Bagimliliklar kuruluyor...
%PYTHON% -m pip install -q --upgrade pip
if errorlevel 1 (
    echo [!] HATA: pip guncellenemedi.
    exit /b 1
)
%PYTHON% -m pip install -q -r requirements-build.txt
if errorlevel 1 (
    echo [!] HATA: Build bagimliliklari kurulamadi.
    exit /b 1
)

if not exist "dist" mkdir dist
if not exist "release" mkdir release

echo [*] Nuitka build baslatiliyor (bu islem birkac dakika surebilir)...
%PYTHON% -m nuitka ^
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
    echo [!] HATA: Nuitka build basarisiz.
    echo     Visual Studio Build Tools veya MSVC kurulu oldugundan emin olun.
    exit /b 1
)

set "DIST_BINARY=dist\rootipv6-netaudit.exe"
if not exist "%DIST_BINARY%" (
    echo [!] HATA: Binary olusturulamadi: %DIST_BINARY%
    exit /b 1
)

copy /Y "%DIST_BINARY%" "release\%BINARY_NAME%" >nul
if errorlevel 1 (
    echo [!] HATA: Binary release klasorune kopyalanamadi.
    exit /b 1
)
echo [+] Binary kopyalandi: release\%BINARY_NAME%

set "STAGING=release\_staging-windows"
if exist "%STAGING%" rmdir /s /q "%STAGING%"
mkdir "%STAGING%"

copy /Y "%DIST_BINARY%" "%STAGING%\%BINARY_NAME%" >nul
copy /Y "README.md" "%STAGING%\" >nul
copy /Y "LICENSE" "%STAGING%\" >nul
copy /Y "CHANGELOG.md" "%STAGING%\" >nul

if exist "release\%ZIP_NAME%" del /f "release\%ZIP_NAME%"

echo [*] ZIP paketi olusturuluyor: release\%ZIP_NAME%
powershell -NoProfile -Command "Compress-Archive -Path '%STAGING%\*' -DestinationPath 'release\%ZIP_NAME%' -Force"
if errorlevel 1 (
    echo [!] HATA: ZIP paketi olusturulamadi. PowerShell 5+ gerekir.
    exit /b 1
)

rmdir /s /q "%STAGING%"

echo.
echo [+] Release paketi hazir!
echo     Binary: release\%BINARY_NAME%
echo     ZIP:    release\%ZIP_NAME%
echo.
echo GitHub Releases icin: release\%ZIP_NAME% dosyasini yukleyin.
echo   Etiket onerisi: v%VERSION_FULL%

endlocal
