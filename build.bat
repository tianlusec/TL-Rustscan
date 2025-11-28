@echo off
echo [INFO] Checking Rust installation...

where cargo >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Rust - cargo - is not found in your PATH.
    echo [ERROR] Please install Rust from https://rustup.rs/ and restart your terminal.
    pause
    exit /b 1
)

echo [INFO] Rust is installed. Starting build process...
echo [INFO] Building TL-Rustscan in release mode...

cargo build --release

if %errorlevel% neq 0 (
    echo [ERROR] Build failed. Please check the error messages above.
    pause
    exit /b 1
)

echo [INFO] Build successful!
echo [INFO] Creating distribution folder 'dist'...

if not exist "dist" mkdir dist

echo [INFO] Copying executable to 'dist'...
copy "target\release\TL-Rustscan.exe" "dist\TL-Rustscan.exe"

echo.
echo ========================================================
echo [SUCCESS] Tool has been packaged successfully!
echo [OUTPUT] You can find the tool at: dist\TL-Rustscan.exe
echo ========================================================
echo.

pause
