

echo "[INFO] Checking Rust installation..."

if ! command -v cargo &> /dev/null; then
    echo "[ERROR] Rust - cargo - is not found in your PATH."
    echo "[ERROR] Please install Rust from https://rustup.rs/ and restart your terminal."
    exit 1
fi

echo "[INFO] Rust is installed. Starting build process..."
echo "[INFO] Building TL-Rustscan in release mode..."

cargo build --release

if [ $? -ne 0 ]; then
    echo "[ERROR] Build failed. Please check the error messages above."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "[HINT] On macOS, ensure you have OpenSSL installed: brew install openssl@3"
    fi
    exit 1
fi

echo "[INFO] Build successful!"
echo "[INFO] Creating distribution folder 'dist'..."

mkdir -p dist

echo "[INFO] Copying executable to 'dist'..."

if [ -f "target/release/TL-Rustscan" ]; then
    cp target/release/TL-Rustscan dist/TL-Rustscan
    chmod +x dist/TL-Rustscan
else
    echo "[WARNING] Could not find binary at target/release/TL-Rustscan"
fi

echo ""
echo "========================================================"
echo "[SUCCESS] Tool has been packaged successfully!"
echo "[OUTPUT] You can find the tool at: dist/TL-Rustscan"
echo "========================================================"
echo ""
