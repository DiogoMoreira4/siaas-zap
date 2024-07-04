#!/bin/bash

# Definir a URL de download da versão desejada do OWASP ZAP
ZAP_VERSION="2.15.0"
ZAP_DOWNLOAD_URL="https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz"

INSTALL_DIR="$HOME/zaproxy"

mkdir -p "$INSTALL_DIR"

wget -O "$INSTALL_DIR/ZAP_${ZAP_VERSION}_Linux.tar.gz" "$ZAP_DOWNLOAD_URL"

tar -xzf "$INSTALL_DIR/ZAP_${ZAP_VERSION}_Linux.tar.gz" -C "$INSTALL_DIR"

cd "$INSTALL_DIR/ZAP_${ZAP_VERSION}"

chmod +x zap.sh

echo "ZAP installed successfully."
