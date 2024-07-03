#!/bin/bash

# Atualizar o sistema e instalar pacotes necessários
sudo apt-get update
sudo apt-get install -y python3 python3-pip

# Instalar dependências do Python
pip3 install -r requirements.txt

ZAP_VERSION="2.15.0"
ZAP_DOWNLOAD_URL="https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz"


# Definir o diretório de instalação
INSTALL_DIR="$HOME/zaproxy"

# Criar o diretório de instalação se ele não existir
mkdir -p "$INSTALL_DIR"

# Instalar o OWASP ZAP
echo "Baixando OWASP ZAP versão ${ZAP_VERSION}..."
wget -O "$INSTALL_DIR/ZAP_${ZAP_VERSION}_Linux.tar.gz" "$ZAP_DOWNLOAD_URL"

# Extrair o arquivo tar.gz
echo "Extraindo OWASP ZAP..."
tar -xzf "$INSTALL_DIR/ZAP_${ZAP_VERSION}_Linux.tar.gz" -C "$INSTALL_DIR"

# Navegar para o diretório onde o ZAP foi extraído
cd "$INSTALL_DIR/ZAP_${ZAP_VERSION}"

# Tornar o script zap.sh executável
chmod +x zap.sh

# Criar o arquivo de unidade systemd
SERVICE_FILE=/etc/systemd/system/zap_manager.service

sudo bash -c "cat > $SERVICE_FILE" <<EOL
[Unit]
Description=ZAP Manager Service
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$(pwd)
ExecStart=/usr/bin/python3 $(pwd)/zap_service.py start --ini-file=$(pwd)/targets.ini
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOL

# Recargar o systemd e iniciar o serviço
sudo systemctl daemon-reload
sudo systemctl start zap_manager.service
sudo systemctl enable zap_manager.service

echo "Setup completed successfully."
