#!/bin/bash

# Atualizar o sistema e instalar pacotes necessários
sudo apt-get update
sudo apt-get install -y python3 python3-pip openjdk-17-jdk

echo "Setting up Python virtual environment..."
VENV_DIR="venv_zap"
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    echo "Virtual environment created at $(pwd)/$VENV_DIR"
else
    echo "Virtual environment already exists at $(pwd)/$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

#Instalar o ZAP
INSTALL_ZAP_SCRIPT="./zap_installation.sh"

if [ -f "$INSTALL_ZAP_SCRIPT" ]; then
    echo "Installing ZAP..."
    
    chmod +x "$INSTALL_ZAP_SCRIPT"
    
    "$INSTALL_ZAP_SCRIPT"
    
    if [ $? -eq 0 ]; then
        echo "Installation finished"
    else
        echo "Installation failed"
        exit 1
    fi
else
    echo "Script to install ZAP not found"
    exit 1
fi

# Instalar dependências do Python
echo "Installing requirements..."
pip3 install -r requirements.txt

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
ExecStart=$(pwd)/$VENV_DIR/bin/python3 $(pwd)/zap_service.py start --targets-file=$(pwd)/targets.ini

[Install]
WantedBy=multi-user.target
EOL

# Recargar o systemd
sudo systemctl daemon-reload

echo "Setup completed successfully."
