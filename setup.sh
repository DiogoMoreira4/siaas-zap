#!/bin/bash

# Atualizar o sistema e instalar pacotes necessários
sudo apt-get update
sudo apt-get install -y python3 python3-pip openjdk-17-jdk

# Instalar dependências do Python
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
ExecStart=/usr/bin/python3 $(pwd)/zap_service.py start --targets-file=$(pwd)/targets.ini
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOL

# Recargar o systemd e iniciar o serviço
sudo systemctl daemon-reload
sudo systemctl start zap_manager.service
sudo systemctl enable zap_manager.service

echo "Setup completed successfully."
