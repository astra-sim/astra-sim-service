#!/usr/bin/env bash
set -e

echo "Updating system..."
sudo apt update

echo "Installing base packages..."
sudo apt install -y \
python3.11 \
python3-pip \
python3-venv \
python3.11-dev \
coreutils \
wget \
vim \
git \
gcc-11 \
g++-11 \
make \
cmake \
clang-format \
libboost-dev \
libboost-program-options-dev \
libprotobuf-dev \
protobuf-compiler \
openmpi-bin \
openmpi-common \
openmpi-doc \
libopenmpi-dev \
graphviz \
apt-transport-https \
ca-certificates \
gnupg \
lsb-release \
curl \
dos2unix \
ant

echo "Adding Docker repo key..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo "Adding Docker repository..."
echo \
"deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update

echo "Installing Node.js 18..."
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo bash -
sudo apt install -y nodejs

echo "Installing Redoc CLI..."
sudo npm install -g @redocly/cli

echo "Creating workspace..."
mkdir -p ~/workspaces

echo 'export PATH=$HOME/.local/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
echo "Setup complete."
