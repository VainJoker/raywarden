#!/bin/bash

# Get latest version tag
LATEST_TAG=$(curl -s https://api.github.com/repos/dani-garcia/bw_web_builds/releases/latest | jq -r .tag_name)

# Download and extract
wget "https://github.com/dani-garcia/bw_web_builds/releases/download/$LATEST_TAG/bw_web_${LATEST_TAG}.tar.gz"
mkdir -p public
tar -xzf bw_web_${LATEST_TAG}.tar.gz -C public/

# Move files from web-vault subfolder
shopt -s dotglob
mv public/web-vault/* public/
shopt -u dotglob
rmdir public/web-vault
rm bw_web_${LATEST_TAG}.tar.gz