#!/bin/bash
# pqscan installer
# Usage: curl -sSfL https://raw.githubusercontent.com/Hacker21-punk/pqscan/main/install.sh | bash

set -e

REPO="Hacker21-punk/pqscan"
VERSION="v0.1.0"
INSTALL_DIR="/usr/local/bin"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case $ARCH in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  arm64)   ARCH="arm64" ;;
  *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case $OS in
  linux)  BINARY="pqscan-linux-${ARCH}" ;;
  darwin) BINARY="pqscan-darwin-${ARCH}" ;;
  *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

echo "Installing pqscan ${VERSION} for ${OS}/${ARCH}..."

URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY}"

# Download
curl -sSfL "$URL" -o /tmp/pqscan
chmod +x /tmp/pqscan

# Install
if [ -w "$INSTALL_DIR" ]; then
  mv /tmp/pqscan "$INSTALL_DIR/pqscan"
else
  sudo mv /tmp/pqscan "$INSTALL_DIR/pqscan"
fi

echo ""
echo "✅ pqscan installed successfully!"
echo ""
echo "Usage:"
echo "  pqscan google.com"
echo "  pqscan --format html -o report.html example.com"
echo ""
pqscan --version
