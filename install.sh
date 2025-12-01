#!/bin/sh
# Beltic CLI installer
# Usage: curl -fsSL https://raw.githubusercontent.com/belticlabs/beltic-cli/master/install.sh | sh

set -e

REPO="belticlabs/beltic-cli"
INSTALL_DIR="${BELTIC_INSTALL_DIR:-$HOME/.beltic/bin}"

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        darwin) OS="apple-darwin" ;;
        linux) OS="unknown-linux-gnu" ;;
        *)
            echo "Unsupported OS: $OS"
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64) ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
        *)
            echo "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    echo "${ARCH}-${OS}"
}

# Get latest version from GitHub
get_latest_version() {
    curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | \
        grep '"tag_name":' | \
        sed -E 's/.*"v([^"]+)".*/\1/'
}

main() {
    echo "Installing Beltic CLI..."
    
    PLATFORM=$(detect_platform)
    VERSION=$(get_latest_version)
    
    if [ -z "$VERSION" ]; then
        echo "Failed to get latest version"
        exit 1
    fi
    
    echo "Platform: $PLATFORM"
    echo "Version: $VERSION"
    
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${VERSION}/beltic-${PLATFORM}.tar.gz"
    
    echo "Downloading from: $DOWNLOAD_URL"
    
    # Create install directory
    mkdir -p "$INSTALL_DIR"
    
    # Download and extract
    TEMP_DIR=$(mktemp -d)
    curl -fsSL "$DOWNLOAD_URL" | tar xz -C "$TEMP_DIR"
    
    # Install
    mv "$TEMP_DIR/beltic" "$INSTALL_DIR/beltic"
    chmod +x "$INSTALL_DIR/beltic"
    
    # Cleanup
    rm -rf "$TEMP_DIR"
    
    echo ""
    echo "Beltic CLI installed to: $INSTALL_DIR/beltic"
    echo ""
    
    # Check if install dir is in PATH
    case ":$PATH:" in
        *":$INSTALL_DIR:"*) ;;
        *)
            echo "Add the following to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
            echo ""
            echo "  export PATH=\"\$PATH:$INSTALL_DIR\""
            echo ""
            ;;
    esac
    
    echo "Run 'beltic --help' to get started."
}

main

