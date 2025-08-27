#!/bin/bash
# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root" >&2
    echo "Try running with sudo: sudo $0" >&2
    exit 1
fi

# Set proper script path
SCRIPT_DIR=$(dirname $(realpath $0))
INSTALL_DIR="/usr/local/share/cert-scripts"

# Create directories if they don't exist
mkdir -p ${INSTALL_DIR}
mkdir -p /etc/pki

# Copy scripts to installation directory
cp -f ${SCRIPT_DIR}/*.sh ${INSTALL_DIR}/

# Make scripts executable
chmod +x ${INSTALL_DIR}/*.sh

# Create a symbolic link to the scripts directory
ln -sf ${INSTALL_DIR} /etc/pki/scripts

echo "Certificate scripts installed at ${INSTALL_DIR} and linked at /etc/pki/scripts"
echo "Run /etc/pki/scripts/generate_test_rdk_certs.sh to generate test certificates"

# Create default OpenSSL config if it doesn't exist
if [ ! -f "/etc/pki/openssl.cnf" ]; then
    echo "Creating default OpenSSL configuration at /etc/pki/openssl.cnf"
    ${INSTALL_DIR}/cert_utils.sh
fi
