# RDK Certificate Generation Scripts

This directory contains modularized scripts for generating and managing RDK test certificates.
The scripts provide a complete PKI infrastructure for testing various certificate-related scenarios.

## Script Overview

### 1. generate_test_rdk_certs.sh
- Main wrapper script that orchestrates the complete certificate generation process
- Handles various failure scenarios (expired, corrupted, revoked certificates)
- Creates a full certificate chain: Root CA → Intermediate CAs → Leaf Certificates

### 2. create_ca.sh
- Creates CA certificates (both root and intermediate)
- Handles CA-specific configurations and key management
- Can create various failure scenarios for CA certificates

### 3. create_leaf_cert.sh
- Creates leaf certificates (server and client) signed by a CA
- Manages certificate signing requests (CSRs)
- Can create various test scenarios with invalid certificates

### 4. cert_utils.sh
- Contains common utility functions used by all scripts
- Centralizes certificate operations like key generation, certificate signing, etc.
- Provides consistent implementation across all certificate types

## Installation

The scripts are installed in Docker images in `/usr/local/share/cert-scripts/` and can be used in two ways:

1. Directly from the installation directory:
   ```bash
   /usr/local/share/cert-scripts/generate_test_rdk_certs.sh [OPTIONS]
   ```

2. Using the symlink at `/etc/pki/scripts/`:
   ```bash
   /etc/pki/scripts/generate_test_rdk_certs.sh [OPTIONS]
   ```

## Certificate Hierarchy

The scripts generate a complete certificate hierarchy with the following structure:

```
Root CA (Test-RDK-root)
├── Server Intermediate CA (Test-RDK-server-ICA)
│   └── Server Certificate (test-rdk-server-cert)
└── Client Intermediate CA (Test-RDK-client-ICA)
    └── Client Certificate (test-rdk-client-cert)
```

## Usage

### Basic Usage
```bash
/etc/pki/scripts/generate_test_rdk_certs.sh
```

### Generate Specific Failure Scenarios
```bash
# Create expired leaf certificate
/etc/pki/scripts/generate_test_rdk_certs.sh --expired-cert

# Create corrupted intermediate CA
/etc/pki/scripts/generate_test_rdk_certs.sh --corrupted-intermediate

# Create certificates with different ECC curves
/etc/pki/scripts/generate_test_rdk_certs.sh --ecc-p384
```
