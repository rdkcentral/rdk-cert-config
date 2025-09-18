# RDK Certificate Test Scripts

This directory contains scripts for generating test certificates for various PKI testing scenarios. These scripts are designed to help test certificate validation logic by generating both valid certificates and certificates with specific issues.

## Scripts Overview

### Main Scripts:

- **generate_test_rdk_certs.sh**: Main entry point for generating test certificates
- **create_ca.sh**: Creates Certificate Authority certificates (Root or Intermediate)
- **create_leaf_cert.sh**: Creates leaf certificates signed by a CA
- **cert_utils.sh**: Shared utility functions for certificate operations

## Installation

The scripts are installed in Docker images in `/usr/share/cert-scripts/` and can be used in two ways:

1. Directly from the installation directory:
   ```bash
   /usr/share/cert-scripts/generate_test_rdk_certs.sh --type <TYPE> [OPTIONS]
   ```

2. Using the symlink at `/etc/pki/scripts/`:
   ```bash
   /etc/pki/scripts/generate_test_rdk_certs.sh --type <TYPE> [OPTIONS]
   ```

## Usage

### Basic Usage

```bash
./generate_test_rdk_certs.sh --type <TYPE> [OPTIONS]
```

### Required Parameters

- `--type <TYPE>`: Certificate type (must be "server" or "client")
- `--cn <COMMON_NAME>`: Common Name (CN) for the leaf certificate

### Optional Parameters

#### Certificate Curve Options
- `--ecc-p384`: Use ECC curve P-384 (default is P-256)
- `--ecc-p521`: Use ECC curve P-521 (default is P-256)

#### Failure Mode Options
- `--expired-cert`: Generate a leaf certificate that is already expired
- `--expired-intermediate`: Generate an expired intermediate CA
- `--expired-root`: Generate an expired root CA
- `--corrupted-cert`: Generate a corrupted leaf certificate
- `--corrupted-intermediate`: Generate a corrupted intermediate CA
- `--corrupted-root`: Generate a corrupted root CA
- `--revoked-cert`: Generate a revoked leaf certificate
- `--revoked-intermediate`: Generate a revoked intermediate CA
- `--revoked-root`: Generate a revoked root CA
- `--untrusted-root`: Generate a root CA that won't be in the trust store
- `--missing-cert`: Simulate a missing certificate file
- `--cert-key-mismatch`: Generate a certificate with mismatched private key
- `--missing-passcode`: Generate a P12 file with no password
- `--wrong-passcode`: Generate a P12 file with a different password than expected

### Examples

#### Generate standard client certificates
```bash
./generate_test_rdk_certs.sh --type client --cn "rdkclient"
```

#### Generate server certificates with P-384 curve
```bash
./generate_test_rdk_certs.sh --type server --cn "mockxconf" --ecc-p384
```

#### Generate expired client certificate
```bash
./generate_test_rdk_certs.sh --type client --cn "rdkclient" --expired-cert
```

## Certificate Directory Structure

The certificates are organized in a hierarchical directory structure:

```
<output-dir>/
├── Test-RDK-root/                  # Root CA directory
│   ├── certs/                      # Root CA certificates
│   │   └── Test-RDK-root.pem       # Root CA certificate
│   ├── private/                    # Root CA private keys
│   │   └── Test-RDK-root.key       # Root CA private key
│   ├── Test-RDK-root_chain.pem     # Root CA chain file (same as root cert for root CAs)
│   │
│   ├── Test-RDK-<type>-ICA/        # Intermediate CA directory (type = client or server)
│       ├── certs/                  # Intermediate CA certificates
│       │   ├── Test-RDK-<type>-ICA.pem # Intermediate CA certificate
│       │   ├── test-rdk-<type>-cert.pem # Leaf certificate
│       │   └── test-rdk-<type>-cert.p12 # PKCS#12 file with cert and key
│       ├── private/                # Intermediate CA and leaf certificate private keys
│       │   ├── Test-RDK-<type>-ICA.key # Intermediate CA private key
│       │   └── test-rdk-<type>-cert.key # Leaf certificate private key
│       └── Test-RDK-<type>-ICA_chain.pem # Intermediate CA chain file
```

## ECC Curve Information

- **P-256 (prime256v1)**: 256-bit elliptic curve (default)
- **P-384 (secp384r1)**: 384-bit elliptic curve
- **P-521 (secp521r1)**: 521-bit elliptic curve

## Certificate Chain Files

- **fullchain.pem**: Contains the leaf certificate followed by the CA chain (when created)
- **chain.pem**: Contains the CA chain without the leaf certificate
- **[CA_NAME]_chain.pem**: Contains the certificate chain for a CA
  - For root CAs: Contains only the root CA certificate
  - For intermediate CAs: Contains the intermediate CA certificate followed by its parent CA chain

## Docker Integration

For details on how these certificate scripts are used in Docker containers for testing mTLS functionality, please refer to:
- [README-docker-integration.md](./README-docker-integration.md)
