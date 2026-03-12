# RDK Certificate Test Scripts
Scripts to generate deterministic test PKI material for client/server mTLS scenarios, including valid chains and targeted failure cases.

## what’s here

- generate_test_rdk_certs.sh — main entry point to generate a full chain (Root CA → Intermediate CA → Leaf)
- create_ca.sh — creates a Root CA or an Intermediate CA
- create_leaf_cert.sh — creates a leaf cert signed by a selected CA
- cross_sign_roots.sh — cross-signs root CAs to establish trust between separate PKI hierarchies
- cert_utils.sh — shared helpers (OpenSSL config, CSR, chain, PKCS#12, revoke/corrupt, logging)

## install & invoke

When installed, scripts live at `/usr/share/cert-scripts/` with a symlink at `/etc/pki/scripts/`.

- Direct path:
   ```bash
   /usr/share/cert-scripts/generate_test_rdk_certs.sh --type <server|client> --cn <CN> [options]
   ```
- Via symlink:
   ```bash
   /etc/pki/scripts/generate_test_rdk_certs.sh --type <server|client> --cn <CN> [options]
   ```

Notes:
- OpenSSL must be available in PATH.
- Output base directory is fixed at `/etc/pki` (see layout below).
- Set `DEBUG_ENABLED=true` to see verbose trace from the utilities.

## quick start

- Client cert (default P‑256):
   ```bash
   /etc/pki/scripts/generate_test_rdk_certs.sh --type client --cn rdkclient
   ```
- Server cert with P‑384:
   ```bash
   /etc/pki/scripts/generate_test_rdk_certs.sh --type server --cn mockxconf --key-type ecc --key-size secp384r1
   ```
- Expired client leaf:
   ```bash
   /etc/pki/scripts/generate_test_rdk_certs.sh --type client --cn rdkclient --expired-cert
   ```

## cli reference (top-level)

Required
- `--type <server|client>`: leaf cert type
- `--cn <COMMON_NAME>`: CN for the leaf certificate

Key options
- `--key-type <rsa|ecc>` key algorithm (auto-selected: server→RSA, client→ECC)
- `--key-size <size>` RSA bits (default: 2048) or ECC curve (default: prime256v1)
   - ECC curves: prime256v1 (P-256), secp384r1 (P-384), secp521r1 (P-521)

Failure modes
- `--expired-cert` expired leaf certificate
- `--expired-intermediate` expired intermediate CA
- `--expired-root` expired root CA
- `--corrupted-cert` corrupt leaf certificate
- `--corrupted-intermediate` corrupt intermediate CA
- `--corrupted-root` corrupt root CA
- `--revoked-cert` revoke leaf (CRL produced)
- `--revoked-intermediate` revoke intermediate (CRL produced under parent CA)
- `--revoked-root` not implemented (warns only)
- `--untrusted-root` also creates an alternate root not intended for trust
- `--missing-cert` simulate missing leaf pem
- `--cert-key-mismatch` mismatch leaf key vs cert
- `--missing-passcode` create P12 without a password
- `--wrong-passcode` create P12 with wrong password

Notes
- For more granular control, `create_ca.sh` and `create_leaf_cert.sh` expose:
   - `--key-type {rsa|ecc}` (auto-selected: server→RSA, client→ECC)
   - `--key-size <size>` (RSA: bits like 2048; ECC: curve like prime256v1)
   - `--validity <days>` (default 1 day for both CA and leaf; use --validity to specify longer periods)
   - `--pathlen <N>` for intermediates; defaults derive from parent pathlen

## creating CAs directly

For cases where you need more control than `generate_test_rdk_certs.sh` provides, use `create_ca.sh` to create root or intermediate CAs directly.

### usage

```bash
/etc/pki/scripts/create_ca.sh --ca-name <CA_NAME> --parent-ca <PARENT_CA> [OPTIONS]
```

Required options:
- `--ca-name <NAME>` — Name of the CA to create
- `--parent-ca <NAME>` — Name of the parent CA to sign with
  - If same as `--ca-name`, creates a **root CA** (self-signed)
  - If different, creates an **intermediate CA** signed by the parent

Optional:
- `--pathlen <NUM>` — Path length constraint (default: 5 for root, auto-calculated for intermediate)
- `--validity <DAYS>` — Validity period in days (default: 1)
- `--key-type <TYPE>` — Key type: `rsa` or `ecc` (default: ecc)
- `--key-size <SIZE>` — RSA key size in bits (default: 2048) or ECC curve name (default: prime256v1)
  - ECC curves: prime256v1 (P-256), secp384r1 (P-384), secp521r1 (P-521)
- `--expired` — Generate an expired CA certificate
- `--corrupted` — Generate a corrupted CA certificate
- `--revoked` — Generate a revoked CA certificate
- `--help` — Display help message

### examples

Create a root CA with 10-year validity:
```bash
/etc/pki/scripts/create_ca.sh --ca-name "My-Root-CA" --parent-ca "My-Root-CA" --validity 3650
```

Create an intermediate CA signed by the root:
```bash
/etc/pki/scripts/create_ca.sh --ca-name "My-Intermediate-CA" --parent-ca "My-Root-CA" --validity 1825
```

Create an RSA-based root CA:
```bash
/etc/pki/scripts/create_ca.sh --ca-name "RSA-Root" --parent-ca "RSA-Root" --key-type rsa --key-size 4096 --validity 3650
```

## creating leaf certificates directly

Use `create_leaf_cert.sh` to create leaf certificates signed by an existing CA.

### usage

```bash
/etc/pki/scripts/create_leaf_cert.sh --cert-name <CERT_NAME> --ca-name <CA_NAME> [OPTIONS]
```

Required options:
- `--cert-name <NAME>` — Name of the certificate to create
- `--ca-name <NAME>` — Name of the CA to sign with
- `--cn <COMMON_NAME>` — Common Name for the certificate

Optional:
- `--type <TYPE>` — Certificate type: `server` or `client` (default: client)
- `--validity <DAYS>` — Validity period in days (default: 1)
- `--key-type <TYPE>` — Key type: `rsa` or `ecc` (auto-selected: server→RSA, client→ECC)
- `--key-size <SIZE>` — RSA key size in bits or ECC curve name (default depends on key type: RSA: 2048, ECC: prime256v1)
  - ECC curves: prime256v1 (P-256), secp384r1 (P-384), secp521r1 (P-521)
- `--expired` — Generate an expired certificate
- `--corrupted` — Generate a corrupted certificate
- `--revoked` — Generate a revoked certificate
- `--key-mismatch` — Generate a certificate with mismatched private key
- `--no-password` — Generate a P12 file with no password
- `--wrong-password` — Generate a P12 file with incorrect password
- `--missing-cert` — Simulate a missing certificate file
- `--help` — Display help message

### examples

Create a standard client certificate with 1-year validity:
```bash
/etc/pki/scripts/create_leaf_cert.sh --cert-name "client-cert" --ca-name "My-Intermediate-CA" --cn "client-cert" --validity 365
```

Create a server certificate:
```bash
/etc/pki/scripts/create_leaf_cert.sh --cert-name "server-cert" --ca-name "My-Intermediate-CA" --type server --cn "example.com" --validity 365
```

Create an expired client certificate (for testing):
```bash
/etc/pki/scripts/create_leaf_cert.sh --cert-name "expired-client" --ca-name "My-Intermediate-CA" --cn "expired-client" --expired
```

Create a P-384 ECC client certificate:
```bash
/etc/pki/scripts/create_leaf_cert.sh --cert-name "p384-client" --ca-name "My-Intermediate-CA" --cn "p384-client" --key-type ecc --key-size secp384r1 --validity 365
```

## cross-signing root CAs

Cross-signing establishes trust between separate PKI hierarchies by having one root CA sign another root CA's public key.

The script supports two modes:
- Standard mode: Use --source-root <NAME> to cross-sign a root CA (requires private key).
- Certificate-only mode: Use --source-cert <PATH> to cross-sign using just a certificate file (no private key needed).

### usage

```bash
/etc/pki/scripts/cross_sign_roots.sh --source-root <SOURCE_ROOT> --signing-root <SIGNING_ROOT> [OPTIONS]
/etc/pki/scripts/cross_sign_roots.sh --source-cert <PATH> --signing-root <SIGNING_ROOT> [OPTIONS]
```

Required options:
- `--source-root <NAME>` — Name of the root CA to be cross-signed (standard mode)
- `--source-cert <PATH>` — Path to the certificate file to be cross-signed (certificate-only mode)
- `--signing-root <NAME>` — Name of the root CA that will sign

Optional:
- `--output-name <NAME>` — Name for the cross-signed certificate (default: `<source-root>-cross-signed-by-<signing-root>` or `<cert>-cross-signed-by-<signing-root>`)
- `--validity <DAYS>` — Validity period in days (default: auto-calculated as minimum of source and signing root remaining validity)
- `--help` — Display help message

Certificate-only mode notes:
- Use `--source-cert <PATH>` when you only have the certificate file and not the private key.
- Works with any OpenSSL version; uses a synthetic cross-signed certificate.
- Subject DN is preserved from the source certificate.
- `basicConstraints` (including `pathlen`) and `keyUsage` are reconstructed from the source, preserving `critical` flags. `extendedKeyUsage` is forwarded if present.
- `subjectKeyIdentifier` is always recomputed as `hash` (valid because the same public key is copied). `authorityKeyIdentifier` is always set to reference the signing CA — it is never copied from the source, as cross-signing requires it to point to the new issuer.


### examples

Create unidirectional trust (certificates under Root-CA-A trusted by systems trusting Root-CA-B):
```bash
/etc/pki/scripts/cross_sign_roots.sh --source-root "Root-CA-A" --signing-root "Root-CA-B"
```

Cross-sign using only a certificate file:
```bash
/etc/pki/scripts/cross_sign_roots.sh --source-cert "/etc/pki/Root-CA-A/certs/Root-CA-A.pem" --signing-root "Root-CA-B"
```

Create bidirectional trust (run cross-signing in both directions):
```bash
/etc/pki/scripts/cross_sign_roots.sh --source-root "Root-CA-A" --signing-root "Root-CA-B"
/etc/pki/scripts/cross_sign_roots.sh --source-root "Root-CA-B" --signing-root "Root-CA-A"
```

Specify custom validity period:
```bash
/etc/pki/scripts/cross_sign_roots.sh --source-root "Root-CA-A" --signing-root "Root-CA-B" --validity 1825
```

### outputs

Cross-signed certificates are placed in the signing root's directory:

```
/etc/pki/
└─ Root-CA-B/
    ├─ cross-signed/
    │  ├─ Root-CA-A-cross-signed-by-Root-CA-B.pem        # Cross-signed certificate
    │  └─ Root-CA-A-cross-signed-by-Root-CA-B_chain.pem  # Full chain (cross-signed + signing root)
    └─ csr/
       └─ Root-CA-A-cross-signed-by-Root-CA-B.csr        # CSR (for reference)
```

### verifying certificates across hierarchies

To verify a leaf certificate from Source Root using Signing Root as trust anchor:

```bash
# All intermediate certificates must be included in the untrusted chain
openssl verify -CAfile /etc/pki/Signing-Root/certs/Signing-Root.pem \
  -untrusted /etc/pki/Source-Root/Intermediate-CA/certs/Intermediate-CA.pem \
  -untrusted /etc/pki/Signing-Root/cross-signed/Source-Root-cross-signed-by-Signing-Root.pem \
  /etc/pki/Source-Root/Intermediate-CA/certs/leaf.pem
```

Or create a bundle with all intermediate certificates:
```bash
cat /etc/pki/Source-Root/Intermediate-CA/certs/Intermediate-CA.pem \
    /etc/pki/Signing-Root/cross-signed/Source-Root-cross-signed-by-Signing-Root.pem \
    > chain_bundle.pem

openssl verify -CAfile /etc/pki/Signing-Root/certs/Signing-Root.pem \
  -untrusted chain_bundle.pem \
  /etc/pki/Source-Root/Intermediate-CA/certs/leaf.pem
```

### notes on cross-signing

- Both root CAs must already exist before cross-signing
- Cross-signing creates a unidirectional trust by default
- For bidirectional trust, cross-sign in both directions (swap source and signing roots)
- The cross-signed certificate preserves the exact subject DN from the source root (including field order)
- Validity period is automatically calculated as the minimum of both roots' remaining validity to prevent expiration mismatches
- Cross-signed certificates use v3_ca extensions and SHA-256 signing



## outputs & layout

Base directory: `/etc/pki` (created on demand). The OpenSSL config is written to `/etc/pki/openssl.cnf` on first use.

Structure for a generated chain (example CN = rdkclient, type = client):

```
/etc/pki/
├─ openssl.cnf
└─ Test-RDK-root/                          # Root CA
    ├─ certs/Test-RDK-root.pem              # Root CA cert
    ├─ private/Test-RDK-root.key            # Root CA key
    ├─ csr/  crl/
    ├─ Test-RDK-root_chain.pem              # Root chain (same as root cert)
    ├─ Test-RDK-client-ICA/                 # Intermediate CA for clients
    │  ├─ certs/Test-RDK-client-ICA.pem     # Intermediate CA cert
    │  ├─ private/Test-RDK-client-ICA.key   # Intermediate CA key
    │  ├─ csr/  crl/
    │  ├─ Test-RDK-client-ICA_chain.pem     # Intermediate + root
    │  ├─ certs/rdkclient.pem               # Leaf certificate
    │  ├─ certs/rdkclient.p12               # PKCS#12 (password: changeit unless overridden via flags)
    │  └─ private/rdkclient.key             # Leaf private key
    └─ Test-RDK-server-ICA/                 # Intermediate CA for servers (when generated)
         ├─ certs/Test-RDK-server-ICA.pem
         ├─ private/Test-RDK-server-ICA.key
         ├─ csr/  crl/
         └─ Test-RDK-server-ICA_chain.pem
```

Leaf chain files
- The scripts don’t emit a separate `fullchain.pem` for leaves. Use the leaf cert together with the appropriate `*_chain.pem` from the issuing CA when needed, or extract a full chain as required.

Revocation
- When revocation is requested, a CRL file is produced under the `crl/` directory of the issuing CA (or its parent for intermediate CA revocation).
