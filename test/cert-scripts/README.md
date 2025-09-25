# RDK Certificate Test Scripts

Scripts to generate deterministic test PKI material for client/server mTLS scenarios, including valid chains and targeted failure cases.

## what’s here

- generate_test_rdk_certs.sh — main entry point to generate a full chain (Root CA → Intermediate CA → Leaf)
- create_ca.sh — creates a Root CA or an Intermediate CA
- create_leaf_cert.sh — creates a leaf cert signed by a selected CA
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
   /etc/pki/scripts/generate_test_rdk_certs.sh --type server --cn mockxconf --ecc-p384
   ```
- Expired client leaf:
   ```bash
   /etc/pki/scripts/generate_test_rdk_certs.sh --type client --cn rdkclient --expired-cert
   ```

## cli reference (top-level)

Required
- `--type <server|client>`: leaf cert type
- `--cn <COMMON_NAME>`: CN for the leaf certificate

Curve options
- `--ecc-p384` use P‑384 (secp384r1)
- `--ecc-p521` use P‑521 (secp521r1)
   - Default is P‑256 (prime256v1)

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
   - `--ecc-curve {prime256v1|secp384r1|secp521r1}`
   - `--validity <days>` (root default 3650; leaf default 365)
   - `--pathlen <N>` for intermediates; defaults derive from parent pathlen

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
