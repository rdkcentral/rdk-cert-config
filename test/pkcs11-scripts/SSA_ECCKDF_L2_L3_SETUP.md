# SSA ECC KDF Daemon — L2/L3 Test Implementation Guide

> **Scope:** L2/L3 test coverage for the `rdkssaecckdf` daemon (`ssa-cpc`).
> The daemon listens on `/tmp/ssa.sock`, accepts a label (8–32 bytes), and returns
> a 32-byte HMAC-SHA256 derived key computed via the `rdktrusthal` PKCS\#11 stack.
> In L2/L3, the production TEE/libckteec.so is replaced with **SoftHSM** — no
> hardware changes, no source code changes.

---

## 1. What We Are Doing

### Goal
Run the `rdkssaecckdf` daemon end-to-end in a Docker/native test container without
real TEE hardware. The full `ssa-cpc → rdktrusthal → PKCS#11` call chain is
exercised as-is; only the PKCS#11 module and PIN-retrieval library are swapped.

### Architecture

```
 Test Client (test_ecckdf_l2.c)
       │  write(label, 8-32 bytes)
       ▼
 /tmp/ssa.sock
       │
       ▼  [ssa-cpc generic daemon — rdktrhalinterface.c]
 rdkssa_genericDaemon_trhal_connectionHandler()
       │  rdktrHal_sym_decrypt()     → pkcs11_sym_decrypt()
       │  HMAC-SHA256(baseKey, label) → Kderived[32]
       │  write(Kderived, 32)
       ▼
 [rdktrusthal-cpc — pkcs11_api.c]
       │  pkcs11_hal_init(hrothardware.cfg)
       │    ├── dlopen(hrotsupportlib)  →  libsofthsm2.so        ← TEST SWAP
       │    └── dlopen(tltasupportlib) →  libtrhal_tlta_pin_stub.so ← TEST SWAP
       │  pkcs11_hal_check_exists()   → ECC private key at PRIVATE_KEY_ID=11
       │  pkcs11_hal_derive_ecdh()    → reads /etc/ssadaemon/cal_1.bin (SPKI DER)
       │  pkcs11_hal_derive_hkdf()    → HKDF-SHA256, label "RDKCEDMHWKEYING"
       │  pkcs11_hal_validate_interm_key() → reads /etc/ssadaemon/cal_tee_bkh.bin
       │  pkcs11_hal_AESEncrypt()     → AES-CBC wrap of baseKey at AESKEY_ID=12
       ▼
 SoftHSM token (libsofthsm2.so)
       ECC P-256 private key   [ID=11, label=vendor-priv-ecc]
       AES-128 key             [ID=12, label=cedm_dusk]      ← generated at daemon init
       ECDH shared secret      [ID=13, label=cedm_shared_secret] ← derived in-token
       HKDF intermediate key   [ID=14, label=cedm_intermediate]  ← derived in-token
```

### PKCS#11 Object IDs — Test vs. Production

| Object | Production ID | **Test (L2/L3) ID** | Created by |
|--------|:-----------:|:------------------:|------------|
| `PRIVATE_KEY_ID` — ECC P-256 vendor private key | 20 | **11** | `setup-pkcs11.sh` STEP 5 |
| `AESKEY_ID` — AES-128 DUSK equivalent | 35 | **12** | `pkcs11_hal_generate_symkey()` at daemon init |
| `CEDM_SHARED` — ECDH shared secret | 33 | **13** | `pkcs11_hal_derive_ecdh()` at daemon init |
| `CEDM_INTERMEDIATE` — HKDF-derived key | 34 | **14** | `pkcs11_hal_derive_hkdf()` at daemon init |

> IDs 11–14 are intentionally different from production so test tokens cannot be
> confused with real device tokens.

---

## 2. What Is Already Done

### `rdk-cert-config/test/pkcs11-scripts/setup-pkcs11.sh`

| Step | What it does | Status |
|------|-------------|--------|
| STEP 1 | Initialize SoftHSM token `RDK_TOKEN`, SO_PIN=`1234`, USER_PIN=`1234` | ✅ Done |
| STEP 2 | Import mTLS client cert/key at IDs `0x01`, `0x02` | ✅ Done |
| STEP 3 | Write `/etc/ssl/openssl.cnf` with PKCS#11 engine config | ✅ Done |
| STEP 4 | Write `/etc/ssl/certsel/hrot.properties` and full SSA-daemon `hrothardware.cfg` with all 9 fields (`slotid`, `AESKEY_ID`, `PRIVATE_KEY_ID`, `CEDM_SHARED`, `CEDM_INTERMEDIATE`, `hrotsupportlib`, `tltasupportlib`, `basekeyhmac`, `buildpubkey`) | ✅ Done |
| STEP 5 | Generate ECC P-256 device private key → import into SoftHSM at `PRIVATE_KEY_ID=11` (ID=`0x0b`), label `vendor-priv-ecc`; public key imported at same ID | ✅ Done |
| STEP 5b | Generate separate **peer** (build-system) ECC P-256 key pair → export public key as **SubjectPublicKeyInfo DER** → write to `/etc/ssadaemon/cal_1.bin`; private key deleted immediately | ✅ Done |
| STEP 5c | `sed` the real SoftHSM slot number into `hrothardware.cfg` (`slotid=<real_slot>`) | ✅ Done |

**`hrothardware.cfg` as written by STEP 4+5c:**

```ini
# /etc/ssl/certsel/pkcs11/hrothardware.cfg
slotid=<dynamic — patched by STEP 5c>
AESKEY_ID=12
PRIVATE_KEY_ID=11
CEDM_SHARED=13
CEDM_INTERMEDIATE=14
hrotsupportlib=/usr/lib/softhsm/libsofthsm2.so
tltasupportlib=<TLTA_STUB_LIB env var, default /usr/local/lib/libtrhal_tlta_pin_stub.so>
basekeyhmac=/etc/ssadaemon/cal_tee_bkh.bin
buildpubkey=/etc/ssadaemon/cal_1.bin
```

**`cal_1.bin` format:**
`pkcs11_hal_derive_ecdh()` reads the file with `d2i_PUBKEY_bio()` — it must be
**SubjectPublicKeyInfo (SPKI) DER** encoded (~91 bytes), produced by:
```bash
openssl pkey -in peer_priv.pem -pubout -outform DER -out /etc/ssadaemon/cal_1.bin
```
It is **not** a raw 64-byte EC point.

---

### `rdktrusthal-cpc/source/pkcs11/test/trhal_tlta_pin_stub.c`

Test-only shared library replacing the production TLTA/TEE PIN-retrieval library.
Exports exactly `TEE_get_pkcs11_usr_pin(uint8_t *pin_buf)` — the symbol resolved
via `dlsym` in `trhal_pkcstee_api_loader.c`.
Returns PIN `"1234"` (matches the SoftHSM token User PIN).
PIN is never logged.

---

### `rdktrusthal-cpc/source/pkcs11/test/Makefile.am`

Automake target added:

```makefile
lib_LTLIBRARIES = libtrhal_tlta_pin_stub.la
libtrhal_tlta_pin_stub_la_SOURCES = trhal_tlta_pin_stub.c
libtrhal_tlta_pin_stub_la_CFLAGS  = -fPIC
libtrhal_tlta_pin_stub_la_LDFLAGS = -shared -avoid-version
```

Output: `libtrhal_tlta_pin_stub.so`
Set `TLTA_STUB_LIB=<build-dir>/.libs/libtrhal_tlta_pin_stub.so` before running
`setup-pkcs11.sh` to have it inserted into `hrothardware.cfg`.

---

### `ssa-cpc/test/L2-tests/ecckdf/test_ecckdf_l2.c`

Three-test validation binary (`-ldl` only, no extra dependencies):

| Test | What it validates |
|------|------------------|
| **TEST-1** `test_pkcs11_key_present()` | `dlopen(libsofthsm2.so)`, `C_Login`, `C_FindObjects` — confirms ECC private key at `PRIVATE_KEY_ID=11` (ID `0x0b`) exists in the token |
| **TEST-2** `test_pin_stub()` | `dlopen(libtrhal_tlta_pin_stub.so)`, calls `TEE_get_pkcs11_usr_pin()`, `strcmp` against expected User PIN |
| **TEST-3** `test_daemon_socket()` | Connects to `/tmp/ssa.sock`, sends labels of 8, 16, and 32 bytes, reads 32-byte response, confirms correct byte count for each label and a second send of the 8-byte label |

Build:
```bash
gcc -Wall -Werror -Os -o test_ecckdf_l2 test_ecckdf_l2.c -ldl
```

---

### `ssa-cpc/test/L2-tests/ecckdf/Makefile`

Standalone Makefile for the test binary. Mirrors `test/L2-tests/pkcs11-mtls/Makefile`.

---

### `ssa-cpc/configure.ac`

Added:
```
AM_COND_IF([L2TEST], [AC_CONFIG_FILES([test/L2-tests/ecckdf/Makefile])])
```
so the Makefile is registered under `--enable-l2tests`.

---

## 3. What Is Missing

### 3.1 `cal_tee_bkh.bin` — HMAC verification blob

`pkcs11_hal_validate_interm_key()` reads `/etc/ssadaemon/cal_tee_bkh.bin` (32 bytes,
defined as `BASE_KEY_HMAC_PATH` in `pkcs11_api.c`) and compares it against
`HMAC-SHA256(HKDF_key, "CEDM_BK_Verification")` computed inside the token.
If the file is absent, the daemon re-derives the full chain on every run.

**How to generate (one-time bootstrap per token):**
After the first successful daemon init (all ECDH+HKDF steps pass), the function
`pkcs11_hal_derive_IntermKey_HMAC()` writes the HMAC to `/opt/secure/IkVerhmac`.
Copy that file to the expected path:

```bash
sudo mkdir -p /etc/ssadaemon
sudo cp /opt/secure/IkVerhmac /etc/ssadaemon/cal_tee_bkh.bin
sudo chmod 600 /etc/ssadaemon/cal_tee_bkh.bin
```

On all subsequent daemon runs the validation check passes without re-deriving.

---

### 3.2 TEST-3 hash value comparison

The current TEST-3 only confirms that **32 bytes are received**. The design requires
byte-for-byte verification against an independently computed expected HMAC.

**What needs adding:**
- Link with `-lcrypto` (OpenSSL) in addition to `-ldl`
- Accept the test base key via env var `SSA_TEST_BASE_KEY_HEX` (64-char hex)
- Compute `HMAC-SHA256(test_base_key, label)` using `HMAC(EVP_sha256(), ...)`
- `memcmp` actual daemon response against computed expected value
- Print `PASS`/`FAIL` with a hex diff on mismatch — without logging key bytes

Updated Makefile link line:
```makefile
LDFLAGS = -ldl -lcrypto
```

---

### 3.3 Negative-path tests

| Missing test | Expected daemon behaviour |
|-------------|--------------------------|
| Label shorter than 8 bytes | `rdkssa_genericDaemon_trhal_connectionHandler` returns `rdkssaDaemonReadFailure`; client receives EOF or error |
| Label longer than 32 bytes | Same rejection path |
| Socket not yet running | `connect()` returns `ECONNREFUSED`; client exits non-zero with a clear message |

---

### 3.4 Build ordering constraint

The stub `.so` must be built **before** `setup-pkcs11.sh` is run.
If the stub is absent, `hrothardware.cfg` will contain a wrong path and
`rdktrusthal` will fail `dlopen` at daemon init.

**Required ordering:**
```
1. Build libtrhal_tlta_pin_stub.so   (rdktrusthal-cpc)
2. export TLTA_STUB_LIB=<path>.so
3. Run setup-pkcs11.sh
4. Build rdktrusthal + rdkssaecckdf
5. Start daemon
6. Run test_ecckdf_l2
```

---

## 4. How to Test

### Prerequisites

```bash
apt-get install -y softhsm2 opensc openssl libssl-dev libengine-pkcs11-openssl
```

### Step-by-step

```bash
# 1. Build the PIN stub shared library
cd rdktrusthal-cpc
autoreconf --install
./configure --enable-pkcs11 --enable-gtestapp
make
STUB_SO=$(find . -name "libtrhal_tlta_pin_stub.so" | head -1)

# 2. Initialize SoftHSM token and provision all PKCS#11 objects + cal_1.bin
export SOFTHSM2_CONF=/etc/softhsm2.conf
export TLTA_STUB_LIB=$(realpath "$STUB_SO")
bash rdk-cert-config/test/pkcs11-scripts/setup-pkcs11.sh
# After this:
#   SoftHSM token RDK_TOKEN initialized
#   ECC private key at ID 11 (0x0b) in token
#   /etc/ssadaemon/cal_1.bin written (SPKI DER, ~91 bytes)
#   /etc/ssl/certsel/pkcs11/hrothardware.cfg written with correct slotid

# 3. Build ssa-cpc generic daemon (PKCS#11 backend + L2 tests)
cd ssa-cpc
autoreconf --install
./configure --enable-pkcs11 --enable-l2tests
make

# 4. Start the daemon (foreground for first run — confirms init succeeds)
export SOFTHSM2_CONF=/etc/softhsm2.conf
./rdkssaecckdf &
DAEMON_PID=$!

# 5. Wait for socket readiness (max 15 s)
for i in $(seq 1 15); do
    [ -S /tmp/ssa.sock ] && break
    sleep 1
done
[ -S /tmp/ssa.sock ] || { echo "FAIL: daemon socket not ready"; kill $DAEMON_PID; exit 1; }

# 6. Run the L2 test binary
cd ssa-cpc/test/L2-tests/ecckdf
make
export SSA_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export SSA_TOKEN_LABEL=RDK_TOKEN
export SSA_USER_PIN=1234
export SSA_PIN_STUB_LIB=$TLTA_STUB_LIB
./test_ecckdf_l2
# Exit 0 = all tests passed

# 7. Cleanup
kill $DAEMON_PID
```

### Expected output

```
=== SSA-CPC ECC KDF Daemon L2 Validation ===

[TEST-1] PKCS#11 key presence at object ID 0x0b
  [PASS] pkcs11-module-loaded
  [PASS] pkcs11-symbols-resolved
  [PASS] C_Initialize
  [PASS] token-slot-found
  [PASS] C_OpenSession
  [PASS] C_Login
  [PASS] ecc-private-key-at-id-0x0b

[TEST-2] tltasupportlib PIN stub
  [PASS] pin-stub-load
  [PASS] pin-stub-symbol-resolved
  [PASS] pin-stub-return-code
  [PASS] pin-matches-user-pin

[TEST-3] ssa-cpc daemon socket (/tmp/ssa.sock)
  [PASS] daemon-socket-exists
  [PASS] label-8-bytes-response
  [PASS] label-16-bytes-response
  [PASS] label-32-bytes-response
  [PASS] label-8-bytes-determinism-check

=== Results: 12 passed, 0 failed ===
```

---

## 5. How to Integrate

### CI / Docker container additions

Add to the `native-platform` Dockerfile:

```dockerfile
RUN apt-get install -y \
    softhsm2 opensc openssl libssl-dev libengine-pkcs11-openssl
```

### Build system wiring

**rdktrusthal-cpc** — enable PKCS#11 backend and build the PIN stub:
```bash
./configure --enable-pkcs11 --enable-gtestapp
make
# Produces: source/pkcs11/test/.libs/libtrhal_tlta_pin_stub.so
```

**ssa-cpc** — enable PKCS#11 path and L2 tests:
```bash
./configure --enable-pkcs11 --enable-l2tests
make
# Produces: test/L2-tests/ecckdf/test_ecckdf_l2
```

### Single-command test runner

Add `run_l2_ecckdf.sh` alongside `run_l2.sh` in `ssa-cpc/`:

```bash
#!/bin/bash
# run_l2_ecckdf.sh
set -e
export SOFTHSM2_CONF=/etc/softhsm2.conf
STUB_SO=$(find . -name "libtrhal_tlta_pin_stub.so" | head -1)
export TLTA_STUB_LIB=$(realpath "$STUB_SO")
bash rdk-cert-config/test/pkcs11-scripts/setup-pkcs11.sh
./rdkssaecckdf &
DAEMON_PID=$!
for i in $(seq 1 15); do [ -S /tmp/ssa.sock ] && break; sleep 1; done
[ -S /tmp/ssa.sock ] || { echo "FAIL: socket not ready"; kill $DAEMON_PID; exit 1; }
export SSA_USER_PIN=1234
export SSA_PIN_STUB_LIB=$TLTA_STUB_LIB
./test/L2-tests/ecckdf/test_ecckdf_l2
RC=$?
kill $DAEMON_PID
exit $RC
```

### Full dependency chain

```
1. Build libtrhal_tlta_pin_stub.so        [rdktrusthal-cpc]
          │
          ▼
2. setup-pkcs11.sh                        [rdk-cert-config]
   ├── Init SoftHSM token RDK_TOKEN
   ├── Import ECC device key at ID 11 (0x0b)
   ├── Generate /etc/ssadaemon/cal_1.bin  (peer pub key — SPKI DER, ~91 bytes)
   └── Write /etc/ssl/certsel/pkcs11/hrothardware.cfg
          │
          ▼
3. Start rdkssaecckdf daemon              [ssa-cpc]
   ├── pkcs11_hal_init(hrothardware.cfg)
   ├── pkcs11_hal_check_exists()          → confirms ECC key at ID 11
   ├── pkcs11_hal_derive_ecdh()           → reads cal_1.bin (SPKI DER)
   ├── pkcs11_hal_derive_hkdf()
   ├── pkcs11_hal_validate_interm_key()   → reads cal_tee_bkh.bin  ⚠ MISSING on first run
   ├── pkcs11_hal_generate_symkey()       → generates AES key at ID 12 in-token
   └── Listen on /tmp/ssa.sock
          │
          ▼
4. Run test_ecckdf_l2                     [ssa-cpc L2 test]
   ├── TEST-1: PKCS#11 key at ID 0x0b
   ├── TEST-2: PIN stub returns correct PIN
   └── TEST-3: Socket → 32-byte HMAC response per label
```

### `cal_tee_bkh.bin` bootstrap (one-time per token)

On the very first container run, `pkcs11_hal_validate_interm_key()` will fail
(file absent) and the daemon re-derives the full chain. After that first run:

```bash
# The daemon writes the HMAC to /opt/secure/IkVerhmac
sudo mkdir -p /etc/ssadaemon
sudo cp /opt/secure/IkVerhmac /etc/ssadaemon/cal_tee_bkh.bin
sudo chmod 600 /etc/ssadaemon/cal_tee_bkh.bin
```

On all subsequent daemon runs the validation passes without re-deriving.

---

## 6. Testing in Docker

The `native-platform` Docker image (`docker-device-mgt-service-test/native-platform`)
already includes `softhsm2`, `libsofthsm2.so`, `opensc`, and `libengine-pkcs11-openssl`.
`SOFTHSM2_CONF=/etc/softhsm2.conf` is pre-set as an environment variable.

**Two gaps to close before running the L2 tests:**
1. The image clones `rdk-cert-config` from **GitHub tag `1.0.3`** — not the local
   modified `setup-pkcs11.sh` with STEPs 5/5b/5c.
2. `rdktrusthal-cpc` and `ssa-cpc` are **not** built into the image.

---

### Option A — Interactive test (fastest, no image rebuild)

Run the existing image with the local workspace bind-mounted, then build and test
inside the container.

```bash
# From the RDKTRHAL workspace root
docker run -d \
  --name ssa-ecckdf-test \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -v /mnt/home/ldonth501/RDKTRHAL:/workspace \
  -e ENABLE_MTLS=false \
  -e ENABLE_PKCS11=false \
  ghcr.io/rdkcentral/docker-device-mgt-service-test/native-platform:latest \
  /bin/bash -c "while true; do sleep 60; done"

docker exec -it ssa-ecckdf-test /bin/bash
```

Inside the container:

```bash
export SOFTHSM2_CONF=/etc/softhsm2.conf
cd /workspace

# Step 1 — Build the PIN stub (must be done before setup-pkcs11.sh)
cd rdktrusthal-cpc
autoreconf --install
./configure --enable-pkcs11 --enable-gtestapp
make
export TLTA_STUB_LIB=$(realpath $(find . -name "libtrhal_tlta_pin_stub.so" | head -1))
echo "PIN stub: $TLTA_STUB_LIB"

# Step 2 — Provision the SoftHSM token using the LOCAL (not installed) setup script
#   This runs our modified STEPs 1-5c: token init, ECC key at ID 11,
#   cal_1.bin at /etc/ssadaemon/, and hrothardware.cfg with the right slotid.
bash /workspace/rdk-cert-config/test/pkcs11-scripts/setup-pkcs11.sh

# Step 3 — Build ssa-cpc daemon + L2 test binary
cd /workspace/ssa-cpc
autoreconf --install
./configure --enable-pkcs11 --enable-l2tests
make

# Step 4 — Start the daemon
./rdkssaecckdf &
DAEMON_PID=$!
for i in $(seq 1 15); do [ -S /tmp/ssa.sock ] && break; sleep 1; done
[ -S /tmp/ssa.sock ] || { echo "FAIL: socket not ready"; kill $DAEMON_PID; exit 1; }
echo "Daemon ready"

# Step 5 — Run the L2 tests
cd test/L2-tests/ecckdf
make
export SSA_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export SSA_TOKEN_LABEL=RDK_TOKEN
export SSA_USER_PIN=1234
export SSA_PIN_STUB_LIB=$TLTA_STUB_LIB
./test_ecckdf_l2
echo "Exit code: $?"

# Cleanup
kill $DAEMON_PID
```

---

### Option B — Modify the Dockerfile (for CI / repeatable runs)

Three changes are needed in `docker-device-mgt-service-test/native-platform/Dockerfile`:

**1. Replace the GitHub clone of rdk-cert-config with the local copy:**

```dockerfile
# BEFORE (installs GitHub tag 1.0.3):
RUN cd /opt && git clone -b 1.0.3 https://github.com/rdkcentral/rdk-cert-config.git && \
    cd rdk-cert-config && autoreconf --install && ./configure --prefix=/usr/local \
    --enable-testrdkcerts && make && make install && ...

# AFTER (installs from local workspace):
COPY ../../rdk-cert-config /opt/rdk-cert-config
RUN cd /opt/rdk-cert-config && autoreconf --install && \
    ./configure --prefix=/usr/local --enable-testrdkcerts && \
    make && make install && \
    cp RdkConfigApi/src/librdkconfig.a /usr/local/lib/librdkconfig.a && \
    ln -s /usr/local/share/pkcs11-scripts/setup-pkcs11.sh /usr/local/bin/setup-pkcs11.sh && \
    ln -s /usr/local/share/pkcs11-scripts/setup-pkcs11-openssl.sh \
          /usr/local/bin/setup-pkcs11-openssl.sh && \
    cp /usr/local/share/pkcs11-scripts/softhsm2.conf /etc/softhsm2.conf && \
    mkdir -p /opt/patches && \
    cp /usr/local/share/patches/pkcs11_migration_support_p12.patch /opt/patches/ && \
    cd .. && rm -rf /opt/rdk-cert-config
```

**2. Build and install `libtrhal_tlta_pin_stub.so`:**

```dockerfile
COPY ../../rdktrusthal-cpc /opt/rdktrusthal-cpc
RUN cd /opt/rdktrusthal-cpc && autoreconf --install && \
    ./configure --enable-pkcs11 --enable-gtestapp --prefix=/usr/local && \
    make && make install && \
    # Install the PIN stub to the default path that hrothardware.cfg expects
    find . -name "libtrhal_tlta_pin_stub.so" -exec cp {} /usr/local/lib/ \; && \
    ldconfig && \
    cd / && rm -rf /opt/rdktrusthal-cpc
```

**3. Build and install the `rdkssaecckdf` daemon and L2 test binary:**

```dockerfile
COPY ../../ssa-cpc /opt/ssa-cpc
RUN cd /opt/ssa-cpc && autoreconf --install && \
    ./configure --enable-pkcs11 --enable-l2tests --prefix=/usr/local && \
    make && make install && \
    mkdir -p /usr/local/share/ssa-ecckdf-tests && \
    cp test/L2-tests/ecckdf/test_ecckdf_l2 /usr/local/share/ssa-ecckdf-tests/ && \
    cd / && rm -rf /opt/ssa-cpc
```

After these Dockerfile changes, rebuild the image:
```bash
cd docker-device-mgt-service-test
bash build.sh
```

Then run via `compose.yaml` with `ENABLE_PKCS11=true` added to `l2-container`:

```yaml
# In compose.yaml, under l2-container environment:
    environment:
      - ENABLE_MTLS=true
      - ENABLE_PKCS11=true     # ← add this
```

The existing `certs.sh` will automatically call `setup-pkcs11.sh` (which now
has our STEPs 5/5b/5c), then inside the container:

```bash
docker exec -it native-platform /bin/bash
export SSA_USER_PIN=1234
export SSA_PIN_STUB_LIB=/usr/local/lib/libtrhal_tlta_pin_stub.so
rdkssaecckdf &
for i in $(seq 1 15); do [ -S /tmp/ssa.sock ] && break; sleep 1; done
/usr/local/share/ssa-ecckdf-tests/test_ecckdf_l2
```

---

### Environment variables reference

| Variable | Value | Purpose |
|----------|-------|---------|
| `SOFTHSM2_CONF` | `/etc/softhsm2.conf` | Already set in Dockerfile ENV |
| `ENABLE_PKCS11` | `true` | Tells `certs.sh` to run `setup-pkcs11.sh` |
| `TLTA_STUB_LIB` | `/usr/local/lib/libtrhal_tlta_pin_stub.so` | Path written into `hrothardware.cfg` as `tltasupportlib` |
| `SSA_USER_PIN` | `1234` | Test-only; passed to `test_ecckdf_l2` for PIN comparison (never logged) |
| `SSA_PKCS11_MODULE` | `/usr/lib/softhsm/libsofthsm2.so` | SoftHSM module path for TEST-1 |
| `SSA_TOKEN_LABEL` | `RDK_TOKEN` | SoftHSM token label for TEST-1 |
| `SSA_PIN_STUB_LIB` | `/usr/local/lib/libtrhal_tlta_pin_stub.so` | Stub path for TEST-2 |

---

## File Location Summary

| File | Repository | Path |
|------|-----------|------|
| Token init + key provisioning script | `rdk-cert-config` | `test/pkcs11-scripts/setup-pkcs11.sh` |
| PIN stub C source | `rdktrusthal-cpc` | `source/pkcs11/test/trhal_tlta_pin_stub.c` |
| PIN stub build rules | `rdktrusthal-cpc` | `source/pkcs11/test/Makefile.am` |
| L2 test binary source | `ssa-cpc` | `test/L2-tests/ecckdf/test_ecckdf_l2.c` |
| L2 test standalone Makefile | `ssa-cpc` | `test/L2-tests/ecckdf/Makefile` |
| Autoconf L2TEST registration | `ssa-cpc` | `configure.ac` |
| Runtime config (generated by setup script) | container | `/etc/ssl/certsel/pkcs11/hrothardware.cfg` |
| Peer public key blob (generated by setup script) | container | `/etc/ssadaemon/cal_1.bin` |
| HMAC verification blob (bootstrap, one-time) | container | `/etc/ssadaemon/cal_tee_bkh.bin` |
