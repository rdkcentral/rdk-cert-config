# L2 Functional Test Cases for CertSelector

This document combines the **existing L2 (functional/system) test cases** implemented in the CertSelector sample app and additional **proposed L2 test scenarios** to ensure robust coverage of functional behaviors for certificate selection, fallback, and credential management.

---

## 1. Existing L2 Test Cases

These cases are based on the current implementations and sequences in the sample app and test suite (see [certsel_main.c](https://github.com/rdkcentral/rdk-cert-config/blob/develop/test/l2-sampleapp/certsel_main.c) and [certsel_seq.c](https://github.com/rdkcentral/rdk-cert-config/blob/develop/test/l2-sampleapp/certsel_seq.c)).  
**Term mapping:**  
- **Device Operational Cert:** The primary/first certificate (short-lived, operational use).  
- **Static Cert:** The secondary/second certificate (provisioned, longer-term static fallback).  
- **Red Recovery Cert:** The third certificate (special fallback for recovery scenarios).

| Sequence # | Function               | Scenario                                                        |
|:----------:|-----------------------|-----------------------------------------------------------------|
| 1          | `run_seq1cs`          | Device Operational Cert fails, selection falls back to Static Cert; then skips Device Operational Cert if previously failed. |
| 2          | `run_seq2cs`          | Static Cert is pre-marked as bad, selection uses Device Operational Cert; if both fail, falls back to Red Recovery Cert. |
| 3          | `run_seq3cs`          | Device Operational Cert fails (uses Static Cert), then Device Operational Cert is renewed and reused. |
| 4          | `run_seq4cs`          | Device Operational Cert missing, Static Cert fails (uses Red Recovery Cert); Static Cert and then Device Operational Cert are restored and reused in order. |
| 5          | `run_seq5cs`          | Selection fallback from Device Operational Cert to Static Cert, repeated use, network errors, and recovery scenarios. |
| 6          | `run_seq6cs`          | Both Device Operational Cert and Static Cert fail; Red Recovery Cert is used; upon recovery, Device Operational Cert is prioritized again. |
| 7          | `run_dualseq1cs`      | Parallel/dual selection objects test: multiple groups (e.g., Device Operational, Static, Red Recovery) can be in use at once. |
| 8          | `run_badseq1`         | Tests double get/set/free handling and error recovery, cert memory management and state edge cases.           |

**Setup behaviors** (`test_setup.sh`) provide configuration and install files for Device Operational, Static, and Red Recovery certs plus credentials to enable the above flows.

---

## 2. Proposed L2 Functional/System-Level Test Scenarios

The following test cases are designed to extend and harden CertSelector coverage, focusing only on externally visible behaviors under real system/user operations:

### 2.1. Credential Retrieval

- **Credential Retrieval Success**
  - For any configured cert (Device Operational, Static, Red Recovery), verify the corresponding credential is always returned.
- **Credential Reference Not Found**
  - Configure a cert to use a missing credential file; CertSelector should skip it and use the next available fallback.
- **Passphrase Wipe On Retry**
  - Successive selections should never expose prior cert passphrase.

### 2.2. HROT Engine and Property Usage

- **Functional Engine Property Use**
  - Use a config with a specific hrotengine property and ensure it is honored by CertSelector.

### 2.3. Multi-Group and Label Selection

- **Multi-Group Line Match**
  - Use a config where the `group` field is `A1|A2|A3`, request cert for any specific group. Expect a successful selection.
- **Multiple Entry Handling**
  - If more than one config entry matches a group (mixing Device Operational, Static, and Red Recovery Certs), CertSelector should honor order and backup logic in fallback.

### 2.4. Full End-to-End (Integration) Scenarios

- **Happy Path:** All operational, connection established with Device Operational Cert.
- **Negative Path:** All listed certs are invalid/missing; returns error after exhausting all (Device Operational, Static, Red Recovery) options.

---

## 3. Summary Table

| Test Case                       | Scenario Description                                               |
|----------------------------------|-------------------------------------------------------------------|
| Fallback Selection               | Skips bad/missing certs (Device Operational, Static, Red Recovery)|
| Cert Renewal                     | Recovers to prefer newly renewed Device Operational Cert          |
| Backup Cert Dynamic              | Handles backup restore/addition (Static, Red Recovery) at runtime |
| Credential Fetch/Wipe            | Correct credential, wiped on retry, never leaked                  |
| Engine Usage                     | Uses the `hrotengine` value from properties config                |
| Multi-group                      | Selects certs correctly for any valid group in a multi-group line |
| Retry Logic                      | Retries only on cert errors, not network/server/other errors      |
| E2E Flow                         | Confirmed working positive (happy path) and failsafe negative path|

---

## 4. References

- Sample app and sequence source: [`certsel_main.c`](https://github.com/rdkcentral/rdk-cert-config/blob/develop/test/l2-sampleapp/certsel_main.c), [`certsel_seq.c`](https://github.com/rdkcentral/rdk-cert-config/blob/develop/test/l2-sampleapp/certsel_seq.c)
- Configuration reference: [`certsel.cfg`](https://github.com/rdkcentral/rdk-cert-config/blob/develop/CertSelector/conf/certsel.cfg), [`hrot.properties`](https://github.com/rdkcentral/rdk-cert-config/blob/develop/CertSelector/conf/hrot.properties)

---

**Implementing both these existing and L2-proposed test scenarios ensures the CertSelector is resilient and correct in real deployment and system integration scenarios.**
