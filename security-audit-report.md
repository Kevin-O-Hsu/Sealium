# Security Audit Report

**Project**: Sealium (软件许可 / 激活系统)
**Date**: 2026-07-10
**Auditor**: Claude Security Audit
**Frameworks**: OWASP Top 10:2025 + NIST CSF 2.0
**Mode**: full (Phases 1–5)
**Version audited**: 1.1.0 (src/sealium, commit `af2eb63`)

---

## Executive Summary

| Metric | Count |
|--------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 5 |
| 🟢 Low | 4 |
| 🔵 Informational | 3 |
| 🔲 Gray-box findings | 1 |
| 📍 Security hotspots | 7 |
| 🧹 Code smells | 5 |
| **Total findings** | **22** |

**Overall Risk Assessment**: The cryptographic core is genuinely strong — RSA‑4096‑OAEP/SHA‑256 key wrapping + AES‑256‑GCM with correct nonces, parameterised SQL (no injection), CSPRNG‑generated 128‑bit codes, and a well‑factored, side‑effect‑free import model. The serious problems are in **concurrency / business‑logic atomicity and defence‑in‑depth**, not in the crypto. The headline issue is a non‑atomic check‑then‑act in activation binding that lets **one license activate an unbounded number of machines** under concurrent load (verified: 20/20 machines activated on a single code). Secondary issues are weak anti‑replay, an overly permissive default CORS, no rate limiting, exposed API docs, and unencrypted at‑rest key material. None of the findings expose secrets in source or git history (both verified clean).

---

## OWASP Top 10:2025 Coverage

| OWASP ID | Category | Findings | Status |
|----------|----------|----------|--------|
| A01:2025 | Broken Access Control | 0 | ✅ Acceptable (no auth model; verb tampering blocked, 405) |
| A02:2025 | Security Misconfiguration | 4 | 🟠 Needs Attention |
| A03:2025 | Software Supply Chain Failures | 1 | 🟡 Needs Attention |
| A04:2025 | Cryptographic Failures | 2 | 🟡 Needs Attention (crypto primitives correct; key handling gaps) |
| A05:2025 | Injection | 0 | ✅ Acceptable (100% parameterised SQL; no eval/exec/pickle) |
| A06:2025 | Insecure Design | 4 | 🔴 Needs Attention (race, weak replay, no rate limit, fallback) |
| A07:2025 | Authentication Failures | 1 | 🟡 Needs Attention (no throttle on the activation “credential”) |
| A08:2025 | Software or Data Integrity Failures | 0 | ✅ Acceptable (no unsafe deserialisation; AES‑GCM authenticates) |
| A09:2025 | Security Logging and Alerting Failures | 0* | 🟡 Needs Attention (no security event logging/alerting at all) |
| A10:2025 | Mishandling of Exceptional Conditions | 2 | 🟡 Needs Attention |

*A09 carries no numbered finding because the absence is total — see Recommendations.*

---

## NIST CSF 2.0 Coverage

| Function | Categories | Findings | Status |
|----------|-----------|----------|--------|
| GV (Govern) | GV.OC, GV.RM, GV.RR, GV.PO, GV.OV, GV.SC | 2 | 🟠 Needs Attention (supply chain, threat modelling) |
| ID (Identify) | ID.AM, ID.RA, ID.IM | 0 | ✅ Acceptable |
| PR (Protect) | PR.AA, PR.AT, PR.DS, PR.PS, PR.IR | 8 | 🟠 Needs Attention |
| DE (Detect) | DE.CM, DE.AE | 2 | 🔴 Needs Attention (no detection/alerting) |
| RS (Respond) | RS.MA, RS.AN, RS.CO, RS.MI | 0 | 🔴 Needs Attention (no incident response hooks) |
| RC (Recover) | RC.RP, RC.CO | 0 | ✅ Acceptable |

---

## Compliance Coverage

| Framework | Coverage | Details |
|-----------|----------|---------|
| CWE | 14 unique CWEs | CWE-362, CWE-367, CWE-294, CWE-770, CWE-942, CWE-200, CWE-215, CWE-311, CWE-276, CWE-209, CWE-755, CWE-20, CWE-316, CWE-1104 |
| SANS/CWE Top 25 | 2/25 matched | CWE-362 (#33, Race Condition), CWE-294 (Capture-replay) — note 362 is near the list |
| OWASP ASVS 5.0 | 4/14 chapters | V2 (Crypto), V7 (Logging), V8 (Data Protection), V13 (API) |
| PCI DSS 4.0.1 | 3 requirements relevant | 6.2.4 (secure coding), 3.5 (key management), 10.2 (audit logging) |
| MITRE ATT&CK | 3 techniques | T1190 (Exploit Public App), T1499 (Endpoint DoS), T1078 (valid-code abuse) |
| SOC 2 | 3 criteria | CC6.1, CC7.2, CC8.1 |
| ISO 27001:2022 | 3 controls | A.8.24 (crypto), A.8.5 (secure auth), A.8.34 (protection of information during dev) |

---

## 🟠 High Findings

### 🟠 [HIGH-001] TOCTOU race in activation binding — one code can activate unlimited machines

- **Severity**: 🟠 HIGH (CRITICAL business impact in multi‑worker production deployments)
- **OWASP**: A06:2025 (Insecure Design — race condition by design)
- **CWE**: CWE-362 (Race Condition), CWE-367 (Time‑of‑Check Time‑of‑Use)
- **NIST CSF**: PR.DS (Data Security), DE.AE (Adverse Event Analysis)
- **Compliance**: SANS Top 25 (CWE‑362) | ASVS V12.8 (concurrency) | PCI DSS 6.2.4 | T1499 | CC8.1 | A.8.34
- **Location**: `src/sealium/server/activation_service.py:57` (read) and `:75` (write); `src/sealium/server/database.py:196-213` (blind UPDATE)
- **Attack Vector**: `ActivationService.process()` reads the code status (`get_by_code`, line 57) and later writes it (`bind_machine_code`, line 75) in **two separate transactions**. Between them the `RLock` is released, so the read‑modify‑write is not atomic. `bind_machine_code` issues `UPDATE ... SET status = ?, bound_machine_code = ? WHERE code = ?` with **no `AND status = 0` guard and no affected‑row check** (database.py:201‑213). N concurrent requests for the same UNUSED code all read UNUSED, all pass the expired check, all UPDATE (last writer wins), and **all receive `success`**. Each machine walks away with a valid success response + `authorized_until` + `features`.
- **Proof of Concept** (executed against the real service/storage layer): 20 threads, one unused code, 20 distinct machine codes, barrier‑released simultaneously →
  ```
  Threads that got SUCCESS on ONE unused code: 20 / 20
  Final bound_machine_code: machine16  status: 1
  ```
  All 20 machines believe they are activated; only `machine16` is actually bound.
- **Impact**: Total defeat of the product’s core value proposition (one‑code‑one‑machine hardware binding). An attacker who purchases a single license can script concurrent activations to mint unlimited client activations. The captured `success` response is sufficient for the client to enable the software.
- **Exploitability caveat (accuracy note)**: In the *default* single‑worker `python -m sealium.server.run` deployment the async route handler calls the synchronous `process()` inline without yielding to the event loop, so requests are serialised and the race does not manifest. The race is **live in any multi‑worker deployment** (`uvicorn --workers N`, `gunicorn -w N`) — each worker is a separate process with its own connection to the shared DB file and an independent per‑process `RLock` — which is the standard production topology. The logical defect exists regardless.
- **Vulnerable Code**:
  ```python
  # activation_service.py — read …
  record = self._storage.get_by_code(code)        # line 57, Txn A
  ...
  if record.is_used(): ...                          # check
  ...
  self._storage.bind_machine_code(code, request.machine_code, now)  # line 75, Txn B
  ```
  ```python
  # database.py — blind update, no status precondition
  UPDATE activation_codes
  SET bound_machine_code = ?, activated_at = ?, status = ?
  WHERE code = ?                                    # no `AND status = 0`
  ```
- **Remediation**: Make the bind atomic and conditional. Issue a single `UPDATE activation_codes SET bound_machine_code = ?, activated_at = ?, status = 1 WHERE code = ? AND status = 0` and **check `cursor.rowcount == 1`**; treat `rowcount == 0` as “another request won the race” → return the appropriate response (idempotent success if same machine, else “已被其他设备使用”). Alternatively hold a per‑code lock or a `BEGIN IMMEDIATE` transaction across the whole check‑and‑bind. The conditional UPDATE is the simplest, race‑free fix.

---

### 🟠 [HIGH-002] Anti‑replay guard defeated by full‑flush eviction and per‑process state

- **Severity**: 🟠 HIGH
- **OWASP**: A06:2025 (Insecure Design), A07:2025 (weakened replay defence)
- **CWE**: CWE-294 (Authentication Bypass by Capture‑replay), CWE-770 (Allocation Without Limits/Throttles — here, the inverse: trivial flush)
- **NIST CSF**: PR.DS (Data Security)
- **Compliance**: ASVS V3.3 (replay protection) | PCI DSS 10.2 | T1190 | CC7.2 | A.8.5
- **Location**: `src/sealium/server/replay_guard.py:29-35` (`InMemoryReplayStore.seen`, eviction at `:33-34`); constructor `:44-47`
- **Attack Vector**: Three compounding weaknesses:
  1. **Full‑flush on overflow** (`replay_guard.py:33-34`): when the set exceeds `max_size` (default 10000) it calls `self._seen.clear()`, instantly making **every previously seen nonce replayable**. An attacker sends 10 001 junk `(code, nonce)` pairs to flush the store, then replays a captured legitimate request.
  2. **In‑memory and per‑process**: each worker/replica keeps its own `ReplayGuard`; a captured request replayed to a *different* worker is treated as fresh. Also lost entirely on restart.
  3. **Combined with HIGH‑001**: flushing + concurrency widens the binding race window.
- **Impact**: The advertised “Anti‑Replay (timestamp window + nonce deduplication)” control (README) is bypassable. Practical exploitation value is bounded because the hybrid‑crypto response is encrypted under a per‑request AES key the attacker does not hold for a captured packet (so a replayed response is unreadable to them), and the 300s timestamp window caps replay lifetime — but the *design intent* is not met, and the store also underpins idempotency correctness.
- **Vulnerable Code**:
  ```python
  def seen(self, key: ReplayKey) -> bool:
      if key in self._seen:
          return True
      self._seen.add(key)
      if len(self._seen) > self._max_size:
          self._seen.clear()      # full flush — all prior nonces become replayable
      return False
  ```
- **Remediation**: Replace full‑flush with an LRU/TTL bounded eviction (e.g. `collections.OrderedDict`, or a TTL keyed on the timestamp window) so old entries age out individually rather than the whole set vanishing. For multi‑worker correctness, back the store with shared durable state (Redis, or a DB table with a timestamp index pruned by the tolerance window). At minimum, document the single‑process limitation explicitly.

---

## 🟡 Medium Findings

### 🟡 [MEDIUM-001] CORS misconfiguration: `allow_origins=["*"]` with `allow_credentials=True`

- **Severity**: 🟡 MEDIUM
- **OWASP**: A02:2025 (Security Misconfiguration)
- **CWE**: CWE-942 (Permissive Cross‑domain Policy)
- **NIST CSF**: PR.PS (Platform Security)
- **Compliance**: ASVS V14.5 | CC6.1 | A.8.23
- **Location**: `src/sealium/server/app.py:112-118` (middleware) and `src/sealium/server/config.py:64` (default `"*"`)
- **Attack Vector**: The default config resolves `cors_origins=["*"]` and the app registers `CORSMiddleware(..., allow_origins=cfg.cors_origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])`. This is the canonical “`*` + credentials” misconfiguration. Starlette mitigates the worst case (it will not echo `Access‑Control‑Allow‑Credentials: true` together with `*`, logging a warning), so immediate credential theft is limited — but the intent is wrong and the default is wide open for an activation service that is meant to be called by a native client, not browsers.
- **Impact**: If any future endpoint ever uses cookies/credentials, the misconfiguration becomes exploitable. Today it signals an incorrect security posture and broadens the surface for any browser‑reachable deployment.
- **Vulnerable Code**:
  ```python
  app.add_middleware(
      CORSMiddleware,
      allow_origins=cfg.cors_origins,   # default ["*"]
      allow_credentials=True,
      allow_methods=["*"],
      allow_headers=["*"],
  )
  ```
- **Remediation**: Since this API is consumed by a non‑browser client over `application/octet-stream`, set `allow_credentials=False` and a restrictive explicit origin list (or remove CORS middleware entirely). Never combine `allow_origins=["*"]` with `allow_credentials=True`.

---

### 🟡 [MEDIUM-002] No rate limiting / abuse protection on the activation endpoint

- **Severity**: 🟡 MEDIUM
- **OWASP**: A06:2025 (missing rate limits on high‑value operations), A07:2025
- **CWE**: CWE-307 (Improper Restriction of Excessive Auth Attempts), CWE-770
- **NIST CSF**: PR.AA (Authenticator Management), DE.CM
- **Compliance**: ASVS V11.1 (rate limiting) | PCI DSS 10.2 | T1499 | CC7.2 | A.8.6
- **Location**: `src/sealium/server/app.py` (no throttling middleware registered) and `src/sealium/server/routes/activation.py`
- **Attack Vector**: The single high‑value endpoint (`POST /v1/activation`) has no throttle. Combined with HIGH‑001 and HIGH‑002, an attacker can fire unlimited concurrent/flood requests to widen the race window or flush the replay cache. Activation codes are 128‑bit so brute force is infeasible, but denial‑of‑service, DB pressure, and cache‑flush facilitation are all unmitigated.
- **Impact**: Enables the HIGH‑002 flush attack and the HIGH‑001 race amplification; allows DoS via unbounded requests; no friction for probing.
- **Remediation**: Add per‑IP/per‑fingerprint rate limiting (e.g. `slowapi`) and a global concurrency cap. Reject bursts well below the `replay_cache_size` so the cache cannot be intentionally flushed.

---

### 🟡 [MEDIUM-003] Machine‑code fallback injects wall‑clock time, breaking binding and idempotency

- **Severity**: 🟡 MEDIUM
- **OWASP**: A06:2025 (Insecure Design)
- **CWE**: CWE-1242 (Insecure Default / weak binding), CWE-330 (Insufficient Randomness in context)
- **NIST CSF**: PR.DS
- **Compliance**: ASVS V3.4 | A.8.34
- **Location**: `src/sealium/server/common/../machine_code.py:165-167` (`src/sealium/common/machine_code.py:166-167`)
- **Attack Vector**: When fewer than 3 hardware signatures are collected (common on minimal VMs or when WMI returns sparse data), `hash_hardware_info` appends `("fallback", str(time.time()))`. Because `time.time()` changes on every call, **the same machine yields a different machine code on every run**. The first activation binds code → machine_code_t1; a later legitimate reactivation produces machine_code_t2 ≠ t1 and the server rejects it as “其他设备”. The code comment itself admits “降低安全性”.
- **Impact**: Defeats hardware binding *and* the advertised idempotent‑reactivation feature (README “🔁 Idempotent”) on exactly the class of machines (VMs, locked‑down hosts) where licensing matters most. Also silently weakens the one‑machine‑per‑code guarantee.
- **Vulnerable Code**:
  ```python
  info_list = list(hardware_info)
  if len(info_list) < 3:
      info_list.append(("fallback", str(time.time())))   # non-deterministic
  ```
- **Remediation**: Do not inject entropy that changes per call. Either (a) refuse to generate a code when entropy is below threshold (fail safe, require more hardware sources), or (b) derive a stable fallback from static host data (hostname + a persistent per‑install random secret written once to disk). Document the chosen behaviour explicitly.

---

### 🟡 [MEDIUM-004] Unhandled exception in `service.process()` surfaces as HTTP 500

- **Severity**: 🟡 MEDIUM
- **OWASP**: A10:2025 (Mishandling of Exceptional Conditions), A05:2025 (input validation)
- **CWE**: CWE-755 (Improper Handling of Exceptional Conditions), CWE-20 (Improper Input Validation)
- **NIST CSF**: DE.AE
- **Compliance**: ASVS V5.3 / V14.4 | CC7.2 | A.8.32
- **Location**: `src/sealium/server/routes/activation.py:57` (no `try/except` around `service.process()`); `src/sealium/server/activation_service.py:49` (timestamp arithmetic)
- **Attack Vector**: `ActivationRequest.from_dict()` (`models.py:91-98`) performs **no type coercion/validation** — it copies `timestamp=data["timestamp"]` verbatim. In `process()`, `abs(int(now.timestamp()) - request.timestamp)` (`activation_service.py:49`) raises `TypeError` if `timestamp` is a non‑numeric JSON value (e.g. `"abc"`), and the route does not wrap the `service.process()` call (unlike the decrypt/parse steps above it, which are wrapped). The exception propagates as a 500; in debug mode FastAPI returns a full traceback. The same applies to non‑str fields used in comparisons/lookups.
- **Impact**: Protocol crash (un‑encrypted 500 breaks the client contract), possible stack‑trace leakage in debug, inconsistent error handling (decrypt errors → 400; service errors → 500).
- **Vulnerable Code**:
  ```python
  # routes/activation.py — decrypt/parse wrapped, but process() is not
  result = service.process(activation_req)      # line 57, no guard
  return _encrypted_response(result, aes_key)
  ```
  ```python
  # activation_service.py:49
  if abs(int(now.timestamp()) - request.timestamp) > self._tolerance: ...
  ```
- **Remediation**: Validate request field types in `ActivationRequest.from_dict` (or with a Pydantic model) and coerce `timestamp` to `int` defensively. Wrap `service.process()` in the route with a handler that returns an encrypted generic error on unexpected failure (and logs internally), so all error paths are consistent.

---

### 🟡 [MEDIUM-005] API documentation endpoints exposed in production

- **Severity**: 🟡 MEDIUM
- **OWASP**: A02:2025 (Security Misconfiguration)
- **CWE**: CWE-200 (Information Exposure), CWE-215 (Insertion of Sensitive Info Into Debug Code)
- **NIST CSF**: PR.PS
- **Compliance**: ASVS V14.3 | CC6.1 | A.8.23
- **Location**: `src/sealium/server/app.py:103-109` (`FastAPI(...)` created without `docs_url`/`redoc_url`/`openapi_url` overrides)
- **Attack Vector**: Verified at runtime: even with `debug=False`, `GET /docs` → 200, `GET /redoc` → 200, `GET /openapi.json` → 200. The OpenAPI schema discloses the full endpoint shape, field names, and content type, giving an attacker a precise map of the surface.
- **Impact**: Information disclosure that lowers the effort for the enumeration/oracle attacks (see GRAY‑001) and any future probing.
- **Remediation**: In production disable automatic docs: `FastAPI(..., docs_url=None, redoc_url=None, openapi_url=None)` (gate behind `cfg.debug` if docs are wanted in dev).

---

## 🟢 Low & 🔵 Informational Findings

### 🟢 [LOW-001] Server private key stored unencrypted at rest (no passphrase)
- **Severity**: 🟢 LOW | **OWASP**: A02:2025, A04:2025 | **CWE**: CWE-311 (Missing Encryption of Sensitive Data), CWE-798 if passphrase were hardcoded (n/a here) | **NIST**: PR.DS | **Compliance**: ASVS V6.1 | PCI DSS 3.5 | A.8.24
- **Location**: `src/sealium/scripts/generate_keys.py:48-49`; `src/sealium/common/crypto.py:117-118` (default `NoEncryption()`)
- **Pattern**: The RSA‑4096 private key is written via `export_private_key()` with `encryption_algorithm=None` → `NoEncryption()`, stored as plaintext `data/server_private.pem`.
- **Security implication**: Any file‑system read compromise (backup leak, mis‑configured container volume, shared host) yields the master key, letting an attacker decrypt all traffic and forge valid success responses for any code.
- **Remediation**: Store the key passphrase out‑of‑band (env/vault) and load with a passphrase; enforce `0600` on the key file (see LOW‑002); consider an HSM/KMS for the master key.

### 🟢 [LOW-002] Key and database files written with default umask (no restrictive permissions)
- **Severity**: 🟢 LOW | **OWASP**: A02:2025 | **CWE**: CWE-276 (Incorrect Default Permissions) | **NIST**: PR.PS | **Compliance**: CC6.1 | A.8.31
- **Location**: `generate_keys.py:49-50`, `database.py:39`, `scripts/generate_activation_codes.py:65`
- **Pattern**: `Path.write_bytes(...)` / `sqlite3.connect(...)` create files with the process umask (often `0644`/`0666`‑ish). No `os.chmod(path, 0o600)` follows.
- **Security implication**: On multi‑user hosts, other local users can read the private key, the SQLite DB (all activation codes + bindings), and generated‑code output files.
- **Remediation**: `os.chmod(private_key_path, 0o600)` and `0o600` on the DB file immediately after creation; create with `open(..., 0o600)` via `os.open`.

### 🟢 [LOW-003] Raw exception string leaked (encrypted) to client on DB write failure
- **Severity**: 🟢 LOW | **OWASP**: A10:2025 | **CWE**: CWE-209 (Generation of Error Message Containing Sensitive Information) | **NIST**: DE.AE | **Compliance**: ASVS V7.4 | A.8.32
- **Location**: `src/sealium/server/activation_service.py:76-77`
- **Pattern**: `return ActivationResponse.error(f"数据库更新失败: {e}")` interpolates the raw exception (may include SQL text / internal paths) into the (encrypted) response.
- **Security implication**: Limited — only the requesting client can decrypt — but it discloses internals. Inconsistent with the otherwise generic error messages.
- **Remediation**: Return a generic `"激活失败，请稍后重试"` to the client; log the full `e` server‑side.

### 🟢 [LOW-004] Per‑session AES key retained on the `ClientKeyManager` and never auto‑cleared
- **Severity**: 🟢 LOW | **OWASP**: A04:2025 | **CWE**: CWE-316 (Cleartext Storage of Sensitive Information in Memory) | **NIST**: PR.DS | **Compliance**: ASVS V6.4 | A.8.24
- **Location**: `src/sealium/client/key_manager.py:33` (`self._current_aes_key`), `:67-69` (`clear_aes_key`, never called)
- **Pattern**: The ephemeral AES key persists on the instance after `decrypt_response`; `Activator.activate()` never calls `clear_aes_key()`.
- **Security implication**: A memory dump of a long‑lived client process could expose a session key. Minor, since the key is request‑scoped and the manager is usually short‑lived.
- **Remediation**: Call `clear_aes_key()` in a `finally` after the response is decrypted, or zero the bytes.

### 🔵 [INFO-001] No dependency version pinning or lock file; no SCA tooling
- **Severity**: 🔵 INFO | **OWASP**: A03:2025 | **CWE**: CWE-1104 (Use of Unmaintained Third Party Components — here, unbounded versions) | **NIST**: GV.SC | **Compliance**: CC8.1 | A.8.29
- **Location**: `pyproject.toml:13-19` (no upper bounds); no `requirements.txt`/lock committed; `pip‑audit` not installed (not run).
- **Note**: Resolved versions are current (cryptography 46.0.6, fastapi 0.135.3, uvicorn 0.44.0, requests 2.33.1), but unpinned ranges can pull vulnerable/breaking versions later.
- **Remediation**: Commit a lock file (or pin compatible ranges) and add `pip‑audit`/`safety` to CI.

### 🔵 [INFO-002] No TLS at the transport layer (plain HTTP)
- **Severity**: 🔵 INFO | **OWASP**: A02:2025 | **CWE**: CWE-319 (Cleartext Transmission of Sensitive Information) | **NIST**: PR.PS, PR.DS | **Compliance**: ASVS V9.1 | A.8.24
- **Location**: `src/sealium/server/run.py:17-23`
- **Note**: `uvicorn.run(...)` starts plain HTTP. This is **defensible** because payloads are end‑to‑end encrypted by the application‑layer hybrid crypto (request/response are ciphertext), so confidentiality and integrity hold without TLS. No HSTS / cert pinning, however.
- **Remediation**: Recommended to still terminate TLS at a reverse proxy for defence‑in‑depth and to hide metadata (timing, size, error codes).

### 🔵 [INFO-003] Server binds `0.0.0.0` by default
- **Severity**: 🔵 INFO | **OWASP**: A02:2025 | **CWE**: CWE-1327 | **NIST**: PR.PS
- **Location**: `src/sealium/server/config.py:61` (`host` default `"0.0.0.0"`)
- **Note**: Listens on all interfaces. Expected behind a reverse proxy; in a bare deployment it exposes the service network‑wide.
- **Remediation**: Default to `127.0.0.1` and require explicit opt‑in for public binding, or document the proxy assumption.

---

## 🔲 Gray-Box Findings

### [GRAY-001] Activation‑state enumeration oracle (responses are decryptable by any requester)
- **Severity**: 🟢 LOW (mitigated by 128‑bit code entropy)
- **OWASP**: A01:2025, A06:2025, A10:2025 | **CWE**: CWE-204 (Observable Response Discrepancy), CWE-200 | **NIST**: PR.DS, DE.CM
- **Compliance**: ASVS V13.1 | CC7.2 | A.8.5
- **Tested As**: Anonymous attacker holding only the (publicly distributed) server public key.
- **Endpoint**: `POST /v1/activation`
- **Expected**: Error responses should not reveal whether a code exists, is used, or is bound elsewhere.
- **Actual**: Because the **client generates the AES session key**, anyone who can obtain the public key can build a valid request *and decrypt the response*. Verified distinct, decryptable states:
  - `{"result":"error","error_msg":"激活码不存在"}` — code does not exist
  - `{"result":"error","error_msg":"激活码已被其他设备使用"}` — code exists and is USED by another machine
  - `{"result":"success", ...}` — code exists, was UNUSED, now bound to the requester
  These messages let an attacker enumerate/probe code states.
- **Request**: Any `ClientKeyManager(pub).build_encrypted_request(...)` with a chosen `activation_code`.
- **Remediation**: Standardise on a single generic error message (e.g. `"激活码无效或已被使用"`) for all non‑success paths so states are indistinguishable; rely on rate limiting (MEDIUM‑002) to bound probing. Practically safe today because 2¹²⁸ codes cannot be enumerated.

### Gray‑box — clean areas (no finding)
- **Verb tampering**: `GET/PUT/DELETE/PATCH/HEAD` on `/v1/activation` all return **405** (FastAPI enforces POST). ✅
- **Decrypt‑error oracle**: malformed/too‑short/RSA‑failure packets all return the same `400` empty body (no distinction between RSA‑fail and AES‑fail). ✅
- **No hidden/undocumented endpoints**: only `/v1/activation`, `/health`, and (debug‑only) `/debug/config`. ✅

---

## 📍 Security Hotspots

### [HOTSPOT-001] Hybrid‑encryption packet parsing hardcodes RSA‑4096 size
- **OWASP**: A06:2025 | **CWE**: CWE-1047, CWE-704 | **NIST**: ID.AM, PR.DS
- **Location**: `src/sealium/server/crypto_transport.py:20` (`rsa_key_size: int = RSA_KEY_SIZE`) and caller `routes/activation.py:41` (does not pass the loaded key’s size)
- **Why sensitive**: The parser slices the packet assuming a 512‑byte RSA block. It does **not** derive the size from the actual loaded private key. I hit this during auditing (a 2048‑bit key silently parsed as “too short” → 400). The default (4096) is consistent today, but any future key‑size change or non‑default `generate_keys --key-size` breaks activation opaquely.
- **Risk if modified**: Changing the slice math without syncing to the real key size corrupts the entire request pipeline; conversely, silently trusting the constant hides key‑rotation mistakes.
- **Review guidance**: PRs touching key generation or crypto_transport must keep `parse_encrypted_request`’s `rsa_key_size` in sync with the loaded key (derive from `encryptor.key_size`).

### [HOTSPOT-002] Crypto primitives (RSA‑OAEP / AES‑GCM)
- **OWASP**: A04:2025 | **CWE**: CWE-327 | **NIST**: PR.DS
- **Location**: `src/sealium/common/crypto.py:67-194`, `client/key_manager.py:35-65`, `server/crypto_transport.py`
- **Why sensitive**: All confidentiality/integrity rests here. Currently correct: OAEP(SHA‑256), AES‑256‑GCM, `secrets.token_bytes` nonces, tag verification (GCM rejects tampered ciphertext). AES‑GCM also authenticates the RSA‑decrypted key implicitly (wrong key → tag fail).
- **Risk if modified**: Switching padding to PKCS#1 v1.5, reusing nonces, or dropping associated‑data would be catastrophic. Any change must preserve AEAD.
- **Review guidance**: Treat as protected; require crypto review for any edit.

### [HOTSPOT-003] Binding state machine (the race surface)
- **OWASP**: A06:2025 | **CWE**: CWE-362 | **NIST**: PR.DS, DE.AE
- **Location**: `src/sealium/server/activation_service.py:38-86` and `database.py:188-213`
- **Why sensitive**: The UNUSED→USED transition and same‑machine idempotency are the trust boundary of the licence model.
- **Risk if modified**: See HIGH‑001 — already non‑atomic. Any refactor must make the transition atomic.
- **Review guidance**: Gate changes on the concurrency test from HIGH‑001’s PoC.

### [HOTSPOT-004] Replay guard as an availability/security control
- **OWASP**: A06:2025, A07:2025 | **CWE**: CWE-294 | **NIST**: PR.DS
- **Location**: `src/sealium/server/replay_guard.py`
- **Why sensitive**: Underpins idempotency correctness and anti‑replay. Already weak (HIGH‑002).
- **Risk if modified**: A naive store change could either drop dedup (replay) or deadlock the request path.
- **Review guidance**: Keep eviction bounded‑and‑individual (LRU/TTL), never full‑flush.

### [HOTSPOT-005] Machine‑code fingerprint composition
- **OWASP**: A06:2025 | **CWE**: CWE-1242 | **NIST**: PR.DS
- **Location**: `src/sealium/common/machine_code.py:157-190`
- **Why sensitive**: Determines binding identity. The time‑based fallback (MEDIUM‑003) already degrades it; the sort‑by‑tag defence against reordering is good.
- **Risk if modified**: Changing the join order or salt logic invalidates existing bindings (forces mass re‑activation or, worse, collision).
- **Review guidance**: Version the fingerprint scheme if changed.

### [HOTSPOT-006] FastAPI lifespan / resource initialisation
- **OWASP**: A02:2025 | **CWE**: CWE-703 | **NIST**: PR.PS
- **Location**: `src/sealium/server/app.py:64-101`
- **Why sensitive**: Creates the singleton encryptor, DB connection (`check_same_thread=False`), and service. The RLock model depends on this single shared connection.
- **Risk if modified**: Switching to per‑request connections, async drivers, or multiple workers without re‑evaluating the race (HIGH‑001) breaks safety.
- **Review guidance**: Any change to connection/worker topology must be paired with the binding‑atomicity fix.

### [HOTSPOT-007] Debug‑mode configuration surface
- **OWASP**: A02:2025 | **CWE**: CWE-489, CWE-215 | **NIST**: PR.PS
- **Location**: `src/sealium/server/app.py:126-144` (`/debug/config`), `config.py:63` (`DEBUG`), `run.py:21` (`reload=debug`)
- **Why sensitive**: `debug=True` exposes `/debug/config` (DB + key *paths*), enables uvicorn reload, and surfaces tracebacks (MEDIUM‑004). Correctly disabled by default, but the flag is the single switch between safe and leaky.
- **Risk if modified**: Accidentally defaulting `debug=True`, or leaving reload on in prod, is a common outage/leak.
- **Review guidance**: Never ship with `DEBUG=true`; assert it in a deployment smoke test.

---

## 🧹 Code Smells

### [SMELL-001] RSA size is a magic constant threaded through three modules
- **OWASP**: A06:2025 | **CWE**: CWE-1047 | **NIST**: GV.RM
- **Location**: `constants.py:13`, `crypto_transport.py:20`, `routes/activation.py:41`, `crypto.py`
- **Pattern**: `RSA_KEY_SIZE` is a constant that must equal the actual generated/loaded key; nothing enforces the invariant (see HOTSPOT‑001).
- **Security implication**: Silent breakage on key‑size mismatch.
- **Suggestion**: Derive packet parsing from `encryptor.key_size` and add a test asserting `parse_encrypted_request` works for the configured key.

### [SMELL-002] No input‑validation layer on request models
- **OWASP**: A05:2025, A06:2025 | **CWE**: CWE-20 | **NIST**: GV.RM
- **Location**: `common/models.py:91-98` (`ActivationRequest.from_dict`), `database.py` deserialisers
- **Pattern**: `from_dict` blindly trusts JSON types; validation is scattered (a string check only at `activation_service.py:43`).
- **Security implication**: Feeds MEDIUM‑004 (TypeError → 500).
- **Suggestion**: Adopt Pydantic `BaseModel` for request/response DTOs so types, ranges, and lengths are validated at the boundary.

### [SMELL-003] Broad `except Exception` blocks that swallow detail
- **OWASP**: A10:2025 | **CWE**: CWE-390, CWE-755 | **NIST**: DE.AE
- **Location**: `common/crypto.py:96`, `routes/activation.py:47`, `machine_code.py` (multiple `except Exception: pass`)
- **Pattern**: Several catch‑alls, some `pass`‑only (machine_code collectors), convert failures to generic errors with no logging.
- **Security implication**: Silent failures hide hardware‑collection failures (relevant to MEDIUM‑003) and crypto errors.
- **Suggestion**: Catch specific exceptions; log at DEBUG with context; never bare‑`pass` security‑relevant collection.

### [SMELL-004] Single shared SQLite connection relied upon for concurrency
- **OWASP**: A06:2025 | **CWE**: CWE-362 | **NIST**: PR.DS
- **Location**: `server/database.py:31-96`
- **Pattern**: One `check_same_thread=False` connection + one `RLock`. Sufficient for a single process but the design obscures that it provides no cross‑process atomicity (HIGH‑001).
- **Security implication**: Misleads maintainers into assuming the lock makes binding safe under scale‑out.
- **Suggestion**: Document the single‑process limitation; make the atomic bind fix regardless.

### [SMELL-005] No security logging or alerting anywhere
- **OWASP**: A09:2025 | **CWE**: CWE-778 | **NIST**: DE.CM, DE.AE
- **Location**: project‑wide (only startup/shutdown INFO logs in `app.py`)
- **Pattern**: No audit logging of activation successes/failures, replay hits, “other device” rejections, or error spikes; no alerting.
- **Security implication**: The HIGH‑001 race and HIGH‑002 replay‑flush attacks would be invisible to operators; no detection of licence‑sharing abuse.
- **Suggestion**: Emit structured audit logs (code hash, machine_code hash, result, IP) for every activation decision; alert on burst/replay‑flush patterns.

---

## Recommendations Summary

**Priority 1 — fix before any production scale‑out:**
1. **HIGH‑001 (race)**: atomic conditional `UPDATE ... WHERE status=0` + `rowcount` check. *This single change restores the one‑code‑one‑machine guarantee.*
2. **HIGH‑002 (replay)**: LRU/TTL eviction + shared/durable store for multi‑worker; never full‑flush.
3. **MEDIUM‑002 (rate limit)**: throttle `/v1/activation` (per‑IP + global concurrency) below `replay_cache_size`.

**Priority 2 — hardening:**
4. **MEDIUM‑001 (CORS)**: drop credentials + restrict origins (or remove CORS).
5. **MEDIUM‑005 (docs)**: disable `/docs /redoc /openapi.json` in production.
6. **MEDIUM‑004 (input)**: Pydantic DTOs + wrap `process()` for consistent errors.
7. **MEDIUM‑003 (machine code)**: remove the `time.time()` fallback; fail safe or use a stable per‑install secret.
8. **LOW‑001/002**: encrypt/`chmod 0600` the private key + DB.

**Priority 3 — governance:**
9. **A09**: add audit logging + alerting (SMELL‑005) — required to detect abuse of the above.
10. **A03**: pin/lock dependencies and run `pip‑audit` in CI (INFO‑001).

Clean areas worth preserving: SQL is 100% parameterised (no injection), the hybrid crypto is textbook‑correct, codes are CSPRNG‑128‑bit, verb tampering is blocked, and import has no side effects.

---

## Methodology

| Aspect | Details |
|--------|---------|
| Phases executed | 1–5 (recon, white‑box, gray‑box, hotspots, smells) |
| Frameworks detected | FastAPI 0.135.3 (async), Uvicorn 0.44.0, SQLite (stdlib `sqlite3`), `cryptography` 46.0.6, `requests` 2.33.1, `wmi` (Windows‑only, lazy) |
| White‑box categories | All 20 OWASP categories evaluated; relevant ones documented (A01, A02, A03, A04, A05, A06, A07, A09, A10; A08 clean) |
| Gray‑box testing | Anonymous requester (public key only); verb tampering, decrypt‑error differential, enumeration oracle probed |
| Security hotspots | 7 (crypto packet parse, crypto primitives, binding state machine, replay guard, machine‑code composition, lifespan, debug surface) |
| Code smells | 5 (RSA magic constant, no validation layer, broad excepts, shared‑connection assumption, no security logging) |
| Packs loaded | none |
| Scope exclusions | no `.security-audit-ignore` present; `.venv/` and `data/` (runtime secrets, gitignored) excluded by judgement |
| Baseline comparison | no (`.security-audit-baseline.json` absent) |
| Verification | HIGH‑001 reproduced (20/20 concurrent activations); docs‑exposure & enumeration‑oracle & verb‑tampering executed against a live in‑process TestClient; git history + tracked source scanned for secrets (clean) |
| OWASP Top 10:2025 | 10/10 categories covered |
| NIST CSF 2.0 | GV, ID, PR, DE, RS, RC considered |
| CWE | 14 unique CWE IDs identified |
| SANS/CWE Top 25 | 2 entries matched |
| ASVS 5.0 | V2, V3, V5, V6, V7, V9, V11, V12, V13, V14 referenced |
| Additional frameworks | PCI DSS 4.0.1, MITRE ATT&CK, SOC 2, ISO 27001:2022 mapped per finding |
| Reference files used | `attack-vectors.md`, `frameworks/fastapi.md`, global custom‑template checklist |

---

*Report generated by Claude Security Audit*
