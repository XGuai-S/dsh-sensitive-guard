# Sensitive content guard

A pre-gateway guard for DeepSeek Harness: it recognizes, masks, and optionally blocks
sensitive content before a request leaves the machine. It runs ahead of routing, retry,
and dispatch, with no interaction and no prompting.

## Two modes

| Mode | Behaviour |
|---|---|
| `mask` (default) | Mask and pass: a hit becomes a placeholder, the task continues, only the log carries a risk level |
| `block` | Strict: a high-risk hit raises `CONTENT_REFUSED`, no request is sent and no body is produced |

```yaml
config:
  mode: block
  blockOnRisk: high    # high | normal
```

## Both directions

| Direction | Hook | Effect |
|---|---|---|
| Request | `agent/pre-step` | masks user input before it enters a step; analyzes attached images |
| Request | `tools/post-execute` | masks tool output before it is recorded |
| Request | `llm/stream` | audits the outgoing request and reports residual hits |
| Response | `llm/stream` | masks model output blocks as they close |

Why response masking works: DSH's `BlockAssembler` replaces accumulated `text-delta`
content with the block carried by `block-end`. Emitting a rewritten `block-end`
therefore changes what downstream sees, without touching deltas already delivered.

## Masking map

| Value | Placeholder |
|---|---|
| keys, private keys, Bearer, JWT, high-entropy strings | `{{SECRET_TOKEN}}` |
| national id, phone, bank card, passport, address, medical record, name+id | `{{PRIVACY_ID}}` |
| account and database passwords, wifi password, cookies, session ids, signed links | `{{CRED_CODE}}` |
| one-time codes (keyword plus 4–6 digits) | `{{ONE_TIME_CODE}}` |
| local absolute paths | `{{LOCAL_PATH}}` |
| IMEI, Android ID, serial numbers | `{{DEVICE_ID}}` |
| email addresses | `{{EMAIL_ADDR}}` |
| internal and public IPs | `{{NET_IP}}` |
| private domains and internal hosts | `{{PRIVATE_URL}}` |
| database connection credentials | `{{DB_CRED}}` |

## Detection rules

### Key-value credentials

Keywords such as `password`, `pwd`, `secret`, `token`, `key`, `apikey`, `access_key`,
`bearer`, `账号`, `密码` followed by `=`, `:`, or a quote mark the next value as a
credential. **Only the value is replaced**, so JSON, YAML, properties, and gradle
structure survives.

```json
{"password":"mySecret123"}  →  {"password":"{{CRED_CODE}}"}
```

### Fixed-prefix keys

Strings beginning with `sk-`, `sk-proj-`, `sk-ant-`, `ghp_`, `github_pat_`, `glpat-`,
`AKIA`, `AIza`, `hf_`, or `eyJ` are treated as API keys.

### High-entropy fallback

An unmarked, unprefixed random-looking run of at least 24 characters is treated as a
suspicious credential when all of these hold:

- at least three character classes (lower, upper, digit, symbol)
- at least 12 distinct characters
- Shannon entropy of at least 3.0 bits per character

A hit is labelled `【⚠️高熵可疑密钥】` and masked.

### Exclusions

These are **not** credentials: ports (1–65535), version numbers (`1.2.3`,
`v2.0.0-beta.1`), and MD5 / SHA-1 / SHA-256 / SHA-512 hex digests.

## Whitelist

Built in: `test-key`, `demo-sk`, `example-token`, `placeholder`, `mock-secret`, `md5`,
`sha256`. A whitelisted value is never recognized, labelled, or masked. The test applies
to the replaced value, not the whole match, so `apikey=test-key` survives intact.

A session-scoped list marks false positives:

```yaml
config:
  sessionWhitelist:
    - myFalsePositive
```

## Images

1. EXIF (GPS, capture time, device model, serial) is removed before upload by
   `dsh-attachment-local` at admission.
2. Local OCR reads text inside the picture; the result goes through the same rules.
3. QR payloads are decoded and masked.
4. A failed, garbled, or low-confidence read is labelled `【⚠️OCR识别不可靠】` and the
   image passes.
5. Images are downscaled; the original resolution is not uploaded.

### Irreversible redaction

A line that hits a rule is covered by an opaque fill, then the whole image is re-encoded.
Three things together make it irreversible:

1. **Opaque fill** — no layer, alpha, or blend keeps the pixels reachable.
2. **Full re-encode** — no source scanline of the covered region survives.
3. **No metadata on save** — EXIF, GPS, and camera fields do not return.

Verified: after covering, the same engine recognizes zero lines in the output.

**Limit:** the original file remains under `$DSH_HOME/attachments`, which is
content-addressed and immutable. Redaction changes what the model receives, not what the
host keeps.

### Two backends

| Backend | Platform | Recognition | Pixels, redaction, scaling |
|---|---|---|---|
| `winrt` | Windows | built-in `Windows.Media.Ocr` | WinRT imaging |
| `python` | any | `tesseract` if installed | Pillow |

Probe order is `winrt` then `python`. When neither recognizes text, all text is still
masked and images are still redacted by region; only reading the words is lost.

```yaml
config:
  imageBackend: python        # auto | winrt | python | none
  pythonPath: /usr/bin/python3
  tesseractPath: /usr/bin/tesseract
```

### Recognizer caveats

The Windows Chinese recognizer reports `0.000` confidence for every word, so reliability
is judged by text shape: a line that is mostly symbols, or shorter than two meaningful
characters, is labelled unreliable and skipped. It also inserts spaces between CJK
characters and can split an ASCII token. CJK spacing is collapsed; ASCII spacing is kept,
because joining it would turn `hello world` into `helloworld`. A split token is matched
across the space by a dedicated rule.

## Bypass and subagents

- **Bypass detection**: a request with no session id was not built by the agent loop. It
  is labelled `【⚠️旁路风险】` and still audited.
- **Subagent inheritance**: the plugin mounts globally, so a subagent's requests pass
  through the same hooks with no extra configuration.
- **Independent counting**: alerts accumulate per session; a subagent does not share the
  parent's hit statistics.

## Limits and fallbacks

| Item | Behaviour |
|---|---|
| Images per turn | at most 3 are OCRed; the rest are labelled `【⚠️放行-OCR超限】` |
| Regex / OCR / QR failure | risk is labelled, the turn continues |
| Six consecutive high-risk hits | `【⚠️告警】` is emitted |
| Binary and archive content | labelled `【⚠️放行-二进制内容】`, never parsed, passed through |

Any internal error returns the caller's decision unchanged; the guard never breaks a turn.

## Logs

| Log | Meaning |
|---|---|
| `【⚠️已脱敏-高风险】` | a high-risk rule hit |
| `【⚠️已脱敏-普通】` | a normal rule hit |
| `【✅无敏感】` | nothing matched |
| `【⚠️已脱敏-高风险】[对话明文] 命中=密码` | hook and hit kind |

The log carries placeholders and counts only, **never the original value**.

## Placeholder stability

The same value always maps to the same placeholder within a session, so the model's
context stays coherent. The registry stores a SHA-256 digest, never the value. A written
placeholder is never re-matched, so a value is replaced exactly once.

## Configuration

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Master switch |
| `mode` | `mask` | `mask` or `block` |
| `blockOnRisk` | `high` | Trigger level for strict mode |
| `maskUserMessages` | `true` | Mask user input |
| `maskToolResults` | `true` | Mask tool output |
| `maskResponses` | `true` | Mask model output |
| `auditRequests` | `true` | Audit the outgoing request |
| `detectHighEntropy` | `true` | Entropy fallback |
| `detectAddresses` | `true` | Address detection |
| `detectMedical` | `true` | Medical record detection |
| `detectQr` | `true` | QR decoding |
| `detectBypass` | `true` | Bypass detection |
| `markBinary` | `true` | Binary labelling |
| `maskDbCredentials` | `true` | Database connection strings |
| `maskUrls` | `false` | `false` / `internal` / `all` |
| `privateUrlSuffixes` | built in | Internal host suffixes |
| `whitelist` | built in | Never masked |
| `sessionWhitelist` | `[]` | Session-scoped false positives |
| `logMasks` | `true` | Emit masking logs |
| `highRiskAlertAfter` | `6` | Consecutive high-risk alert threshold |
| `disabledRules` | `[]` | Rule ids to skip |
| `maxImagesPerTurn` | `3` | Image count warning |
| `ocr` | `true` | Image analysis master switch |
| `imageBackend` | `auto` | `auto` / `winrt` / `python` / `none` |
| `pythonPath` | PATH lookup | Python interpreter |
| `tesseractPath` | PATH lookup | Tesseract binary |
| `ocrLanguage` | `zh-Hans-CN` | WinRT language tag |
| `tesseractLanguage` | `chi_sim+eng` | Tesseract language pack |
| `ocrTimeoutMs` | `20000` | Per-image deadline |
| `ocrMaxImagesPerTurn` | `3` | OCR cap per turn |
| `redactImages` | `true` | Irreversible redaction |
| `redactColor` | `#000000` | Fill color |
| `compressImages` | `true` | Downscale |
| `compressMaxDimension` | `2048` | Long-edge cap |

## URL masking levels

| Value | Effect |
|---|---|
| `false` (default) | nothing |
| `internal` | only `.internal` `.local` `.lan` `.corp` `.intra` `.private` `.svc` `.home` |
| `all` | every domain, public included |

`internal` is the practical choice: internal hosts are masked while `github.com` stays
readable.

## Moving to another machine

1. Copy the directory.
2. `npm install` for `jsqr` (skip it and QR detection is lost, everything else works).
3. `node ocr/selfcheck.mjs` reports what this machine can do.
4. For image text off Windows, install Pillow (`pip install pillow`) and tesseract with
   the language pack you need.

The self-check prints `OK` / `WARN` / `MISS` per capability and exits non-zero only on a
real failure, so it works in a script. `--json` gives structured output.

## Guarantees

- Only sensitive values are replaced; code structure, comments, and identifiers survive.
- Replacement is in-memory and transient; plaintext is never restored or persisted, and
  the log carries only a digest.
- After masking, the request proceeds through routing, retry, and dispatch as usual.

## What this cannot do

- **Gateway payload logging**: a gateway-side setting, outside this plugin's control.
- **Erasing the original image on disk**: the attachment store is content-addressed and
  immutable.
- **Rewriting an already-rendered delta**: response masking applies when a block closes;
  the durable log and later requests see masked text, but a delta already shown in the UI
  is not revisited.
- **Covering every spelling**: rules match the listed formats, not all possible ones.

## License

MIT
