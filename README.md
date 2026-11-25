# dsh-sensitive-guard

A Host plugin for DeepSeek Harness that masks sensitive values before a model
request reaches a provider adapter, reads text and QR payloads out of images,
and never blocks a turn.

Designed to move between machines: nothing is hard-wired to one host, and a
self-check reports exactly what the current machine can do.

## Quick start

```bash
# In the bundle directory, on the machine that will run it:
npm install                  # jsqr
node ocr/selfcheck.mjs       # what works here
```

Install the directory as a bundle through **Plugins → Add plugin**, or with
`plugin_manager install_bundle`.

## What it does

**One outcome: mask.** Every match is replaced with a placeholder and the
request continues through routing, retry, and dispatch. There is no refusal
branch; only the log carries a risk level.

| Value | Placeholder | Risk |
|---|---|---|
| APIKEY, private keys, `sk-`, `ghp_`, `glpat-`, Bearer, JWT, `storePassword`, pkcs12 | `{{SECRET_TOKEN}}` | high |
| national id, phone, bank card, passport | `{{PRIVACY_ID}}` | high |
| name adjacent to a national id | `{{PRIVACY_ID}}` | high |
| address (administrative chain or street number) | `{{PRIVACY_ID}}` | high |
| medical record number, diagnosis line | `{{PRIVACY_ID}}` | high |
| adb/root/wifi/db passwords, 2FA codes, cookies, session ids, signed login links | `{{CRED_CODE}}` | high |
| database connection strings | `{{DB_CRED}}` | high |
| local absolute paths | `{{LOCAL_PATH}}` | normal |
| IMEI, Android ID, serial numbers | `{{DEVICE_ID}}` | normal |
| email addresses | `{{EMAIL_ADDR}}` | normal |
| internal and public IPs | `{{NET_IP}}` | normal |
| private domains and repo addresses (opt-in) | `{{PRIVATE_URL}}` | normal |

A placeholder written by one rule is never re-matched by a later rule, so a
value is replaced exactly once and never gains a `_2` variant.

## Where it hooks

| Event | Effect |
|---|---|
| `agent/pre-step` | masks user message text as it enters a step; analyzes attached images |
| `tools/post-execute` | masks tool output before it is recorded and replayed |
| `llm/stream` | audit only; a loop-built request is deep-frozen, so it is read and reported, never rewritten |

Every listener fails open: an internal error returns the caller's decision
unchanged, so the guard can never break a turn.

## Image backends

Two backends implement the same five operations. The plugin picks one at
startup and logs which is live.

| Backend | Platform | Recognition | Pixels, redaction, scaling |
|---|---|---|---|
| `winrt` | Windows | `Windows.Media.Ocr`, built into the OS | WinRT imaging |
| `python` | any | `tesseract` CLI, if installed | Pillow |

Selection order is `winrt` then `python`. If neither can recognize text, the
guard still masks all text and still redacts images by region — only the
"read the words inside the picture" step is lost.

Configure explicitly when auto-selection guesses wrong:

```yaml
config:
  imageBackend: python        # auto | winrt | python | none
  pythonPath: /usr/bin/python3
  tesseractPath: /usr/bin/tesseract
  ocrLanguage: zh-Hans-CN     # winrt
  tesseractLanguage: chi_sim+eng
```

`imageBackend: none` disables image analysis entirely; text masking is
unaffected.

### Recognizer caveats

The Windows Chinese recognizer reports `0.000` confidence for every word, so
reliability is judged by text shape instead: a line that is mostly symbols, or
shorter than two meaningful characters, is reported as `【⚠️OCR识别不可靠】` and
skipped. It also inserts a space between CJK characters and can split an ASCII
token; CJK spacing is collapsed before matching, and the split-token case is
matched across the space rather than by joining every ASCII gap — joining would
turn `hello world` into `helloworld`.

## Irreversible image redaction

A recognized line that hits a rule is covered, and the image block is repointed
at the redacted copy. Three things make it irreversible:

1. An **opaque fill** over the rectangle. No layer, alpha, or blend keeps the
   original pixels reachable behind it.
2. A **full re-encode** from the modified raster, so no source scanline of the
   covered region survives in the output file.
3. **No metadata** on save, so EXIF/GPS/camera fields do not return.

Verified on a fixture: after covering, the same engine recognizes zero lines in
the output.

**What this cannot do:** the stored attachment is content-addressed and
immutable, so the original file remains on disk under `$DSH_HOME/attachments`.
Redaction changes what the model receives, not what the host keeps. Someone with
local filesystem access can still open the original.

## QR codes

A QR payload is decoded in process with `jsqr` and masked as text. A hit is
reported as `【⚠️二维码命中】`. The code itself is not edited: covering it would
destroy it, and a QR is a single block rather than a line. A decode failure is
reported as `【⚠️二维码解析异常】` and the image passes.

`jsqr` is an optional dependency. Without it, QR detection is skipped and every
other capability still works.

## Binary and archive content

A zip, rar, 7z, gzip, pdf, or any file with a NUL byte in its leading window is
treated as opaque. Masking a chance byte sequence inside it would corrupt the
file without hiding anything, so the risk is reported as
`【⚠️放行-二进制内容】` and the bytes are left untouched.

## Bypass detection

A model request with no session id was not built by the agent loop for an
observed session: a direct call that skipped the normal path. It is still
audited, and the bypass is recorded as `【⚠️旁路风险】`.

## Subagent inheritance

The plugin mounts globally, so a subagent's requests pass through the same
`agent/pre-step`, `tools/post-execute`, and `llm/stream` listeners with no
per-agent configuration. There is no separate subagent switch because there is
no separate path to cover.

## URL masking levels

Masking every public domain makes the model unable to read context, so
`maskUrls` has three levels:

| Value | Effect |
|---|---|
| `false` (default) | nothing |
| `'internal'` | hosts under `internal`, `local`, `lan`, `corp`, `intra`, `private`, `svc`, `home` only |
| `'all'` | every domain, public ones included |

`privateUrlSuffixes` replaces the built-in internal list.

## Configuration

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Master switch |
| `maskUserMessages` | `true` | Mask user text at `agent/pre-step` |
| `maskToolResults` | `true` | Mask tool output at `tools/post-execute` |
| `maskUrls` | `false` | `false`, `internal`, or `all` |
| `privateUrlSuffixes` | built-in | Internal host suffixes |
| `maskDbCredentials` | `true` | Mask database connection strings |
| `auditRequests` | `true` | Report residual matches at dispatch |
| `highRiskAlertAfter` | `6` | Warn after this many consecutive high-risk masks |
| `maxImagesPerTurn` | `3` | Warn when a request carries more images |
| `ocr` | `true` | Analyze images at all |
| `imageBackend` | `auto` | `auto`, `winrt`, `python`, `none` |
| `pythonPath` | PATH lookup | Python interpreter |
| `tesseractPath` | PATH lookup | Tesseract binary |
| `ocrLanguage` | `zh-Hans-CN` | WinRT language tag |
| `tesseractLanguage` | `chi_sim+eng` | Tesseract language pack |
| `ocrTimeoutMs` | `20000` | Per-image deadline |
| `ocrMaxImagesPerTurn` | `3` | Images analyzed per step |
| `redactImages` | `true` | Cover sensitive text with an opaque fill |
| `redactColor` | `#000000` | Fill color, `#RRGGBB` |
| `detectAddresses` | `true` | Mask address-shaped runs |
| `detectMedical` | `true` | Mask medical record markers |
| `detectQr` | `true` | Decode and mask QR payloads |
| `markBinary` | `true` | Report archives and binary files, never parse them |
| `detectBypass` | `true` | Report requests with no session id |
| `compressImages` | `true` | Downscale before upload |
| `compressMaxDimension` | `2048` | Long-edge cap in pixels |
| `disabledRules` | `[]` | Rule ids to skip |
| `whitelist` | built-in samples | Values never masked |
| `logMasks` | `true` | Log markers without values |

## Moving to another machine

Copy the bundle directory, then:

1. `npm install` — installs `jsqr`. Skip it and QR detection is skipped.
2. `node ocr/selfcheck.mjs` — prints what this machine can do.
3. If image analysis is wanted off Windows, install Pillow
   (`pip install pillow`) and tesseract with the language pack you need.

The self-check reports `OK`, `WARN`, or `MISS` per capability and exits
non-zero only on a real failure, so it works in a script. `--json` gives the
same rows as structured output.

## Guarantees and limits

- Substitution is single-pass and forward-only. Originals are never stored,
  never restored, and never logged.
- The session placeholder registry keeps a SHA-256 digest per value, never the
  value, so the same secret keeps the same placeholder across a session without
  the plaintext being retained.
- The plugin governs requests this Host builds. It cannot turn off logging at a
  third-party relay gateway; that stays a gateway-side setting.
- Rules are pattern-based. They catch the listed formats, not every possible
  spelling; add a rule or a `disabledRules` entry for your corpus.
- Address and medical detection is deliberately narrow. It fires on
  administrative-division chains and clinical markers, and accepts limited
  recall rather than masking ordinary prose.
