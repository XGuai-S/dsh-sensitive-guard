#!/usr/bin/env node
/**
 * Portability self-check.
 *
 * Run this on a new machine before trusting the guard. It reports what works,
 * what degrades, and what is missing, using only what is already installed —
 * it never downloads anything.
 *
 *   node ocr/selfcheck.mjs
 *   node ocr/selfcheck.mjs --json
 */

import { selectBackend } from './backend.js';
import { buildRules, resolveConfig, maskText, createRegistry } from '../index.js';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const json = process.argv.includes('--json');

const rows = [];
const record = (area, status, detail) => rows.push({ area, status, detail });

// --- platform ---
record('platform', 'info', `${process.platform} / node ${process.version}`);

// --- text masking, the part that always works ---
try {
  const config = resolveConfig({});
  const rules = buildRules(config);
  const probe = maskText('sk-abcdefghijklmnop1234 13800138000', rules, { config, registry: createRegistry() });
  if (probe.risk === 'high' && probe.text.includes('{{SECRET_TOKEN}}')) {
    record('text masking', 'ok', `${rules.length} rules active`);
  } else {
    record('text masking', 'fail', 'rules did not mask a known secret');
  }
} catch (error) {
  record('text masking', 'fail', error.message);
}

// --- QR decoding ---
try {
  await import('jsqr');
  record('qr decoding', 'ok', 'jsqr resolved');
} catch {
  record('qr decoding', 'degraded', 'jsqr missing; run npm install in the bundle');
}

// --- image backend ---
const backend = await selectBackend({});
if (backend.backend === null) {
  record('image backend', 'degraded', `none (${backend.reason}); images are not read`);
} else {
  record('image backend', 'ok', backend.name);
  if (backend.ocr) {
    record('image text (ocr)', 'ok', `backend ${backend.name}`);
  } else {
    record('image text (ocr)', 'degraded', `no recognizer (${backend.reason ?? 'unknown'}); pixels, redaction and scaling still work`);
  }
}

// --- bundled scripts ---
for (const script of ['win-ocr.ps1', 'win-redact.ps1', 'win-pixels.ps1', 'win-compress.ps1', 'imgops.py']) {
  const present = existsSync(join(HERE, script));
  record(`file ${script}`, present ? 'ok' : 'missing', present ? '' : 'not in the package');
}

if (json) {
  process.stdout.write(`${JSON.stringify(rows, null, 2)}\n`);
} else {
  const width = Math.max(...rows.map((row) => row.area.length));
  for (const row of rows) {
    const marker = row.status === 'ok' ? 'OK  ' : row.status === 'info' ? '--  ' : row.status === 'missing' ? 'MISS' : 'WARN';
    process.stdout.write(`${marker}  ${row.area.padEnd(width)}  ${row.detail}\n`);
  }
  const degraded = rows.filter((row) => row.status !== 'ok' && row.status !== 'info');
  process.stdout.write(`\n${degraded.length === 0 ? 'All capabilities available.' : `${degraded.length} item(s) degraded; text masking still works.`}\n`);
}

process.exitCode = rows.some((row) => row.status === 'fail') ? 1 : 0;
