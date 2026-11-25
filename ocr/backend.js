/**
 * Backend selection for the image operations.
 *
 * Two backends implement the same five operations:
 *
 * - **winrt** — Windows only. `Windows.Media.Ocr` for recognition and the
 *   WinRT imaging surface for pixels, redaction, and scaling. Ships with the OS,
 *   so a Windows machine needs nothing installed.
 * - **python** — any platform with Python and Pillow. Recognition uses the
 *   `tesseract` CLI; pixels, redaction, and scaling use Pillow directly.
 *
 * Selection is by probe, in that order, and the choice is reported so a caller
 * can log which path is live. A missing backend degrades to "text masking only"
 * rather than failing the guard.
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { access, mkdtemp, open, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';

const HERE = dirname(fileURLToPath(import.meta.url));

/** Default bound for one image operation. */
export const DEFAULT_TIMEOUT_MS = 20_000;

/**
 * Run a command with no piped stdio.
 *
 * `stdio: 'ignore'` is required, not a preference: a confined host cannot open
 * the pipes that `execFile` and `stdio: 'pipe'` rely on, and spawning with them
 * fails with EPERM. Every result travels through a file instead.
 */
export function runQuiet(command, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { timeout: timeoutMs, windowsHide: true, stdio: 'ignore' });
    child.on('error', (error) => reject(new Error(error.code === 'EPERM' ? 'spawn-denied' : error.message)));
    child.on('exit', (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(signal ? `timeout-${signal}` : `exit-${code}`));
    });
  });
}

/** Locate a command on PATH without spawning a shell. */
async function findCommand(name) {
  const pathValue = process.env.PATH ?? '';
  const separator = process.platform === 'win32' ? ';' : ':';
  const extensions = process.platform === 'win32' ? ['.exe', '.cmd', '.bat', ''] : [''];
  for (const directory of pathValue.split(separator)) {
    if (!directory) continue;
    for (const extension of extensions) {
      const candidate = join(directory, name + extension);
      try {
        await access(candidate);
        return candidate;
      } catch {
        // Try the next candidate.
      }
    }
  }
  return undefined;
}

/** Read the leading bytes of a file, for container detection. */
export async function readFileHead(filePath, length = 16) {
  const handle = await open(filePath, 'r');
  try {
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await handle.read(buffer, 0, length, 0);
    return new Uint8Array(buffer.buffer, buffer.byteOffset, bytesRead);
  } finally {
    await handle.close();
  }
}

/** Parse the tab-separated box format both backends emit. */
function parseBoxes(raw) {
  const lines = [];
  for (const line of raw.split(/\r?\n/)) {
    if (line.length === 0) continue;
    const parts = line.split('\t');
    if (parts.length < 6) continue;
    lines.push({
      x: Number(parts[1]),
      y: Number(parts[2]),
      w: Number(parts[3]),
      h: Number(parts[4]),
      text: parts.slice(5).join('\t'),
    });
  }
  return lines;
}

/**
 * The WinRT backend, available on Windows only.
 * @param {{language: string, timeoutMs: number}} options
 */
function winrtBackend(options) {
  const scripts = {
    ocr: join(HERE, 'win-ocr.ps1'),
    redact: join(HERE, 'win-redact.ps1'),
    pixels: join(HERE, 'win-pixels.ps1'),
    compress: join(HERE, 'win-compress.ps1'),
  };
  const shell = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');

  const run = (script, args) =>
    runQuiet(shell, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script, ...args], options.timeoutMs);

  return {
    name: 'winrt',
    platform: 'win32',
    async recognize(imagePath) {
      const workDir = await mkdtemp(join(tmpdir(), 'dsh-ocr-'));
      const outFile = join(workDir, 'result.txt');
      const args = ['-Path', imagePath, '-OutFile', outFile];
      if (options.language) args.push('-Language', options.language);
      try {
        await run(scripts.ocr, args);
        return parseBoxes(await readFile(outFile, 'utf8'));
      } finally {
        await rm(workDir, { recursive: true, force: true }).catch(() => {});
      }
    },
    async redact(imagePath, boxes, redactOptions) {
      const boxArgs = boxes.map((box) => `${box.x},${box.y},${box.w},${box.h}`).join(';');
      const args = ['-Path', imagePath, '-OutFile', redactOptions.outPath, '-Boxes', boxArgs];
      if (redactOptions.color) args.push('-Color', redactOptions.color);
      await run(scripts.redact, args);
    },
    async pixels(imagePath) {
      const workDir = await mkdtemp(join(tmpdir(), 'dsh-px-'));
      const outFile = join(workDir, 'pixels.bin');
      try {
        await run(scripts.pixels, ['-Path', imagePath, '-OutFile', outFile]);
        const raw = await readFile(outFile);
        if (raw.length < 8) throw new Error('pixels-truncated');
        const width = raw.readInt32LE(0);
        const height = raw.readInt32LE(4);
        const expected = width * height * 4;
        if (width <= 0 || height <= 0 || raw.length < 8 + expected) throw new Error('pixels-malformed');
        return { width, height, pixels: new Uint8Array(raw.buffer, raw.byteOffset + 8, expected) };
      } finally {
        await rm(workDir, { recursive: true, force: true }).catch(() => {});
      }
    },
    async compress(imagePath, compressOptions) {
      const args = ['-Path', imagePath, '-OutFile', compressOptions.outPath, '-MaxDimension', String(compressOptions.maxDimension)];
      await run(scripts.compress, args);
      const raw = await readFile(compressOptions.outPath);
      if (raw.length < 8) throw new Error('compress-truncated');
      return {
        width: raw.readInt32LE(0),
        height: raw.readInt32LE(4),
        data: new Uint8Array(raw.buffer, raw.byteOffset + 8, raw.length - 8),
      };
    },
  };
}

/**
 * The Python backend, available wherever Pillow and optionally tesseract exist.
 * @param {{python: string, tesseract?: string, language: string, timeoutMs: number}} options
 */
function pythonBackend(options) {
  const script = join(HERE, 'imgops.py');
  const run = (args) => runQuiet(options.python, [script, ...args], options.timeoutMs);

  return {
    name: 'python',
    platform: process.platform,
    async recognize(imagePath) {
      if (options.tesseract === undefined) throw new Error('no-tesseract');
      const workDir = await mkdtemp(join(tmpdir(), 'dsh-ocr-'));
      const outFile = join(workDir, 'result.txt');
      try {
        await run([
          'ocr',
          '--path', imagePath,
          '--out', outFile,
          '--language', options.language,
          '--tesseract', options.tesseract,
          '--timeout', String(options.timeoutMs / 1000),
        ]);
        return parseBoxes(await readFile(outFile, 'utf8'));
      } finally {
        await rm(workDir, { recursive: true, force: true }).catch(() => {});
      }
    },
    async redact(imagePath, boxes, redactOptions) {
      const boxArgs = boxes.map((box) => `${box.x},${box.y},${box.w},${box.h}`).join(';');
      await run(['redact', '--path', imagePath, '--out', redactOptions.outPath, '--boxes', boxArgs, '--color', redactOptions.color ?? '#000000']);
    },
    async pixels(imagePath) {
      const workDir = await mkdtemp(join(tmpdir(), 'dsh-px-'));
      const outFile = join(workDir, 'pixels.bin');
      try {
        await run(['pixels', '--path', imagePath, '--out', outFile]);
        const raw = await readFile(outFile);
        if (raw.length < 8) throw new Error('pixels-truncated');
        const width = raw.readInt32LE(0);
        const height = raw.readInt32LE(4);
        const expected = width * height * 4;
        if (width <= 0 || height <= 0 || raw.length < 8 + expected) throw new Error('pixels-malformed');
        return { width, height, pixels: new Uint8Array(raw.buffer, raw.byteOffset + 8, expected) };
      } finally {
        await rm(workDir, { recursive: true, force: true }).catch(() => {});
      }
    },
    async compress(imagePath, compressOptions) {
      await run(['compress', '--path', imagePath, '--out', compressOptions.outPath, '--max-dimension', String(compressOptions.maxDimension)]);
      const raw = await readFile(compressOptions.outPath);
      if (raw.length < 8) throw new Error('compress-truncated');
      return {
        width: raw.readInt32LE(0),
        height: raw.readInt32LE(4),
        data: new Uint8Array(raw.buffer, raw.byteOffset + 8, raw.length - 8),
      };
    },
  };
}

/**
 * Pick a backend for this host.
 *
 * @param {{backend?: 'auto'|'winrt'|'python'|'none', pythonPath?: string, tesseractPath?: string, language?: string, timeoutMs?: number}} options
 * @returns {Promise<{backend: object|null, name: string, ocr: boolean, reason?: string}>}
 *   `backend` is null when nothing is usable; `ocr` says whether recognition
 *   (as opposed to only pixel operations) works.
 */
export async function selectBackend(options = {}) {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const language = options.language ?? (process.platform === 'win32' ? 'zh-Hans-CN' : 'chi_sim+eng');
  const wanted = options.backend ?? 'auto';

  if (wanted === 'none') return { backend: null, name: 'none', ocr: false, reason: 'disabled' };

  if (wanted === 'auto' || wanted === 'winrt') {
    if (process.platform === 'win32') {
      try {
        await access(join(HERE, 'win-ocr.ps1'));
        await access(join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'));
        return { backend: winrtBackend({ language, timeoutMs }), name: 'winrt', ocr: true };
      } catch (error) {
        if (wanted === 'winrt') return { backend: null, name: 'winrt', ocr: false, reason: error?.code ?? 'missing-script' };
      }
    } else if (wanted === 'winrt') {
      return { backend: null, name: 'winrt', ocr: false, reason: 'unsupported-platform' };
    }
  }

  const python = options.pythonPath ?? (await findCommand(process.platform === 'win32' ? 'python' : 'python3'));
  if (python === undefined) {
    return { backend: null, name: 'none', ocr: false, reason: 'no-python' };
  }
  const tesseract = options.tesseractPath ?? (await findCommand('tesseract'));
  return {
    backend: pythonBackend({ python, tesseract, language, timeoutMs }),
    name: 'python',
    ocr: tesseract !== undefined,
    reason: tesseract === undefined ? 'no-tesseract' : undefined,
  };
}
