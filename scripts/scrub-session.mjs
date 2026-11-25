#!/usr/bin/env node
/**
 * 会话日志明文清理 / Session-log plaintext scrubber.
 *
 * 用途 / Purpose:
 *
 * DSH 在 API 层把用户输入写入 `agent/inbox/spliced`，这一层早于任何插件钩子。
 * 因此即使前置拦截生效，历史日志里仍可能留有明文。本工具按会话日志的
 * 事件结构就地脱敏，把明文替换为占位符。
 *
 * DSH writes the prompt into `agent/inbox/spliced` before any plugin hook runs.
 * Historical logs can therefore still contain plaintext. This tool masks those
 * events in place.
 *
 * 风险 / Risks:
 *
 * - **破坏性**：直接改写已提交的会话日志。改写后无法还原。
 * - **必须停用 DSH 后再运行**：运行中的 Host 会追加新帧，并发写会损坏日志。
 * - **先备份**：工具默认先复制一份 `.bak`，除非显式传 `--no-backup`。
 *
 * - Destructive: it rewrites committed session logs, and the change is final.
 * - The Host must be stopped first; a running Host appends frames concurrently.
 * - A `.bak` copy is written first unless `--no-backup` is passed.
 *
 * 用法 / Usage:
 *
 *   node ocr/../scripts/scrub-session.mjs --session <dir> [--dry-run] [--no-backup]
 *   node scripts/scrub-session.mjs --all --dry-run
 */

import { readFile, writeFile, readdir, stat, copyFile } from 'node:fs/promises';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { homedir } from 'node:os';
import { zstdDecompressSync, zstdCompressSync } from 'node:zlib';

const HERE = dirname(fileURLToPath(import.meta.url));
const ZSTD_MAGIC = Buffer.from([0x28, 0xB5, 0x2F, 0xFD]);

/** 默认会话根目录 / default session root. */
const DEFAULT_ROOT = join(process.env.DSH_HOME ?? join(homedir(), '.dsh'), 'sessions');

/**
 * 拆解多帧 zstd 日志 / Split a multi-frame zstd log into frames.
 * @param {Buffer} raw
 * @returns {{offset: number, end: number}[]}
 */
export function splitFrames(raw) {
  const offsets = [];
  let index = 0;
  while (true) {
    const found = raw.indexOf(ZSTD_MAGIC, index);
    if (found === -1) break;
    offsets.push(found);
    index = found + 4;
  }
  return offsets.map((offset, position) => ({
    offset,
    end: position + 1 < offsets.length ? offsets[position + 1] : raw.length,
  }));
}

/**
 * 解压整个多帧日志 / Decompress every frame of a multi-frame log.
 * @param {Buffer} raw
 * @returns {string}
 */
export function decompressAll(raw) {
  let text = '';
  for (const frame of splitFrames(raw)) {
    try {
      text += zstdDecompressSync(raw.subarray(frame.offset, frame.end)).toString('utf8');
    } catch {
      // 损坏的帧跳过，不影响其余内容。
    }
  }
  return text;
}

/**
 * 扫描并替换一段文本 / Scan and replace one string.
 *
 * 本工具只做「把明文换成占位符」这一件事，不依赖插件的完整规则引擎：
 * 它按调用方传入的规则表工作，保证与插件同一套判定。
 *
 * @param {string} text
 * @param {object[]} rules
 * @param {object} context
 * @param {Function} runSanitize
 * @returns {{text: string, changed: boolean, counts: object}}
 */
export function scrubText(text, runSanitize, rules, context) {
  if (typeof text !== 'string' || text.length === 0) return { text, changed: false, counts: {} };
  const result = runSanitize(text, rules, context);
  if (result.level === 'PASS') return { text, changed: false, counts: {} };
  return { text: result.content, changed: result.content !== text, counts: result.counts };
}

/**
 * 清理一条会话日志 / Scrub one session log.
 *
 * @param {string} file
 * @param {{dryRun?: boolean, backup?: boolean, runSanitize: Function, rules: object[], context: object}} options
 * @returns {Promise<{file: string, events: number, scrubbed: number, samples: string[]}>}
 */
export async function scrubLog(file, options) {
  const raw = await readFile(file);
  const text = decompressAll(raw);
  if (text.length === 0) return { file, events: 0, scrubbed: 0, samples: [] };

  const lines = text.split('\n').filter((line) => line.length > 0);
  let scrubbed = 0;
  const samples = [];
  const rewritten = [];

  for (const line of lines) {
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      rewritten.push(line);
      continue;
    }

    // 只处理携带用户文本的事件类型。
    if (event?.type !== 'agent/inbox/spliced' && event?.type !== 'user/message') {
      rewritten.push(line);
      continue;
    }

    const before = JSON.stringify(event);
    const masked = scrubEvent(event, options.runSanitize, options.rules, options.context);
    const after = JSON.stringify(masked);
    if (after !== before) {
      scrubbed += 1;
      if (samples.length < 5) samples.push(`seq=${event.seq} type=${event.type}`);
      rewritten.push(after);
    } else {
      rewritten.push(line);
    }
  }

  if (!options.dryRun && scrubbed > 0) {
    if (options.backup !== false) {
      await copyFile(file, `${file}.bak`);
    }
    // 重新编码为单帧 zstd；读取端按帧扫描，单帧同样合法。
    const payload = Buffer.from(`${rewritten.join('\n')}\n`, 'utf8');
    await writeFile(file, zstdCompressSync(payload));
  }

  return { file, events: lines.length, scrubbed, samples };
}

/**
 * 递归清理一个事件里所有字符串叶子 / Scrub every string leaf of one event.
 * @param {unknown} value
 */
function scrubEvent(value, runSanitize, rules, context) {
  if (typeof value === 'string') {
    return scrubText(value, runSanitize, rules, context).text;
  }
  if (Array.isArray(value)) {
    return value.map((item) => scrubEvent(item, runSanitize, rules, context));
  }
  if (value !== null && typeof value === 'object') {
    const next = {};
    for (const [key, item] of Object.entries(value)) {
      next[key] = scrubEvent(item, runSanitize, rules, context);
    }
    return next;
  }
  return value;
}

/**
 * 列出所有会话日志 / List every session log under a root.
 *
 * 目录结构是三层：`<root>/<workspace>/<session>/session.v4.jsonl.zstd`。
 * 逐层展开，最多三层，避免在深层目录上浪费 I/O。
 *
 * The layout is three levels deep. It is walked explicitly rather than with a
 * recursive search, so an unexpected tree costs one bounded readdir.
 *
 * @param {string} root
 * @returns {Promise<string[]>}
 */
async function findLogs(root) {
  const logs = [];
  let workspaces;
  try {
    workspaces = await readdir(root, { withFileTypes: true });
  } catch {
    return logs;
  }
  for (const workspace of workspaces) {
    if (!workspace.isDirectory()) continue;
    const workspaceDir = join(root, workspace.name);
    let sessions;
    try {
      sessions = await readdir(workspaceDir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const session of sessions) {
      if (!session.isDirectory()) continue;
      const sessionDir = join(workspaceDir, session.name);
      let files;
      try {
        files = await readdir(sessionDir);
      } catch {
        continue;
      }
      for (const file of files) {
        if (!file.endsWith('.zstd')) continue;
        logs.push(join(sessionDir, file));
      }
    }
  }
  return logs;
}

async function main() {
  const args = process.argv.slice(2);
  const dryRun = args.includes('--dry-run');
  const noBackup = args.includes('--no-backup');
  const all = args.includes('--all');
  const skipActive = args.includes('--skip-active');
  const activeIndex = args.indexOf('--active');
  const sessionIndex = args.indexOf('--session');
  const rootIndex = args.indexOf('--root');

  const root = rootIndex >= 0 ? args[rootIndex + 1] : DEFAULT_ROOT;
  // 活动会话：正在被 Host 追加帧，覆写会损坏日志。
  const activeSession = activeIndex >= 0 ? args[activeIndex + 1] : undefined;

  // 动态载入插件规则，保证与运行中的判定一致。
  // Windows 绝对路径必须转成 file:// URL，ESM 加载器不接受裸盘符。
  const pluginUrl = pathToFileURL(join(HERE, '..', 'index.js')).href;
  const plugin = await import(pluginUrl);
  const config = plugin.resolveConfig({});
  const rules = plugin.buildFullRules(config);
  const context = { rules, config, registry: plugin.createRegistry() };

  const targets = [];
  if (sessionIndex >= 0) {
    const sessionDir = args[sessionIndex + 1];
    const files = await readdir(sessionDir).catch(() => []);
    for (const file of files) if (file.endsWith('.zstd')) targets.push(join(sessionDir, file));
  } else if (all) {
    targets.push(...await findLogs(root));
  } else {
    process.stderr.write('需要 --session <dir> 或 --all\n');
    process.exitCode = 2;
    return;
  }

  // 跳过活动会话：Host 正在追加帧，并发写会损坏文件。
  const filtered = targets.filter((file) => {
    if (!skipActive || activeSession === undefined) return true;
    const isActive = file.includes(activeSession);
    if (isActive) {
      process.stdout.write(`跳过活动会话（Host 正在写入）：${basename(dirname(file))}\n`);
    }
    return !isActive;
  });

  if (filtered.length === 0) {
    process.stdout.write('没有可清理的会话日志\n');
    return;
  }

  let total = 0;
  for (const file of filtered) {
    const result = await scrubLog(file, {
      dryRun,
      backup: !noBackup,
      runSanitize: plugin.runSanitize,
      rules,
      context,
    });
    total += result.scrubbed;
    const label = basename(dirname(file));
    process.stdout.write(`${dryRun ? '[dry-run] ' : ''}${label}: ${result.scrubbed}/${result.events} 事件需清理\n`);
    for (const sample of result.samples) process.stdout.write(`    ${sample}\n`);
  }

  process.stdout.write(`\n合计 ${total} 个事件${dryRun ? '（未写入）' : '已清理'}\n`);
  if (!dryRun && total > 0 && noBackup) {
    process.stdout.write('注意：使用了 --no-backup，原始日志未备份\n');
  }
}

// 仅作为脚本运行时执行 main。
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    process.stderr.write(`失败：${error?.message ?? error}\n`);
    process.exitCode = 1;
  });
}
