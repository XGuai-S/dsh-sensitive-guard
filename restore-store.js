/**
 * 可逆脱敏映射表 / Reversible placeholder→plaintext store.
 *
 * 仅在 config.reversible=true 时启用。按会话存 占位符→原文 映射，
 * 0600 权限落盘，供 sensitive_guard_restore 工具还原。
 * 发给厂商的模型上下文里只有占位符，原文只在本机。
 */
import { mkdirSync, writeFileSync, readFileSync, existsSync, chmodSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
const HOME = process.env.DSH_HOME || homedir();
const STORE_ROOT = join(HOME, 'sensitive-guard', 'restore');
/** 落盘失败时的退回目录（沙箱环境 .dsh 不可写时用临时目录）。 */
const FALLBACK_ROOT = join(tmpdir(), 'dsh-sensitive-guard-restore');

/** 按 session 取映射表 / get the per-session restore map. */
export function createRestoreStore(sessionId = 'default') {
  const safe = String(sessionId).replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 64);
  const file = join(STORE_ROOT, `${safe}.json`);
  const fallbackFile = join(FALLBACK_ROOT, `${safe}.json`);
  let map = new Map();
  try {
    const src = existsSync(file) ? file : (existsSync(fallbackFile) ? fallbackFile : null);
    if (src) {
      const obj = JSON.parse(readFileSync(src, 'utf8'));
      map = new Map(Object.entries(obj));
    }
  } catch { /* 读失败从空表开始 */ }

  let activeFile = file;
  const persist = () => {
    const content = JSON.stringify(Object.fromEntries(map));
    for (const target of [file, fallbackFile]) {
      try {
        mkdirSync(dirname(target), { recursive: true });
        writeFileSync(target, content, { encoding: 'utf8', mode: 0o600 });
        chmodSync(target, 0o600);
        activeFile = target;
        return;
      } catch { /* 换下一个位置 */ }
    }
  };

  return {
    /** 记录 占位符→原文 / record a mapping. */
    record(placeholder, plaintext) {
      if (typeof placeholder !== 'string' || typeof plaintext !== 'string') return;
      if (map.has(placeholder)) return; // 同一占位符只记一次
      map.set(placeholder, plaintext);
      persist();
    },
    /** 还原一个或多个占位符 / restore placeholders. */
    restore(placeholders) {
      const out = {};
      for (const p of placeholders) {
        if (typeof p === 'string' && map.has(p)) out[p] = map.get(p);
      }
      return out;
    },
    get size() { return map.size; },
  };
}

/** 把还原结果写成 0600 文件，返回路径 / write restored text to a 0600 file. */
export function writeRestoreFile(rendered, sessionId = 'default') {
  const safe = String(sessionId).replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 64);
  for (const dir of [STORE_ROOT, FALLBACK_ROOT]) {
    const file = join(dir, `${safe}.restored.txt`);
    try {
      mkdirSync(dir, { recursive: true });
      writeFileSync(file, rendered, { encoding: 'utf8', mode: 0o600 });
      chmodSync(file, 0o600);
      return file;
    } catch { /* 换下一个位置 */ }
  }
  throw new Error('无法写入还原文件');
}
