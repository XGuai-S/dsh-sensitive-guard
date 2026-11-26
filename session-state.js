/**
 * 会话状态 / Per-session state.
 *
 * 挂载点共享同一份会话状态：占位符注册表、告警计数、已分析附件、临时白名单。
 * 把它们从 `apply()` 的闭包变量收进一个对象，是为了让三个挂载点不再各自
 * 复制「按 sessionId 取状态」的样板代码。
 *
 * The hook points share one per-session state object. Collecting the four maps
 * here removes the repeated "look up by sessionId" boilerplate that each hook
 * previously carried.
 */

import { createRegistry } from './masking.js';

/** 未归属会话的键 / key for state without a session id. */
const FALLBACK_KEY = 'default';

/**
 * 按会话组织的状态仓库 / Session-scoped state store.
 *
 * 懒创建：只有真正发生过命中的会话才会占用内存，长会话不会因为「打开过」
 * 就持有空对象。
 *
 * Lazy: a session allocates an entry only when it actually needs one, so a long
 * session that never triggers a rule holds nothing.
 */
export class SessionState {
  /**
   * @param {object} config 归一化配置 / normalized config
   */
  constructor(config) {
    this.config = config;
    this.disabledRules = config.disabledRulesSet ?? new Set(config.disabledRules ?? []);
    /** @type {Map<string, object>} 占位符注册表 / placeholder registries */
    this.registries = new Map();
    /** @type {Map<string, number>} 连续高风险计数 / consecutive high-risk counts */
    this.streaks = new Map();
    /** @type {Map<string, Set<string>>} 已分析附件 / analyzed attachments */
    this.scanned = new Map();
    /** @type {Map<string, Set<string>>} 会话临时白名单 / session whitelists */
    this.whitelists = new Map();
  }

  /**
   * 归一化会话键 / Normalize a session key.
   * @param {unknown} sessionId
   * @returns {string}
   */
  static keyOf(sessionId) {
    return typeof sessionId === 'string' && sessionId.length > 0 ? sessionId : FALLBACK_KEY;
  }

  /** 占位符注册表 / placeholder registry for one session. */
  registryFor(sessionId) {
    const key = SessionState.keyOf(sessionId);
    let registry = this.registries.get(key);
    if (registry === undefined) {
      registry = createRegistry();
      this.registries.set(key, registry);
    }
    return registry;
  }

  /** 已分析附件集合 / analyzed attachment ids for one session. */
  scannedFor(sessionId) {
    const key = SessionState.keyOf(sessionId);
    let seen = this.scanned.get(key);
    if (seen === undefined) {
      seen = new Set();
      this.scanned.set(key, seen);
    }
    return seen;
  }

  /** 会话临时白名单 / session-scoped whitelist. */
  whitelistFor(sessionId) {
    const key = SessionState.keyOf(sessionId);
    let list = this.whitelists.get(key);
    if (list === undefined) {
      list = new Set(this.config.sessionWhitelist);
      this.whitelists.set(key, list);
    }
    return list;
  }

  /**
   * 构造一次扫描的上下文 / Build the context one scan needs.
   * @param {unknown} sessionId
   * @param {object[]} rules
   */
  contextFor(sessionId, rules) {
    return {
      rules,
      config: this.config,
      disabledRules: this.disabledRules,
      registry: this.registryFor(sessionId),
      sessionWhitelist: this.whitelistFor(sessionId),
    };
  }

  /**
   * 累加一次命中并更新计数 / Accumulate one hit and advance the streak.
   * @param {unknown} sessionId
   * @returns {number} 该会话当前连续计数 / the session's current streak
   */
  bumpStreak(sessionId) {
    const key = SessionState.keyOf(sessionId);
    const next = (this.streaks.get(key) ?? 0) + 1;
    this.streaks.set(key, next);
    return next;
  }

  /** 新一轮用户输入：重置该会话的连续计数 / Reset the streak for a new input. */
  resetStreak(sessionId) {
    this.streaks.delete(SessionState.keyOf(sessionId));
  }

  /** 释放一个会话的全部状态 / Drop every entry for one session. */
  forget(sessionId) {
    const key = SessionState.keyOf(sessionId);
    this.registries.delete(key);
    this.streaks.delete(key);
    this.scanned.delete(key);
    this.whitelists.delete(key);
  }

  /** 当前占用会话数 / number of tracked sessions. */
  get size() {
    return this.registries.size;
  }
}
