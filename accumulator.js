/**
 * 扫描结果累加器 / Scan-result accumulator.
 *
 * 三个挂载点都需要把多次扫描的结果合并成一个「本轮总判定」：计数相加、
 * 类型取并集、等级取最高。这段逻辑此前在 `index.js` 里重复了三次，
 * 每处约 10 行。
 *
 * All three hook points merge several scan results into one verdict: counts
 * added, kinds unioned, level raised. That logic was duplicated three times in
 * `index.js`, roughly ten lines each.
 */

import { LEVELS } from './rules.js';

/**
 * 一次合并后的判定 / One merged verdict.
 */
export class ResultAccumulator {
  constructor() {
    /** @type {Record<string, number>} 占位符计数 / placeholder counts */
    this.counts = {};
    /** @type {Set<string>} 命中类型 / hit kinds */
    this.kinds = new Set();
    /** @type {object[]} 命中明细 / hit details */
    this.hits = [];
    /** @type {string} 当前最高等级 / current highest level */
    this.level = LEVELS.pass;
    /** @type {boolean} 是否有内容被改写 / whether any content changed */
    this.changed = false;
  }

  /**
   * 合并一次扫描结果 / Merge one scan result.
   * @param {{counts?: object, kinds?: Set<string>, hits?: object[], level?: string, changed?: boolean}} result
   * @returns {this}
   */
  add(result) {
    if (result === undefined || result === null) return this;
    for (const [placeholder, count] of Object.entries(result.counts ?? {})) {
      this.counts[placeholder] = (this.counts[placeholder] ?? 0) + count;
    }
    for (const kind of result.kinds ?? []) this.kinds.add(kind);
    if (Array.isArray(result.hits)) this.hits.push(...result.hits);
    this.level = higherLevel(this.level, result.level);
    if (result.changed === true) this.changed = true;
    return this;
  }

  /** 是否有命中 / whether anything matched. */
  get matched() {
    return this.level !== LEVELS.pass;
  }

  /** 是否命中阻断级 / whether the verdict is a block. */
  get blocked() {
    return this.level === LEVELS.block;
  }

  /** 命中类型列表，用于日志 / kinds as a list for logging. */
  kindList() {
    return this.kinds.size > 0 ? [...this.kinds] : ['其他'];
  }

  /** 纯数据视图，交给日志与结构化输出 / plain view for logs. */
  toResult() {
    return { level: this.level, counts: this.counts, kinds: this.kinds, hits: this.hits, changed: this.changed };
  }
}

/**
 * 取两个等级中较高的一个 / Return the higher of two levels.
 *
 * 顺序：BLOCK > MASK > PASS。未知值按 PASS 处理，避免异常值抬高判定。
 *
 * Order: BLOCK > MASK > PASS. An unknown value degrades to PASS so a malformed
 * result cannot raise the verdict.
 *
 * @param {string} current
 * @param {string} [next]
 * @returns {string}
 */
export function higherLevel(current, next) {
  const rank = (level) => (level === LEVELS.block ? 2 : level === LEVELS.mask ? 1 : 0);
  return rank(next) > rank(current) ? next : current;
}
