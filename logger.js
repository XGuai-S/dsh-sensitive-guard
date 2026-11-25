/**
 * 日志输出 / Logging.
 *
 * 三件事集中在这里：通道选择（logger + stderr）、格式选择（json / text）、
 * 告警分级（普通 / 高风险 / 连续命中）。
 *
 * Three concerns live here: channel selection, format selection, and alert
 * grading. Keeping them out of the hook points is what lets each hook read as
 * "scan, then act" instead of "scan, then format a log line".
 */

import { structuredLog, inputHash } from './masking.js';
import { LEVELS, HIGH_RISK_KINDS } from './rules.js';

/**
 * 日志器 / Logger bound to one plugin instance.
 */
export class GuardLogger {
  /**
   * @param {object} config 归一化配置 / normalized config
   * @param {{info?: (line: string) => void}} [sink] 宿主 logger / host logger
   */
  constructor(config, sink) {
    this.config = config;
    this.sink = sink;
  }

  /**
   * 输出一行 / Emit one line.
   *
   * 同时写 stderr：`ctx.logger` 在某些部署下被吞掉，诊断需要一条直接可见的
   * 通道。`logToStderr` 可关闭。
   *
   * Also writes to stderr because `ctx.logger` is swallowed in some deployments.
   */
  line(text) {
    if (this.config.logMasks === false) return;
    try {
      this.sink?.info?.(text);
    } catch {
      // 日志失败不得改变判定 / logging never changes a decision.
    }
    if (this.config.logToStderr !== false) {
      try {
        process.stderr.write(`${text}\n`);
      } catch {
        // 忽略 / ignored.
      }
    }
  }

  /**
   * 输出一次脱敏结果 / Report one scan outcome.
   *
   * 固定字段：time、source、level、hitType、hitText、ruleId、inputHash。
   * `hitText` 只含掩码预览，不含原文。
   *
   * @param {{level: string, counts: object, kinds: Set<string>, hits: object[]}} result
   * @param {string} source 来源标记 / origin label
   * @param {string} [rawText] 原始输入，仅用于摘要 / raw input, hashed only
   */
  report(result, source, rawText) {
    const digest = inputHash(rawText);
    if (this.config.logFormat === 'json') {
      this.line(`sensitive-guard ${structuredLog(result, source, digest)}`);
      return;
    }
    const kinds = result.kinds && result.kinds.size > 0 ? [...result.kinds].join('/') : '-';
    const counts = Object.entries(result.counts ?? {}).map(([p, c]) => `${p}×${c}`).join(' ');
    this.line(`sensitive-guard [${source}] level=${result.level} 命中=${kinds}${counts ? ` ${counts}` : ''} hash=${digest}`);
  }

  /**
   * 输出一条告警 / Emit one alert.
   *
   * 分三级：普通脱敏、高风险命中、绕过攻击尝试。高风险类别单独标注，
   * 因为它与普通验证码的风险量级不同。
   *
   * Three grades: ordinary mask, high-risk hit, bypass attempt. High-risk kinds
   * are marked separately because they differ in severity from, say, an OTP.
   *
   * @param {string} label 告警文本 / alert text
   * @param {{level?: string, kinds?: Set<string>}} [context]
   */
  alert(label, context = {}) {
    const isHighRisk = context.level === LEVELS.block
      && (context.kinds === undefined || [...context.kinds].some((kind) => HIGH_RISK_KINDS.has(kind)));
    const grade = isHighRisk ? '【高风险命中】' : '';
    this.line(`sensitive-guard ${grade}${label}`);
  }

  /** 一条普通诊断 / one ordinary diagnostic. */
  info(label) {
    this.line(`sensitive-guard ${label}`);
  }

  /** 一条警告 / one warning. */
  warn(label) {
    this.line(`sensitive-guard 【⚠️${label}】`);
  }

  /** 一条错误 / one error. */
  error(label) {
    this.line(`sensitive-guard 【⛔${label}】`);
  }
}

/**
 * 连续命中告警 / Streak alert.
 *
 * 规格要求「单会话连续 6 次命中高风险脱敏，输出告警提醒」。计数由
 * `SessionState` 维护，这里只判断是否到达阈值。
 *
 * The spec asks for an alert after six consecutive high-risk hits in one
 * session. The count lives in `SessionState`; this only tests the threshold.
 *
 * @param {number} streak 当前连续计数 / current streak
 * @param {number} threshold 阈值 / threshold
 * @returns {boolean}
 */
export function shouldAlertStreak(streak, threshold) {
  return streak === threshold;
}
