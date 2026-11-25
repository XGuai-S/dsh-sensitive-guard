/**
 * 绕过防护 / Bypass-attack detection.
 *
 * 判定原则 / Judgement rule:
 *
 * 用户指令**要求**跳过脱敏、拆分敏感内容、用编码逃逸过滤、还原占位符时，
 * 判定为绕过攻击，直接拦截并上报，不转发给模型。
 *
 * 正常开发任务（写编码函数、做加解密、实现转码）**不是**绕过：
 * 它们描述的是要实现的能力，不是要求本守卫放弃职责。因此检测落在
 * 「祈使 + 目标」的组合上，而不是单独出现某个词。
 *
 * A request that *asks* the guard to stand down is an attack. Ordinary work
 * that implements encoding, encryption, or transcoding is not: it describes a
 * capability to build, not an instruction to abandon the guard. Detection
 * therefore requires an imperative aimed at the filtering itself, not a lone
 * keyword.
 */

/** 命中分类 / Hit category. */
export const BYPASS_KIND = '绕过尝试';

/**
 * 绕过规则 / Bypass rules.
 *
 * 每条规则要求「动作词」与「目标词」同时出现，且距离足够近。
 * 单独出现「base64」或「脱敏」都不触发。
 *
 * Each rule needs an action verb and a target close together. A lone
 * "base64" or "mask" never fires.
 */
const BYPASS_RULES = [
  {
    id: 'skip-masking',
    // 要求跳过/关闭/忽略脱敏或过滤。
    re: /(?:跳过|跳过|绕过|关闭|禁用|忽略|取消|去掉|移除|不执行|不要|别|停止|关掉|skip|disable|ignore|bypass|turn off|disable)\s*(?:掉|了|这个|这些|所有)?\s*(?:敏感)?\s*(?:内容)?\s*(?:脱敏|过滤|拦截|检查|审查|guard|filter|masking|redaction|sanitiz)/i,
  },
  {
    id: 'split-sensitive',
    // 要求把密钥/证件/密码拆开以躲过检测。
    // 中文语序允许「把 X 拆开」和「拆分 X」两种，因此用两条分支覆盖，
    // 而不是依赖固定词序。
    // Chinese allows both "把 X 拆开" and "拆分 X", so two branches cover the
    // two word orders instead of assuming one.
    re: /(?:拆分|分开|分割|切分|拆开|分段|split|break|fragment|chunk)[^\n]{0,16}?(?:密钥|key|token|密码|password|证件|身份证|银行卡|凭据|credential)|(?:把|将|对)[^\n]{0,8}?(?:密钥|key|token|密码|password|证件|身份证|银行卡|凭据|credential)[^\n]{0,8}?(?:拆分|分开|拆开|分割|切分|split|break|fragment)/i,
  },
  {
    id: 'encode-to-evade',
    // 要求把敏感内容编码后发送。
    re: /(?:base64|hex|rot13|rot-13|url\s*编码|urlencode|unicode\s*转义|二进制|encode|编码|加密|转码)\s*(?:一下|这个|这些)?\s*(?:后|再|然后)?\s*(?:发送|发出去|提交|传给|发给|send|submit|transmit)/i,
  },
  {
    id: 'encode-sensitive',
    // 明确要求对敏感内容做编码。
    re: /(?:把|将|对)\s*(?:这个|这些|那个)?\s*(?:密钥|key|token|密码|password|证件|身份证|银行卡|凭据|credential|敏感内容)\s*(?:用|做|进行)?\s*(?:base64|hex|rot13|url\s*编码|urlencode|编码|加密|转码)/i,
  },
  {
    id: 'restore-placeholder',
    // 要求还原占位符。
    re: /(?:还原|恢复|恢复成|换回|替换回|解码|解密|展开|还原出|restore|revert|decode|decrypt|expand)\s*(?:这个|这些)?\s*(?:占位符|placeholder|\{\{[A-Z_]+\}\})/i,
  },
  {
    id: 'reveal-original',
    // 要求输出脱敏前的原文。「未脱敏」是修饰语，允许出现在目标词之前。
    re: /(?:输出|显示|打印|告诉我|给出|列出|show|print|output|reveal|display)[^\n]{0,10}?(?:原始|原本|真实|未脱敏|明文)[^\n]{0,6}?(?:内容|值|密码|密钥|数据|原文)|(?:输出|显示|打印|告诉我|给出|列出|show|print|output|reveal|display)[^\n]{0,10}?(?:脱敏前|过滤前|masking\s*before|before\s*masking)[^\n]{0,6}?(?:内容|值|原文|content|value)/i,
  },
  {
    id: 'ignore-guard',
    // 要求忽略守卫规则。
    re: /(?:忽略|无视|不要遵守|不必遵守|不用管|ignore|disregard|forget)\s*(?:这个|这些|上述|上面|之前|所有)?\s*(?:规则|限制|约束|要求|指令|守卫|防护|rules?|restrictions?|guard|policy|instructions?)/i,
  },
];

/**
 * 判定一条用户指令是否为绕过攻击 / Decide whether one user instruction is a bypass attempt.
 *
 * @param {string} text 用户指令 / user instruction
 * @returns {{bypass: boolean, rule?: string}}
 */
export function detectBypassAttempt(text) {
  if (typeof text !== 'string' || text.length === 0) return { bypass: false };
  if (text.length > 100_000) return { bypass: false };
  for (const rule of BYPASS_RULES) {
    rule.re.lastIndex = 0;
    if (rule.re.test(text)) return { bypass: true, rule: rule.id };
  }
  return { bypass: false };
}

/**
 * 从一段消息内容里取出所有用户文本 / Collect user text from message content.
 * @param {unknown} content
 * @returns {string}
 */
export function userTextOf(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  const parts = [];
  for (const block of content) {
    if (block?.type === 'text' && typeof block.text === 'string') parts.push(block.text);
  }
  return parts.join('\n');
}
