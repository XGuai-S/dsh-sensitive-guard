// 可逆脱敏测试：reversible=true 时占位符→原文映射 0600 落盘，可还原。
import { buildFullRules, resolveConfig, createRegistry, runSanitize } from '../index.js';
import { createRestoreStore } from '../restore-store.js';

let failures = 0;
const check = (label, actual, expected) => {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label} → ${actual}`);
};

const config = resolveConfig({ reversible: true });
config.disabledRulesSet = new Set(config.disabledRules);
const rules = buildFullRules(config);
const store = createRestoreStore('reversible-test');
const ctx = { config, disabledRules: config.disabledRulesSet, registry: createRegistry(), restoreStore: store };

const text = '手机号 13800138000 密码 pass123 xyz';
const r = runSanitize(text, rules, ctx);
check('手机号被脱敏', r.content.includes('{{PHONE_NO}}'), true);
check('密码被脱敏', r.content.includes('{{CRED_CODE}}'), true);
check('映射已记录（≥2条）', store.size >= 2, true);

const phonePh = r.hits.find((h) => h.ruleId === 'cn-mobile')?.placeholder;
check('拿到手机号占位符', typeof phonePh === 'string', true);
if (phonePh) {
  const restored = store.restore([phonePh]);
  check('还原出真实手机号', Object.values(restored)[0] === '13800138000', true);
}

// 关闭 reversible 时不记录
const config2 = resolveConfig({ reversible: false });
config2.disabledRulesSet = new Set(config2.disabledRules);
const store2 = createRestoreStore('reversible-off-test');
const ctx2 = { config: config2, disabledRules: config2.disabledRulesSet, registry: createRegistry(), restoreStore: undefined };
runSanitize(text, buildFullRules(config2), ctx2);
check('reversible=false 不记录', store2.size, 0);

// 跨多次扫描共享同一 store（模拟 per-session context）：映射累积、可还原。
const sharedStore = createRestoreStore('shared-store-test');
const sharedCtx = { config, disabledRules: config.disabledRulesSet, registry: createRegistry(), restoreStore: sharedStore };
const r1 = runSanitize('手机号 13712345678', rules, sharedCtx);
const r2 = runSanitize('邮箱 shared@example.com', rules, sharedCtx);
const p1 = r1.hits.find((h) => h.ruleId === 'cn-mobile')?.placeholder;
const p2 = r2.hits.find((h) => h.ruleId === 'email')?.placeholder;
check('共享 store 累积两条映射', sharedStore.size >= 2, true);
const both = sharedStore.restore([p1, p2].filter(Boolean));
check('跨扫描还原手机号', both[p1] === '13712345678', true);
check('跨扫描还原邮箱', both[p2] === 'shared@example.com', true);

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
