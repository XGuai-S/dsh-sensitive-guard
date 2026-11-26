// 架构模块测试 / Architecture module tests.
// 覆盖重构后新增的四个模块：session-state、accumulator、logger、image-pipeline。
import { SessionState } from '../session-state.js';
import { ResultAccumulator, higherLevel } from '../accumulator.js';
import { GuardLogger, shouldAlertStreak } from '../logger.js';
import { applyReplacements } from '../image-pipeline.js';
import { resolveConfig, LEVELS } from '../index.js';

let failures = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok ? '' : ` → got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};
const section = (name) => console.log(`\n--- ${name} ---`);

const config = resolveConfig({});

section('SessionState：按会话隔离');
const state = new SessionState(config);
const regA = state.registryFor('session-a');
const regB = state.registryFor('session-b');
check('不同会话不同注册表', regA !== regB, true);
check('同会话复用注册表', state.registryFor('session-a'), regA);
check('无会话落到 default', state.registryFor(undefined), state.registryFor('default'));
const scanContextA = state.contextFor('session-a', []);
const scanContextB = state.contextFor('session-b', []);
check('不同会话共享禁用规则集合实例', scanContextA.disabledRules === scanContextB.disabledRules, true);
check('空字符串落到 default', state.registryFor(''), state.registryFor('default'));

section('SessionState：占位符稳定性跨调用');
const p1 = regA.placeholderFor('{{SECRET_TOKEN}}', 'sk-abc123');
const p2 = state.registryFor('session-a').placeholderFor('{{SECRET_TOKEN}}', 'sk-abc123');
const p3 = regB.placeholderFor('{{SECRET_TOKEN}}', 'sk-abc123');
check('同会话同值同占位符', p1, p2);
check('跨会话各自计数', p3, '{{SECRET_TOKEN}}');

section('SessionState：连续计数');
check('首次计数为 1', state.bumpStreak('session-a'), 1);
check('二次计数为 2', state.bumpStreak('session-a'), 2);
check('重置后回到 1', (state.resetStreak('session-a'), state.bumpStreak('session-a')), 1);
check('不同会话独立', state.bumpStreak('session-b'), 1);

section('SessionState：白名单');
const wl = state.whitelistFor('session-a');
wl.add('myFalsePositive');
check('白名单可写入', wl.has('myFalsePositive'), true);
check('不同会话白名单隔离', state.whitelistFor('session-b').has('myFalsePositive'), false);

section('SessionState：释放');
const before = state.size;
state.forget('session-a');
check('释放后 size 减少', state.size < before, true);
check('释放后注册表重建', state.registryFor('session-a') !== regA, true);
check('释放后计数归零', state.bumpStreak('session-a'), 1);

section('ResultAccumulator：等级合并');
check('PASS 与 MASK 取 MASK', higherLevel(LEVELS.pass, LEVELS.mask), LEVELS.mask);
check('MASK 与 BLOCK 取 BLOCK', higherLevel(LEVELS.mask, LEVELS.block), LEVELS.block);
check('BLOCK 与 MASK 保持 BLOCK', higherLevel(LEVELS.block, LEVELS.mask), LEVELS.block);
check('未知值降级为 PASS', higherLevel(LEVELS.pass, 'garbage'), LEVELS.pass);
check('next 为 undefined 保持原值', higherLevel(LEVELS.mask, undefined), LEVELS.mask);

const acc = new ResultAccumulator();
check('初始为 PASS', acc.level, LEVELS.pass);
check('初始未命中', acc.matched, false);
acc.add({ level: LEVELS.mask, counts: { '{{LAN_IP}}': 2 }, kinds: new Set(['网络地址']), hits: [{ ruleId: 'lan-ipv4' }] });
check('累加后为 MASK', acc.level, LEVELS.mask);
check('计数累加', acc.counts['{{LAN_IP}}'], 2);
acc.add({ level: LEVELS.mask, counts: { '{{LAN_IP}}': 3, '{{MAC_ADDR}}': 1 }, kinds: new Set(['MAC地址']), hits: [{ ruleId: 'mac-address' }] });
check('同类计数相加', acc.counts['{{LAN_IP}}'], 5);
check('异类计数并存', acc.counts['{{MAC_ADDR}}'], 1);
check('类型取并集', [...acc.kinds].sort(), ['MAC地址', '网络地址']);
check('命中明细累积', acc.hits.length, 2);
acc.add({ level: LEVELS.block, counts: {}, kinds: new Set(['api密钥']), hits: [] });
check('升级为 BLOCK', acc.level, LEVELS.block);
check('blocked 为真', acc.blocked, true);
check('空结果不报错', (acc.add(undefined), acc.level), LEVELS.block);
check('kindList 非空', acc.kindList().length > 0, true);

section('ResultAccumulator：changed 传播');
const acc2 = new ResultAccumulator();
acc2.add({ level: LEVELS.mask, changed: false, counts: {}, kinds: new Set(), hits: [] });
check('未改写时 changed 为假', acc2.changed, false);
acc2.add({ level: LEVELS.mask, changed: true, counts: {}, kinds: new Set(), hits: [] });
check('改写后 changed 为真', acc2.changed, true);

section('GuardLogger：通道与格式');
const lines = [];
const sink = { info: (line) => lines.push(line) };
const jsonLogger = new GuardLogger(resolveConfig({ logFormat: 'json', logToStderr: false }), sink);
jsonLogger.report({ level: LEVELS.block, counts: { '{{SECRET_TOKEN}}': 1 }, kinds: new Set(['api密钥']), hits: [{ ruleId: 'key-prefix', preview: 'sk-*** (19)' }] }, 'user_input', 'sk-abcdefghijklmnop');
check('写入了日志', lines.length, 1);
const parsed = JSON.parse(lines[0].replace('sensitive-guard ', ''));
check('JSON 含 level', parsed.level, 'BLOCK');
check('JSON 含 source', parsed.source, 'user_input');
check('JSON 含 hitText', parsed.hitText, 'sk-*** (19)');

const textLines = [];
const textLogger = new GuardLogger(resolveConfig({ logFormat: 'text', logToStderr: false }), { info: (l) => textLines.push(l) });
textLogger.report({ level: LEVELS.mask, counts: { '{{LAN_IP}}': 1 }, kinds: new Set(['网络地址']), hits: [] }, 'tool_result', '');
check('text 格式含 level', textLines[0].includes('level=MASK'), true);
check('text 格式含来源', textLines[0].includes('[tool_result]'), true);

section('GuardLogger：静默开关');
const silent = [];
const quiet = new GuardLogger(resolveConfig({ logMasks: false, logToStderr: false }), { info: (l) => silent.push(l) });
quiet.report({ level: LEVELS.block, counts: {}, kinds: new Set(), hits: [] }, 'user_input', '');
check('logMasks=false 不输出', silent.length, 0);

section('GuardLogger：告警分级');
const alerts = [];
const alertLogger = new GuardLogger(resolveConfig({ logToStderr: false }), { info: (l) => alerts.push(l) });
alertLogger.alert('测试告警', { level: LEVELS.block, kinds: new Set(['api密钥']) });
check('高风险标注出现', alerts[0].includes('【高风险命中】'), true);
const alerts2 = [];
const alertLogger2 = new GuardLogger(resolveConfig({ logToStderr: false }), { info: (l) => alerts2.push(l) });
alertLogger2.alert('测试告警', { level: LEVELS.mask, kinds: new Set(['验证码']) });
check('普通级无高风险标注', alerts2[0].includes('【高风险命中】'), false);

section('GuardLogger：异常安全');
const broken = new GuardLogger(resolveConfig({ logToStderr: false }), { info: () => { throw new Error('sink failed'); } });
let threw = false;
try { broken.line('test'); } catch { threw = true; }
check('sink 抛错不外泄', threw, false);

section('streak 阈值');
check('未达阈值不告警', shouldAlertStreak(5, 6), false);
check('达到阈值告警', shouldAlertStreak(6, 6), true);
check('超过阈值不重复告警', shouldAlertStreak(7, 6), false);

section('applyReplacements：图片替换');
const messages = [{ role: 'user', content: [
  { type: 'text', text: 'hi' },
  { type: 'image', attachment: { attachmentId: 'att-1', mediaType: 'image/png', bytes: 10, width: 2, height: 2 } },
] }];
const repl = new Map([['att-1', { attachmentId: 'att-2', mediaType: 'image/png', bytes: 8, width: 2, height: 2 }]]);
const applied = applyReplacements(messages, repl);
check('替换后 changed', applied.changed, true);
check('图片块已改写', applied.messages[0].content[1].attachment.attachmentId, 'att-2');
check('文本块未动', applied.messages[0].content[0].text, 'hi');
check('原消息未被修改', messages[0].content[1].attachment.attachmentId, 'att-1');
check('空替换集不改写', applyReplacements(messages, new Map()).changed, false);

const noImage = [{ role: 'user', content: [{ type: 'text', text: 'x' }] }];
check('无图片消息安全', applyReplacements(noImage, repl).changed, false);
const stringContent = [{ role: 'user', content: 'plain' }];
check('字符串内容安全', applyReplacements(stringContent, repl).changed, false);

console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILED`);
process.exitCode = failures === 0 ? 0 : 1;