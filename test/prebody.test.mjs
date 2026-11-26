// RPC 前置拦截测试 / Pre-inbox RPC interception tests.
import {
  isPromptEndpoint, sanitizeArgs, interceptPayload,
  buildFullRules, resolveConfig, createRegistry,
} from '../index.js';

let failures = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok ? '' : ` → got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};
const section = (name) => console.log(`\n--- ${name} ---`);

const config = resolveConfig({});
const RULES = buildFullRules(config);
const contextFor = () => ({ config, registry: createRegistry() });
const noop = () => {};

section('端点识别');
check('session/prompt', isPromptEndpoint('session/prompt'), true);
check('session/steer', isPromptEndpoint('session/steer'), true);
check('agent/followup', isPromptEndpoint('agent/followup'), true);
check('sessions/submit', isPromptEndpoint('sessions/submit'), true);
check('session/fork 不匹配', isPromptEndpoint('session/fork'), false);
check('session/list 不匹配', isPromptEndpoint('session/list'), false);
check('其他命名空间不匹配', isPromptEndpoint('workspace/prompt'), false);
check('空字符串', isPromptEndpoint(''), false);
check('非字符串', isPromptEndpoint(null), false);

section('payload 脱敏');
const payload = {
  sessionId: 'session-abc',
  requestId: 'req-1',
  mode: 'queue',
  content: [
    { type: 'text', text: '我的电话是 13800138002' },
  ],
};
const result = sanitizeArgs(payload, RULES, contextFor());
check('内容被替换', result.value.content[0].text.includes('{{PHONE_NO}}'), true);
check('sessionId 保留', result.value.sessionId, 'session-abc');
check('requestId 保留', result.value.requestId, 'req-1');
check('mode 保留', result.value.mode, 'queue');
check('changed 为真', result.changed, true);
check('level 为 BLOCK', result.level, 'BLOCK');

const cleanPayload = { sessionId: 's1', content: [{ type: 'text', text: '普通代码 const x = 1;' }] };
const cleanResult = sanitizeArgs(cleanPayload, RULES, contextFor());
check('无敏感不改变', cleanResult.changed, false);
check('无敏感 level', cleanResult.level, 'PASS');

section('路径与 IP 脱敏');
const pathPayload = { content: [{ type: 'text', text: '打开 C:\\Users\\test\\a.js' }] };
const pathResult = sanitizeArgs(pathPayload, RULES, contextFor());
check('本地路径不再脱敏（local-path 已移除）', pathResult.value.content[0].text.includes('{{LOCAL_PATH}}'), false);

// 图片附件元数据（含绝对路径的文件名）必须原样保留，否则图片发送失败。
const imagePayload = {
  content: [{
    type: 'image',
    attachment: {
      attachmentId: 'ad375b3a-855c-9f11-b2ab-be965ecc9a77',
      mediaType: 'image/png',
      name: 'C:\\Users\\test\\Pictures\\屏幕截图(1).png',
      sha256: 'ad375b3a855c9f11b2abbbe965ecc9a772b5acf7d038f7e294d1ab9fcfec9077',
    },
  }],
};
const imageResult = sanitizeArgs(imagePayload, RULES, contextFor());
check('图片附件不被改写', imageResult.changed, false);
check('附件文件名保留原路径', imageResult.value.content[0].attachment.name, imagePayload.content[0].attachment.name);

const ipPayload = { content: [{ type: 'text', text: 'host 192.168.1.5 up' }] };
const ipResult = sanitizeArgs(ipPayload, RULES, contextFor());
check('内网 IP 替换', ipResult.value.content[0].text.includes('{{LAN_IP}}'), true);

section('interceptPayload 返回值');
const outcome = interceptPayload('session/prompt', { ...payload }, RULES, contextFor, noop);
check('handled 为真', outcome.handled, true);
check('返回新 payload', outcome.payload.content[0].text.includes('{{PHONE_NO}}'), true);

const passOutcome = interceptPayload('session/prompt', { content: [{ type: 'text', text: 'hello' }] }, RULES, contextFor, noop);
check('无敏感 handled 为假', passOutcome.handled, false);

const skipOutcome = interceptPayload('session/fork', { sessionId: 's1' }, RULES, contextFor, noop);
check('非 prompt 端点跳过', skipOutcome.handled, false);

section('图片消息直通（保证附件可发送）');
const imagePrompt = {
  sessionId: 's1',
  args: {
    content: [
      { type: 'text', text: '密码 pass123 看这张图' },
      { type: 'image', attachment: { attachmentId: 'a1', mediaType: 'image/png', name: 'a.png' } },
    ],
  },
};
const imageOutcome = interceptPayload('session/followup', imagePrompt, RULES, contextFor, noop);
check('含图片 prompt 不改写', imageOutcome.handled, false);

section('异常兜底');
const brokenContext = () => { throw new Error('boom'); };
const errOutcome = interceptPayload('session/prompt', { ...payload }, RULES, brokenContext, noop);
check('异常时 handled 为假', errOutcome.handled, false);

section('诊断模式');
const logs = [];
interceptPayload('session/prompt', { content: [{ type: 'text', text: 'hello' }] }, RULES, contextFor, (line) => logs.push(line), { diagnose: true });
check('诊断有输出', logs.length > 0, true);
check('诊断含端点', logs.some((line) => line.includes('session/prompt')), true);

console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILED`);
process.exitCode = failures === 0 ? 0 : 1;
