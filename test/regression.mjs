// 回归测试 / Regression suite. 运行：npm test
import {
  buildFullRules, resolveConfig, maskText, maskContent, maskValue, createRegistry,
  auditRequest, maskResponseStream, isHighEntropy, isExcluded, luhn,
  DEFAULT_WHITELIST, PLACEHOLDERS,
} from '../index.js';
import { detectContainer, looksBinary, decodeQr } from '../ocr/detect.js';
import { normalizeOcrText, assessOcrLine, OCR_RULES } from '../ocr/normalize.js';
import { mergeBoxes, padBox } from '../ocr/redact.js';
import { selectBackend } from '../ocr/backend.js';

let failures = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok ? '' : ` → got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};
const section = (name) => console.log(`\n--- ${name} ---`);

const config = resolveConfig({});
const RULES = buildFullRules(config);
const ctxOf = (overrides = {}) => ({ config, registry: createRegistry(), ...overrides });
const mask = (t, cfg) => {
  const c = cfg ? resolveConfig(cfg) : config;
  return maskText(t, cfg ? buildFullRules(c) : RULES, { config: c, registry: createRegistry() });
};

section('模式与配置');
check('默认脱敏放行', config.mode, 'mask');
check('可切严格阻断', resolveConfig({ mode: 'block' }).mode, 'block');
check('响应侧默认开启', config.maskResponses, true);
check('高熵默认开启', config.detectHighEntropy, true);
check('双向扫描：请求侧', config.auditRequests, true);
check('双向扫描：响应侧', config.maskResponses, true);

section('明文密钥');
check('sk-', mask('sk-abcdefghijklmnop1234').text, '{{SECRET_TOKEN}}');
check('sk-proj-', mask('sk-proj-abcdefghijklmnop').text, '{{SECRET_TOKEN}}');
check('sk-ant-', mask('sk-ant-abcdefghijklmnop').text, '{{SECRET_TOKEN}}');
check('ghp_', mask('ghp_abcdefghijklmnopqrst').text, '{{SECRET_TOKEN}}');
check('github_pat_', mask('github_pat_abcdefghijklmnop').text, '{{SECRET_TOKEN}}');
check('glpat-', mask('glpat-abcdefghijklmnop').text, '{{SECRET_TOKEN}}');
check('AKIA', mask('AKIAIOSFODNN7EXAMPLE').text, '{{SECRET_TOKEN}}');
check('AIza', mask('AIzaSyD-abcdefghijklmnopqrstuvwxyz').text, '{{SECRET_TOKEN}}');
check('hf_', mask('hf_abcdefghijklmnopqrst').text, '{{SECRET_TOKEN}}');
check('私钥块', mask('-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----').text, '{{SECRET_TOKEN}}');
check('JWT', mask('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk').text, '{{SECRET_TOKEN}}');
check('Bearer 保留前缀', mask('Bearer abcdefgh12345678').text, 'Bearer {{SECRET_TOKEN}}');

section('KV 凭证细则');
check('password=', mask('password=mySecret123').text, 'password={{CRED_CODE}}');
check('pwd:', mask('pwd: hunter2').text, 'pwd: {{CRED_CODE}}');
check('secret=', mask('secret="abcdef123456"').text, 'secret="{{CRED_CODE}}"');
check('apikey=', mask('apikey=abcdef123456').text, 'apikey={{CRED_CODE}}');
check('access_key=', mask('access_key=abcdef123456').text, 'access_key={{CRED_CODE}}');
check('密码=', mask('密码=abc12345').text, '密码={{CRED_CODE}}');
check('账号=', mask('账号=zhangsan').text, '账号={{CRED_CODE}}');
check('storePassword', mask('storePassword=abcdef12').text, 'storePassword={{CRED_CODE}}');
check('keyPassword', mask('keyPassword=abcdef12').text, 'keyPassword={{CRED_CODE}}');

section('高熵兜底');
check('高熵判定', isHighEntropy('aB3$xY9!kL2@mN5#pQ8&rS1tU4vW7'), true);
check('短串不高熵', isHighEntropy('abc123'), false);
check('长英文单词不高熵', isHighEntropy('internationalization'), false);
check('高熵被脱敏', mask('token aB3xY9kL2mN5pQ8rS1tU4vW7').text.includes('{{'), true);

section('排除规则');
check('端口排除', isExcluded('8080'), true);
check('端口边界', isExcluded('65535'), true);
check('版本号排除', isExcluded('1.2.3'), true);
check('v 版本号排除', isExcluded('v2.0.0-beta.1'), true);
check('md5 排除', isExcluded('d41d8cd98f00b204e9800998ecf8427e'), true);
check('sha1 排除', isExcluded('da39a3ee5e6b4b0d3255bfef95601890afd80709'), true);
check('sha256 排除', isExcluded('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'), true);
check('普通串不排除', isExcluded('myPassword123'), false);
check('端口不被当密钥', mask('listen on 8080').text, 'listen on 8080');
check('哈希不被当密钥', mask('md5 d41d8cd98f00b204e9800998ecf8427e').text.includes('{{'), false);

section('身份隐私');
check('身份证', mask('110101199003074512').risk, 'high');
check('手机', mask('13800138000').text, '{{PRIVACY_ID}}');
check('银行卡 Luhn', mask('4111111111111111').text, '{{PRIVACY_ID}}');
check('伪卡不脱敏', mask('4111111111111112').text, '4111111111111112');
check('住址', mask('广东省深圳市南山区科技园路1号').risk, 'high');
check('病历', mask('门诊号：A12345678').risk, 'high');
check('姓名+证件', mask('张三 110101199003074512').text, '{{PRIVACY_ID}}');
check('单独姓名保留', mask('张三今天来了').text, '张三今天来了');

section('验证码');
check('中文验证码', mask('验证码：123456').text, '验证码：{{ONE_TIME_CODE}}');
check('otp', mask('otp 654321').text.includes('{{ONE_TIME_CODE}}'), true);
check('verify code', mask('verify code: 4321').text.includes('{{ONE_TIME_CODE}}'), true);
check('7 位不匹配', mask('验证码：1234567').text.includes('{{ONE_TIME_CODE}}'), false);

section('系统凭证与路径');
check('adb 密码', mask('adb password: hunter2xyz').text, 'adb password: {{CRED_CODE}}');
check('wifi 密码', mask('wifi密码=abc12345').text.includes('{{CRED_CODE}}'), true);
check('DB 连接串', mask('postgres://u:p@db.local/x').text, '{{DB_CRED}}');
check('Windows 路径', mask('C:\\Users\\x\\y.js').text, '{{LOCAL_PATH}}');
check('Android 路径', mask('/storage/emulated/0/a.jpg').text, '{{LOCAL_PATH}}');
check('Linux root', mask('/root/.ssh/id_rsa').text, '{{LOCAL_PATH}}');
check('邮箱', mask('a@b.com').text, '{{EMAIL_ADDR}}');
check('内网 IP', mask('192.168.1.10').text, '{{NET_IP}}');
check('回环保留', mask('127.0.0.1').text, '127.0.0.1');

section('白名单');
check('test-key', mask('apikey=test-key').text.includes('{{'), false);
check('demo-sk', mask('demo-sk').text, 'demo-sk');
check('placeholder', mask('placeholder').text, 'placeholder');
check('md5 在白名单', DEFAULT_WHITELIST.includes('md5'), true);
check('sha256 在白名单', DEFAULT_WHITELIST.includes('sha256'), true);

section('会话临时白名单');
const reg = createRegistry();
const wl = new Set(['mySpecialValue123']);
const withWl = maskText('password=mySpecialValue123', RULES, { config, registry: reg, sessionWhitelist: wl });
check('临时白名单跳过', withWl.text, 'password=mySpecialValue123');
const withoutWl = maskText('password=mySpecialValue123', RULES, { config, registry: createRegistry() });
check('非白名单仍脱敏', withoutWl.text.includes('{{'), true);

section('占位符稳定性');
const r2 = createRegistry();
const a = maskText('sk-aaaaaaaaaaaaaaaa1111', RULES, { config, registry: r2 });
const b = maskText('sk-aaaaaaaaaaaaaaaa1111', RULES, { config, registry: r2 });
const c = maskText('sk-bbbbbbbbbbbbbbbb2222', RULES, { config, registry: r2 });
check('同值同占位符', a.text, b.text);
check('异值异占位符', a.text !== c.text, true);
check('不产生 _2 变体', /_\d+\}\}/.test(mask('门诊号：A12345678').text), false);

section('结构化适配');
const json = JSON.stringify({ user: 'zhangsan', password: 'mySecret123', nested: { token: 'abcdef123456' } });
const jsonMasked = maskText(json, RULES, ctxOf());
check('JSON 仍合法', (() => { try { JSON.parse(jsonMasked.text); return true; } catch { return false; } })(), true);
check('JSON 保留键名', jsonMasked.text.includes('"password"'), true);
check('JSON 替换值', jsonMasked.text.includes('"password":"{{'), true);

const yaml = 'db:\n  password: mySecret123\n  host: 192.168.1.5\n';
const yamlMasked = maskText(yaml, RULES, ctxOf());
check('YAML 保留键', yamlMasked.text.includes('password:'), true);
check('YAML 替换值', yamlMasked.text.includes('{{CRED_CODE}}'), true);

const gradle = 'storePassword=abcdef123456\nkeyPassword=xyz789ghi';
const gradleMasked = maskText(gradle, RULES, ctxOf());
check('gradle 保留键', gradleMasked.text.includes('storePassword='), true);
check('gradle 替换值', gradleMasked.text.includes('{{CRED_CODE}}'), true);

const props = 'api.key=abcdef123456';
check('properties 替换值', maskText(props, RULES, ctxOf()).text.includes('{{'), true);

const arr = ['sk-abcdefghijklmnop1234', 'plain', '13800138000'];
const arrMasked = maskValue(arr, RULES, ctxOf());
check('数组长度不变', arrMasked.value.length, 3);
check('数组逐项替换', arrMasked.value[0], '{{SECRET_TOKEN}}');
check('数组普通项保留', arrMasked.value[1], 'plain');

section('代码结构保留');
check('代码结构', mask('if (a) {\n  return b;\n}').text, 'if (a) {\n  return b;\n}');
check('注释保留', mask('// 这是注释\nconst x = 1;').text, '// 这是注释\nconst x = 1;');

section('响应侧脱敏');
async function* fakeStream() {
  yield { type: 'block-start', index: 0, blockType: 'text' };
  yield { type: 'text-delta', index: 0, text: 'my key is sk-abcdefghijklmnop1234' };
  yield { type: 'block-end', index: 0, block: { type: 'text', text: 'my key is sk-abcdefghijklmnop1234' } };
  yield { type: 'finish', reason: { kind: 'stop' } };
}
const collected = [];
let responseHits = 0;
for await (const chunk of maskResponseStream(fakeStream(), RULES, ctxOf(), () => { responseHits += 1; })) {
  collected.push(chunk);
}
const endBlock = collected.find((c) => c.type === 'block-end');
check('响应块被脱敏', endBlock.block.text, 'my key is {{SECRET_TOKEN}}');
check('命中回调触发', responseHits, 1);
check('finish 透传', collected.some((c) => c.type === 'finish'), true);
check('delta 不改写', collected.find((c) => c.type === 'text-delta').text.includes('sk-'), true);

section('审计只读');
const req = { provider: 'p', model: 'm', messages: [{ role: 'user', content: [{ type: 'text', text: 'sk-abcdefghijklmnop1234' }] }] };
const before = JSON.stringify(req);
const verdict = auditRequest(req, RULES, ctxOf());
check('审计检出', verdict.risk, 'high');
check('审计不改写', JSON.stringify(req), before);
check('审计统计图片', verdict.images, 0);

section('URL 分级');
const m2 = (cfg, t) => { const c = resolveConfig(cfg); return maskText(t, buildFullRules(c), { config: c, registry: createRegistry() }).text; };
check('默认不动', m2({}, 'github.com'), 'github.com');
check('internal 脱内网', m2({ maskUrls: 'internal' }, 'git.corp.internal').includes('{{PRIVATE_URL}}'), true);
check('internal 放公网', m2({ maskUrls: 'internal' }, 'github.com'), 'github.com');
check('all 脱公网', m2({ maskUrls: 'all' }, 'github.com').includes('{{PRIVATE_URL}}'), true);

section('二进制与二维码');
check('zip', detectContainer(new Uint8Array([0x50, 0x4b, 0x03, 0x04])), 'zip');
check('7z', detectContainer(new Uint8Array([0x37, 0x7a, 0xbc, 0xaf])), '7z');
check('文本非二进制', looksBinary(new Uint8Array([0x41, 0x42])), false);
check('NUL 为二进制', looksBinary(new Uint8Array([0x41, 0x00])), true);
check('压缩包扩展名', looksBinary(new Uint8Array([0x41]), 'a.zip'), true);
check('decodeQr 可调用', typeof decodeQr, 'function');
check('空图无码', (await decodeQr(new Uint8Array(16 * 16 * 4).fill(255), 16, 16)).length, 0);

section('OCR 归一化');
check('CJK 空格合并', normalizeOcrText('联 系 电 话'), '联系电话');
check('ASCII 空格保留', normalizeOcrText('hello world'), 'hello world');
check('可信行', assessOcrLine('token: abc').reliable, true);
check('符号串不可信', assessOcrLine('||| ###').reliable, false);
const ocrMask = (t) => maskText(t, OCR_RULES, ctxOf());
check('OCR 拆断密钥', ocrMask('sk-abcdefghijklmnopl 234').text, '{{SECRET_TOKEN}}');
check('OCR 分隔手机', ocrMask('138 0013 8000').text, '{{PRIVACY_ID}}');
check('OCR 验证码', ocrMask('验证码 123456').text.includes('{{ONE_TIME_CODE}}'), true);
check('OCR 签名 URL', ocrMask('https://x/?token=abc123').text, 'https://x/?token={{CRED_CODE}}');

section('涂改框');
check('合并重叠', mergeBoxes([{ x: 0, y: 0, w: 10, h: 10 }, { x: 5, y: 0, w: 10, h: 10 }]).length, 1);
check('分离保留', mergeBoxes([{ x: 0, y: 0, w: 10, h: 10 }, { x: 100, y: 100, w: 10, h: 10 }]).length, 2);
check('外扩钳制', padBox({ x: 0, y: 0, w: 5, h: 5 }, 10, 10).x, 0);

section('后端');
const auto = await selectBackend({});
check('自动选后端', auto.backend !== null, true);
console.log('  auto ->', auto.name, 'ocr:', auto.ocr);
check('none 关闭', (await selectBackend({ backend: 'none' })).backend, null);
check('python 可选', (await selectBackend({ backend: 'python' })).name, 'python');

console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILED`);
process.exitCode = failures === 0 ? 0 : 1;


