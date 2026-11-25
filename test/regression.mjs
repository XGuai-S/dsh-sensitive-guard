// Full regression, run before every release.
import { buildRules, resolveConfig, maskText, createRegistry, auditRequest } from '../index.js';
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

const config = resolveConfig({});
const RULES = buildRules(config);
const mask = (t) => maskText(t, RULES, { config, registry: createRegistry() });

console.log('--- secrets ---');
check('sk key', mask('sk-abcdefghijklmnop1234').text, '{{SECRET_TOKEN}}');
check('private key', mask('-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----').text, '{{SECRET_TOKEN}}');
check('bearer keeps prefix', mask('Bearer abcdefgh12345678').text, 'Bearer {{SECRET_TOKEN}}');
check('token assignment', mask('apiKey: "abcdef123456"').text, 'apiKey: "{{SECRET_TOKEN}}"');
check('ghp token', mask('ghp_abcdefghijklmnopqrst').text, '{{SECRET_TOKEN}}');
check('jwt', mask('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk').text, '{{SECRET_TOKEN}}');

console.log('--- privacy ---');
check('cn id', mask('110101199003074512').risk, 'high');
check('mobile', mask('13800138000').text, '{{PRIVACY_ID}}');
check('bank card luhn', mask('4111111111111111').text, '{{PRIVACY_ID}}');
check('bad card kept', mask('4111111111111112').text, '4111111111111112');
check('address', mask('广东省深圳市南山区科技园路1号').risk, 'high');
check('medical', mask('门诊号：A12345678').risk, 'high');
check('name+id', mask('张三 110101199003074512').text, '{{PRIVACY_ID}}');
check('lone name kept', mask('张三今天来了').text, '张三今天来了');

console.log('--- credentials / paths / net ---');
check('service password', mask('adb password: hunter2xyz').text, 'adb password: {{CRED_CODE}}');
check('db url', mask('postgres://u:p@db.local/x').text, '{{DB_CRED}}');
check('windows path', mask('C:\\Users\\x\\y.js').text, '{{LOCAL_PATH}}');
check('android path', mask('/storage/emulated/0/a.jpg').text, '{{LOCAL_PATH}}');
check('email', mask('a@b.com').text, '{{EMAIL_ADDR}}');
check('ip', mask('192.168.1.10').text, '{{NET_IP}}');
check('loopback kept', mask('127.0.0.1').text, '127.0.0.1');

console.log('--- whitelist / stability / structure ---');
check('whitelist', mask('apiKey: test-key').text, 'apiKey: test-key');
const reg = createRegistry();
const a = maskText('sk-aaaaaaaaaaaaaaaa1111', RULES, { config, registry: reg });
const b = maskText('sk-aaaaaaaaaaaaaaaa1111', RULES, { config, registry: reg });
check('stable placeholder', a.text, b.text);
check('structure intact', mask('if (a) {\n  return b;\n}').text, 'if (a) {\n  return b;\n}');
check('no double placeholder', /_\d+\}\}/.test(mask('门诊号：A12345678').text), false);

console.log('--- url levels ---');
const m2 = (cfg, t) => { const c = resolveConfig(cfg); return maskText(t, buildRules(c), { config: c, registry: createRegistry() }).text; };
check('off by default', m2({}, 'github.com'), 'github.com');
check('internal masks corp', m2({ maskUrls: 'internal' }, 'git.corp.internal').includes('{{PRIVATE_URL}}'), true);
check('internal keeps public', m2({ maskUrls: 'internal' }, 'github.com'), 'github.com');
check('all masks public', m2({ maskUrls: 'all' }, 'github.com').includes('{{PRIVATE_URL}}'), true);
check('custom suffix', m2({ maskUrls: 'internal', privateUrlSuffixes: ['acme'] }, 'x.acme').includes('{{PRIVATE_URL}}'), true);

console.log('--- binary / qr ---');
check('zip', detectContainer(new Uint8Array([0x50,0x4b,0x03,0x04])), 'zip');
check('rar', detectContainer(new Uint8Array([0x52,0x61,0x72,0x21])), 'rar');
check('text not binary', looksBinary(new Uint8Array([0x41,0x42])), false);
check('nul is binary', looksBinary(new Uint8Array([0x41,0x00])), true);
check('archive ext', looksBinary(new Uint8Array([0x41]), 'a.zip'), true);
check('decodeQr callable', typeof decodeQr, 'function');
check('blank qr empty', (await decodeQr(new Uint8Array(16*16*4).fill(255), 16, 16)).length, 0);

console.log('--- ocr normalize ---');
check('cjk collapse', normalizeOcrText('联 系 电 话'), '联系电话');
check('ascii gap kept', normalizeOcrText('hello world'), 'hello world');
check('reliable line', assessOcrLine('token: abc').reliable, true);
check('symbol soup', assessOcrLine('||| ###').reliable, false);
const ocrMask = (t) => maskText(t, OCR_RULES, { config, registry: createRegistry() });
check('ocr split secret', ocrMask('sk-abcdefghijklmnopl 234').text, '{{SECRET_TOKEN}}');
check('ocr spaced phone', ocrMask('138 0013 8000').text, '{{PRIVACY_ID}}');
check('ocr signed url', ocrMask('https://x/?token=abc123').text, 'https://x/?token={{CRED_CODE}}');

console.log('--- boxes ---');
check('merge overlapping', mergeBoxes([{x:0,y:0,w:10,h:10},{x:5,y:0,w:10,h:10}]).length, 1);
check('keep separate', mergeBoxes([{x:0,y:0,w:10,h:10},{x:100,y:100,w:10,h:10}]).length, 2);
check('pad clamps', padBox({x:0,y:0,w:5,h:5}, 10, 10).x, 0);

console.log('--- audit read-only ---');
const req = { provider:'p', model:'m', messages:[{role:'user',content:[{type:'text',text:'sk-abcdefghijklmnop1234'}]}] };
const before = JSON.stringify(req);
check('audit detects', auditRequest(req, RULES, { config, registry: createRegistry() }).risk, 'high');
check('audit read-only', JSON.stringify(req), before);

console.log('--- backends ---');
const auto = await selectBackend({});
check('auto picks backend', auto.backend !== null, true);
console.log('  auto ->', auto.name, 'ocr:', auto.ocr);
check('none disables', (await selectBackend({ backend: 'none' })).backend, null);
check('python selects', (await selectBackend({ backend: 'python' })).name, 'python');
check('backend default', config.imageBackend, 'auto');

console.log(failures === 0 ? `\nALL PASS (${failures} failures)` : `\n${failures} FAILED`);
process.exitCode = failures === 0 ? 0 : 1;


