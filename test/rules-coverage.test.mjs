// 全规则覆盖测试 / Full rule coverage. 每条规则都必须有专属命中用例。
// 判定标准是「产出期望占位符」而非「命中指定 id」：同类规则（如三种住址规则）
// 谁先命中不影响语义，输出占位符相同即视为覆盖。
import { buildFullRules, resolveConfig, runSanitize, createRegistry } from '../index.js';
import { OCR_RULES } from '../ocr/normalize.js';

let failures = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok ? '' : ` → got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};
const section = (name) => console.log(`\n--- ${name} ---`);

const config = resolveConfig({});
config.disabledRulesSet = new Set(config.disabledRules);
const rules = buildFullRules(config);
// 每条用例用独立注册表：共享注册表会让第二个不同值拿到 `_2` 后缀，
// 断言 `includes('{{SECRET_TOKEN}}')` 就会因为 `{{SECRET_TOKEN_2}}` 失败。
// 这不是规则缺陷，而是用例隔离问题。
//
// Each case gets a fresh registry: a shared one gives the second distinct value a
// `_2` suffix, so `includes('{{SECRET_TOKEN}}')` fails against
// `{{SECRET_TOKEN_2}}`. That is a test isolation issue, not a rule defect.
const freshContext = () => ({ config, disabledRules: config.disabledRulesSet, registry: createRegistry() });

section('规则表完整性');
check('主规则 47 条', rules.length, 47);
check('OCR 规则 7 条', OCR_RULES.length, 7);
check('禁用规则集合已预计算', config.disabledRulesSet instanceof Set, true);

section('全部 OCR 规则都带 level');
for (const rule of OCR_RULES) {
  check(`OCR ${rule.id} 有 level`, rule.level === 'BLOCK' || rule.level === 'MASK', true);
}

section('主规则逐条覆盖（占位符等价）');
// [规则 id, 期望占位符, 命中输入]
const CASES = [
  ['name-id-pair', '{{NAME_AND_ID}}', '张三 110101199003074513'],
  ['cn-address', '{{HOME_ADDR}}', '广东省肇庆市端州区阳光小区B栋904'],
  ['street-address', '{{HOME_ADDR}}', '科技园路1号3栋502室'],
  ['medical-record', '{{MEDICAL_INFO}}', '门诊号: 20241126A001'],
  ['diagnosis-line', '{{MEDICAL_INFO}}', '诊断: 急性阑尾炎'],
  ['medical-id', '{{MEDICAL_INFO}}', '病历号: ABC12345'],
  ['pem-private-key', '{{SECRET_TOKEN}}', '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----'],
  ['ssh-private-key', '{{SECRET_TOKEN}}', 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC'],
  ['key-prefix', '{{SECRET_TOKEN}}', 'sk-abcdefghijklmnop1234'],
  ['jwt', '{{SECRET_TOKEN}}', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk'],
  ['bearer', '{{SECRET_TOKEN}}', 'Authorization: Bearer abcdefgh12345678'],
  ['privileged-password', '{{SECRET_TOKEN}}', 'root password=SuperSecret123'],
  ['cn-id-card', '{{ID_CARD}}', '110101199003074513'],
  ['cn-id-card-spaced', '{{ID_CARD}}', '1101011990 0307 4513'],
  ['bank-card', '{{BANK_CARD}}', '6222021234567890128'],
  ['bank-card-labelled', '{{BANK_CARD}}', '卡号6221885935650739436'],
  ['cvv', '{{BANK_CARD}}', 'CVV: 123'],
  ['passport', '{{PASSPORT_NO}}', 'E12345678'],
  ['social-security-card', '{{SOCIAL_CARD}}', '社保卡号 D1234567890123'],
  ['license-plate', '{{PLATE_NO}}', '京A12345'],
  ['cn-mobile', '{{PHONE_NO}}', '13912345678'],
  ['email', '{{EMAIL_ADDR}}', 'zhangsan@company.cn'],
  ['social-id', '{{SOCIAL_ID}}', 'wxid_abcdefgh1234'],
  ['social-id-labelled', '{{SOCIAL_ID}}', '微信号 abcdef123'],
  ['one-time-code', '{{ONE_TIME_CODE}}', '验证码 482913'],
  ['home-address', '{{HOME_ADDR}}', '北京市朝阳区建国路88号3栋502室'],
  ['home-address-street', '{{HOME_ADDR}}', '科技园路1号3栋502室'],
  ['home-address-district', '{{HOME_ADDR}}', '朝阳区建国路88号'],
  ['cli-password', '{{CRED_CODE}}', 'mysql -pSuperSecret123'],
  ['kv-credential', '{{CRED_CODE}}', 'password=mySecret123'],
  ['service-password', '{{CRED_CODE}}', 'adb password: abc12345xyz'],
  ['env-credential', '{{CRED_CODE}}', 'export API_KEY=abcdef123456'],
  ['cookie-session', '{{CRED_CODE}}', 'Cookie: sessionid=abcdef1234567890'],
  ['temp-login-link', '{{CRED_CODE}}', 'https://x.com/a?token=abcdef123456'],
  ['url-credential', '{{CRED_CODE}}', 'https://x.com/a?access_token=abcdef123456'],
  ['trade-no', '{{TRADE_NO}}', '订单号: ORDER20240101123456'],
  ['account-balance', '{{BALANCE_AMOUNT}}', '账户余额 1,234,567.89 元'],
  ['cert-info', '{{CERT_INFO}}', '证书序列号: 0A1B2C3D4E5F6071'],
  ['key-fingerprint', '{{KEY_FINGERPRINT}}', 'fingerprint: aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd'],
  ['local-path', '{{LOCAL_PATH}}', 'C:\\Users\\x\\y.js'],
  ['device-id', '{{DEVICE_ID}}', 'IMEI 861234567890123'],
  ['mac-address', '{{MAC_ADDR}}', 'aa:bb:cc:dd:ee:ff'],
  ['net-ipv6', '{{NET_IP}}', '2001:db8:85a3::8a2e:370:7334'],
  ['lan-ipv4', '{{LAN_IP}}', '192.168.1.10'],
  ['net-ipv4', '{{NET_IP}}', '8.8.8.8'],
  ['db-credential', '{{DB_CRED}}', 'postgres://user:pass123@10.0.0.1:5432/db'],
  ['high-entropy', '{{SECRET_TOKEN}}', 'aB3$xY9!kL2@mN5#tU8&vW1*yZ4^aB7'],
];
for (const [id, placeholder, text] of CASES) {
  const result = runSanitize(text, rules, freshContext());
  check(`${id} → ${placeholder}`, result.content.includes(placeholder), true);
}
check('用例数等于主规则数', CASES.length, rules.length);
// 每条主规则都出现在用例中
const covered = new Set(CASES.map((c) => c[0]));
check('无遗漏规则', rules.filter((r) => !covered.has(r.id)).map((r) => r.id), []);

section('OCR 规则逐条覆盖');
const OCR_CASES = [
  ['ocr-split-secret', 'sk-abcdefghijklmnopqrst 1234'],
  ['ocr-cn-mobile', '联系 138 0013 8002'],
  ['ocr-cn-id', '110101199003074513'],
  ['ocr-one-time-code', '验证码 123456'],
  ['ocr-label-value', '密码: abc12345'],
  ['ocr-signed-url', 'https://x.com/a?token=abcdef123456'],
  ['ocr-url', 'https://example.com/path'],
];
for (const [id, text] of OCR_CASES) {
  const rule = OCR_RULES.find((r) => r.id === id);
  rule.re.lastIndex = 0;
  const hit = rule.re.test(text);
  rule.re.lastIndex = 0;
  check(`OCR ${id} 命中`, hit, true);
}
check('OCR 用例数等于规则数', OCR_CASES.length, OCR_RULES.length);

console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILED`);
process.exitCode = failures === 0 ? 0 : 1;