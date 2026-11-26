// 软件开发项目常见内容不得被误判为密钥/隐私。
import { buildFullRules, resolveConfig, createRegistry, runSanitize } from '../index.js';
let failures = 0;
const check = (label, actual, expected) => {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label} → ${actual}`);
};
const config = resolveConfig({});
config.disabledRulesSet = new Set(config.disabledRules);
const rules = buildFullRules(config);
const ctx = () => ({ config, disabledRules: config.disabledRulesSet, registry: createRegistry() });
const level = (s) => runSanitize(s, rules, ctx()).level;

console.log('== 代码标识符 ==');
check('长函数名', level('function myFunction12345678901234567890() { return 1; }'), 'PASS');
check('长类名', level('class MyVeryLongClassName12345678901234567890 {}'), 'PASS');
check('camelCase 方法', level('getShoppingCartItemTotalPriceWithDiscountAmount()'), 'PASS');
check('方法调用', level('someObject.someVeryLongMethodName12345678901234567890(arg);'), 'PASS');
check('snake_case 常量', level('const MAX_CONNECTION_RETRY_ATTEMPTS_DEFAULT_VALUE = 5;'), 'PASS');

console.log('\n== 项目数据 ==');
check('长 JSON 字段', level('"userAuthenticationTokenExpirationTimeInSeconds": 3600'), 'PASS');
check('环境变量', level('NODE_ENV=production'), 'PASS');
check('git hash', level('git commit 3f4ffe8b869455f657c3b8435cb14def7c874ad5'), 'PASS');
check('sha256', level('sha256: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2'), 'PASS');
check('UUID', level('550e8400-e29b-41d4-a716-446655440000'), 'PASS');
check('版本号', level('version: 1.2.3-beta.4+build.5678'), 'PASS');
check('base64 图片', level('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=='), 'PASS');
check('SQL', level('SELECT user_id, user_name FROM users WHERE active = 1'), 'PASS');
check('注释', level('// This is a very long comment explaining the function behavior here'), 'PASS');

console.log('\n== 真密钥仍被拦 ==');
check('sk- 前缀', level('sk-proj-abcdefghijklmnopqrstuvwxyz123456'), 'BLOCK');
check('ghp_ 前缀', level('ghp_abcdefghijklmnopqrstuvwxyz1234567890'), 'BLOCK');
check('随机高熵串', level('aB3xY9kL2mN5tU8vW1yZ4aB7cD6'), 'BLOCK');

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
