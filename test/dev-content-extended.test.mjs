// 软件开发内容误判回归（扩展）：这些是正常代码/配置，不该被脱敏。
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
const ctx = { config, disabledRules: config.disabledRulesSet, registry: createRegistry() };
const scan = s => runSanitize(s, rules, ctx).level;

console.log('== 正常开发内容不误判 ==');
check('长 import 导出名', scan("import { someVeryLongNamedExport12345678901234 } from '@/utils';"), 'PASS');
check('泛型类型名', scan('const x: SomeVeryLongGenericTypeName12345678901234567890 = value;'), 'PASS');
check('接口名', scan('interface IUserAuthenticationTokenValidationResultService {}'), 'PASS');
check('包名', scan('"@myorg/very-long-scoped-package-name": "^1.2.3"'), 'PASS');
check('npm script', scan('"build:production:with:sourcemaps": "webpack"'), 'PASS');
check('docker 镜像', scan('FROM registry.example.com:5000/myorg/image:1.2.3'), 'PASS');
check('yaml 键', scan('database_connection_pool_maximum_size: 100'), 'PASS');
check('toml 键', scan('max_connection_retry_attempts_default_value = 5'), 'PASS');
check('ISO 时间戳日志行', scan('2026-11-26T12:34:56.789Z INFO  [MyApp] Request completed'), 'PASS');
check('堆栈帧', scan('at MyClass.methodName (/src/utils/helper.ts:123:45)'), 'PASS');
check('UUID', scan('550e8400-e29b-41d4-a716-446655440000'), 'PASS');
check('16进制颜色', scan('#FFAABBCCDDEEFF'), 'PASS');
check('长数字', scan('123456789012345678901234567890'), 'PASS');
check('git 分支', scan('feature/very-long-branch-name-for-user-authentication'), 'PASS');
check('版权行', scan('Copyright (c) 2026 MyVeryLongCompanyName12345678901234567890'), 'PASS');
check('正则字面量', scan('/^[A-Za-z0-9_-]{24,}$/'), 'PASS');
check('SQL 列名', scan('user_authentication_token_expiration_timestamp'), 'PASS');
check('GraphQL', scan('query GetVeryLongUserAuthenticationTokenValidationResult { user { id } }'), 'PASS');

console.log('\n== 真密钥仍被拦 ==');
check('JWT', scan('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature'), 'BLOCK');
check('邮箱', scan('user.name@example.com'), 'BLOCK');

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
