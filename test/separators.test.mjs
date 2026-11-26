// 数字串分隔符绕过测试：手机号/身份证换符号分隔仍须脱敏，短数字不误伤。
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
const scan = (s) => runSanitize(s, rules, ctx());

console.log('== 手机号：各符号分隔仍脱敏 ==');
check('连字符分隔', scan('1-3-8-0-0-1-3-8-0-0-0').level, 'BLOCK');
check('点分隔', scan('1.3.8.0.0.1.3.8.0.0.0').level, 'BLOCK');
check('下划线分隔', scan('1_3_8_0_0_1_3_8_0_0_0').level, 'BLOCK');
check('斜杠分隔', scan('1/3/8/0/0/1/3/8/0/0/0').level, 'BLOCK');
check('间隔号分隔', scan('1·3·8·0·0·1·3·8·0·0·0').level, 'BLOCK');
check('分组', scan('138-0013-8000').level, 'BLOCK');

console.log('\n== 身份证：分隔符仍脱敏 ==');
check('空格分组', scan('110101 19900307 4513').level, 'BLOCK');
check('连字符分组', scan('110101-19900307-4513').level, 'BLOCK');

console.log('\n== 不误伤短数字 ==');
check('版本号', scan('版本 1.2.3.4.5').level, 'PASS');
check('时间', scan('时间 12:30:45').level, 'PASS');
check('坐标', scan('坐标 39.9,116.4').level, 'PASS');
check('短编号', scan('编号 1 2 3').level, 'PASS');

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
