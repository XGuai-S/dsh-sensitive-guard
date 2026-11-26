// 图片附件处理回归测试 / Image attachment regression tests.
import { looksBinary } from '../ocr/detect.js';
import { applyReplacements } from '../image-pipeline.js';

let failures = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok ? '' : ` → got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};

console.log('== looksBinary：图片魔数优先于 NUL 启发式 ==');
const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d]);
const jpeg = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]);
const gif = new Uint8Array([0x47, 0x49, 0x46, 0x38, 0x39, 0x61]);
const webp = new Uint8Array([0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x45, 0x42, 0x50]);
const zip = new Uint8Array([0x50, 0x4b, 0x03, 0x04]);
check('PNG 不被误判为二进制', looksBinary(png, 'a.png'), false);
check('JPEG 不被误判为二进制', looksBinary(jpeg, 'a.jpg'), false);
check('GIF 不被误判为二进制', looksBinary(gif, 'a.gif'), false);
check('WebP 不被误判为二进制', looksBinary(webp, 'a.webp'), false);
check('ZIP 仍判为二进制', looksBinary(zip, 'a.zip'), true);
check('.exe 扩展名判为二进制', looksBinary(new Uint8Array([0x4d, 0x5a]), 'setup.exe'), true);

console.log('\n== applyReplacements：合并保留附件字段 ==');
const id = 'abc123';
const msg = {
  content: [{
    type: 'image',
    attachment: {
      attachmentId: id, mediaType: 'image/png', width: 1920, height: 1080,
      bytes: 252465, name: 'a.png', sha256: 'deadbeef',
    },
  }],
};
// saveImage 典型返回：只有 id/mediaType/name，缺 width/height/bytes
const replacements = new Map([[id, { attachmentId: 'NEW', mediaType: 'image/png', name: 'a.png' }]]);
const result = applyReplacements([msg], replacements);
const att = result.messages[0].content[0].attachment;
check('替换后 changed=true', result.changed, true);
check('使用新 attachmentId', att.attachmentId, 'NEW');
check('保留 width', att.width, 1920);
check('保留 height', att.height, 1080);
check('保留 bytes', att.bytes, 252465);
check('保留 sha256', att.sha256, 'deadbeef');

console.log('\n== 无 replacement 时图片块原样 ==');
const untouched = applyReplacements([msg], new Map());
check('无替换 changed=false', untouched.changed, false);
check('附件对象未变', untouched.messages[0].content[0].attachment, msg.content[0].attachment);

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
