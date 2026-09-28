import {test} from 'node:test';
import assert from 'node:assert/strict';
import {publicIP,target,permittedURL} from '../src/security.mjs';
import {classify} from '../src/classify.mjs';
test('reject loopback, metadata, local, mapped and transition targets',()=>{
  for(const ip of ['127.0.0.1','10.0.0.1','169.254.169.254','::1','fc00::1','fe80::1','::ffff:127.0.0.1','2001:db8::1','224.0.0.1','100.64.0.1'])assert.equal(publicIP(ip),false,ip);
  assert.equal(publicIP('1.1.1.1'),true);assert.equal(publicIP('2606:4700:4700::1111'),true);
});
test('pin exact origin; reject credentials and redirects to other hosts/ports',()=>{
  const t=target({ip:'1.1.1.1',host:'example.com',port:8443,scheme:'https'});
  assert.equal(t.url,'https://example.com:8443/');
  assert.equal(permittedURL('https://example.com:8443/style.css',t),true);
  for(const u of ['https://example.com/','http://example.com:8443/','https://example.com.evil.test:8443/','https://user@example.com:8443/','file:///etc/passwd'])assert.equal(permittedURL(u,t),false);
  assert.throws(()=>target({ip:'127.0.0.1',host:'example.com',port:80,scheme:'http'}));
});
test('IPv6 origin and explainable low confidence classification',()=>{
  assert.equal(target({ip:'2606:4700:4700::1111',host:'',port:443,scheme:'https'}).url,'https://[2606:4700:4700::1111]/');
  const c=classify('后台','管理员登录');assert.equal(c.category,'管理后台');assert.ok(c.classification.confidence<1);assert.equal(classify('hello','world').category,'未分类');
});
test('review hints retain uncertainty and do not flag ordinary pages',()=>{
  const flagged=classify('体育投注', '欢迎访问在线博彩平台');
  assert.equal(flagged.category, '疑似博彩');
  assert.equal(flagged.classification.review_required, true);
  assert.ok(flagged.classification.confidence < 0.8);
  assert.equal(classify('企业介绍', '联系我们').classification.review_required, false);
  assert.equal(classify('新闻', '普通资讯').classification.review_required, false);
  assert.equal(classify('企业介绍', '网站描述：在线博彩平台').category, '疑似博彩');
});
test('payment and loan pages are review hints, not illegality findings',()=>{
  const payment=classify('收款服务', '网站描述：提供在线支付服务和支付网关');
  assert.equal(payment.category, '支付平台线索');
  assert.equal(payment.classification.review_required, true);
  const loan=classify('借款申请', '网站描述：在线贷款平台');
  assert.equal(loan.category, '贷款平台线索');
  assert.equal(loan.classification.review_required, true);
  assert.equal(classify('财经新闻', '关于支付和贷款的政策报道').classification.review_required, false);
});
