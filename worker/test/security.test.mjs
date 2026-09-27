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
