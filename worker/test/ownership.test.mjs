import test from 'node:test';
import assert from 'node:assert/strict';
import {createOwnershipChecker,canRequestWebsite,originTestResult} from '../src/ownership.mjs';

test('foreign Host/SNI does not prove deployment; repeated host lookups are cached', async()=>{
  let calls=0;
  const check=createOwnershipChecker({resolve:async()=>{calls++;return {addresses:['198.51.100.1'],uncertain:false};}});
  const results=await Promise.all(Array.from({length:1000},()=>check({host:'unrelated.example',ip:'203.0.113.10',source:'tls_sni'})));
  assert.equal(calls,1);
  assert.ok(results.every(row=>row.ownership_status==='dns_mismatch'));
  assert.equal((await check({host:'unrelated.example',ip:'198.51.100.1'})).ownership_status,'dns_match');
});
test('IPv6 is normalized and DNS timeout remains unknown',async()=>{
  const check=createOwnershipChecker({resolve:async host=>host==='timeout.example'?Promise.reject(new Error('timeout')):{addresses:['2001:db8::1'],uncertain:false}});
  assert.equal((await check({host:'owned.example',ip:'2001:0db8:0000::1'})).ownership_status,'dns_match');
  assert.equal((await check({host:'timeout.example',ip:'203.0.113.10'})).ownership_status,'dns_unknown');
});
test('manual hidden origins and literal IPs need no DNS lookup',async()=>{
  const check=createOwnershipChecker({resolve:async()=>{throw new Error('must not resolve');}});
  assert.equal((await check({host:'hidden.example',ip:'203.0.113.10',source:'manual'})).ownership_status,'manual');
  assert.equal((await check({host:'[2001:db8::1]',ip:'2001:0db8::1'})).ownership_status,'ip_only');
  assert.equal((await check({host:'198.51.100.1',ip:'203.0.113.10'})).ownership_status,'dns_mismatch');
});

test('explicit origin test permits only a one-shot request and preserves DNS provenance', async()=>{
  const check=createOwnershipChecker({resolve:async()=>({addresses:['198.51.100.1'],uncertain:false})});
  const task={host:'hidden.example',ip:'203.0.113.10',source:'tls_sni'};
  const proof=await check(task);
  assert.equal(canRequestWebsite(task,proof),false);
  task.mode='origin_test';
  assert.equal(canRequestWebsite(task,proof),true);
  const result=originTestResult(task,proof);
  assert.equal(result.ownership_status,'origin_response');
  assert.deepEqual(result.ownership_evidence.addresses,['198.51.100.1']);
  assert.equal(result.ownership_evidence.origin_test.target_ip,task.ip);
  assert.equal(result.ownership_evidence.origin_test.dns_status,'dns_mismatch');
  assert.equal(proof.ownership_status,'dns_mismatch');
  assert.equal(proof.ownership_evidence.origin_test,undefined);
  assert.equal(originTestResult({...task,mode:'normal'},proof),proof);
});
