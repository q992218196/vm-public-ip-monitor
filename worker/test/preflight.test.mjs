import {test} from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {preflight,needsBrowser} from '../src/preflight.mjs';
import {renderGate} from '../src/render-gate.mjs';
import {probe} from '../src/probe.mjs';

test('3389 TLS and RDP automatic tasks are stopped before any network or browser',async()=>{
  for(const task of [{port:3389,source:'tls_sni'},{port:18443,source:'rdp_negotiation'}]){
    const result=await probe(task);assert.equal(result.status,'failed');assert.match(result.error,/不自动探测/);
  }
  await assert.rejects(probe({ip:'127.0.0.1',port:3389,source:'tls_sni',discovery_kind:'web_candidate',scheme:'https'}),/globally routable/);
});
test('lightweight check accepts HTTP errors and content type without browser',async()=>{
  const server=http.createServer((req,res)=>{assert.equal(req.headers.host,'fixture.example:8080');res.writeHead(403,{'Content-Type':'application/json'});res.end('{}');});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {
    const result=await preflight({ip:'127.0.0.1',port:server.address().port,scheme:'http',url:'http://fixture.example:8080/'});
    assert.equal(result.status,403);assert.equal(needsBrowser(result),false);
    for(const contentType of ['text/html; charset=utf-8','application/xhtml+xml',''])assert.equal(needsBrowser({contentType}),true);
    for(const contentType of ['application/json','image/png','application/octet-stream'])assert.equal(needsBrowser({contentType}),false);
  }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});
test('lightweight timeout is total elapsed time even when TCP stays open',async()=>{
  const server=http.createServer(()=>{});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {await assert.rejects(preflight({ip:'127.0.0.1',port:server.address().port,scheme:'http',url:'http://fixture.example/'},50),/timeout/);}
  finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});
test('browser permits enforce bounded concurrency and clean timed-out waiters',async()=>{
  const gate=renderGate(1,20);const first=await gate();await assert.rejects(gate(),/wait timeout/);
  first();first();const second=await gate();let acquired=false;const waiting=gate().then(release=>{acquired=true;return release;});
  await new Promise(resolve=>setImmediate(resolve));assert.equal(acquired,false);second();const third=await waiting;assert.equal(acquired,true);third();
});
