import {test} from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import {EventEmitter} from 'node:events';
import {chromium} from 'playwright';
import {preflight,needsBrowser} from '../src/preflight.mjs';
import {renderGate} from '../src/render-gate.mjs';
import {probe} from '../src/probe.mjs';

test('request-only, TLS and RDP automatic tasks are stopped before any network or browser',async()=>{
  for(const task of [
    {port:22,source:'http_host',discovery_kind:'web_candidate'},
    {port:80,source:'http_host',discovery_kind:'http_request'},
    {port:3389,source:'tls_sni'},
    {port:443,source:'tls_alpn',discovery_kind:'web_candidate'},
    {port:18443,source:'rdp_negotiation'},
    {port:22,source:'http_response',observed_http_status:0},
    {port:22,source:'http_response',observed_http_status:600},
    {port:22,source:'http_response',observed_http_status:'200'},
    {port:22,source:'http_response',observed_http_status:200,automatic_web_check_allowed:false}
  ]){
    const result=await probe(task);assert.equal(result.status,'failed');assert.match(result.error,/不自动探测/);
  }
});

test('confirmed HTTP responses keep nonstandard ports eligible without bypassing target safety',async()=>{
  for(const port of [22,8022,31337]){
    for(const observed_http_status of [200,403,500]){
      await assert.rejects(probe({ip:'127.0.0.1',port,scheme:'http',source:'http_response',observed_http_status}),/globally routable/);
    }
  }
});

test('trusted prior verification and explicit manual work retain admission but not SSRF bypasses',async()=>{
  for(const evidence of [
    {source:'http_host',automatic_web_check_allowed:true},
    {source:'tls_sni',automatic_web_check_allowed:true},
    {source:'http_host',request_source:'manual',automatic_web_check_allowed:false},
    {source:'http_host',mode:'origin_test',automatic_web_check_allowed:false},
    {source:'manual'}
  ]){
    await assert.rejects(probe({ip:'127.0.0.1',port:22,scheme:'http',...evidence}),/globally routable/);
  }
});

test('browser allows only the validated target port while retaining the pinned proxy',async t=>{
  t.mock.method(http,'request',(_options,callback)=>{
    const request=new EventEmitter();
    request.end=()=>queueMicrotask(()=>callback({statusCode:200,headers:{'content-type':'text/html'},destroy(){}}));
    request.destroy=error=>request.emit('error',error);
    return request;
  });
  const launches=[];
  const intercepted=new Error('browser launch intercepted');
  t.mock.method(chromium,'launch',async options=>{launches.push(options);throw intercepted;});
  for(const port of [22,992,8022]){
    await assert.rejects(probe({ip:'1.1.1.1',port,scheme:'http',source:'manual'}),error=>error===intercepted);
    const options=launches.at(-1);
    assert.deepEqual(options.args.filter(argument=>argument.startsWith('--explicitly-allowed-ports=')),[`--explicitly-allowed-ports=${port}`]);
    assert.match(options.proxy.server,/^http:\/\/127\.0\.0\.1:\d+$/);
    assert.ok(options.args.includes('--proxy-bypass-list=<-loopback>'));
  }
  for(const task of [{ip:'127.0.0.1',port:22},{ip:'1.1.1.1',port:0},{ip:'1.1.1.1',port:65536},{ip:'1.1.1.1',port:'22'}]){
    await assert.rejects(probe({...task,scheme:'http',source:'manual'}),/globally routable|Invalid port/);
  }
  assert.equal(launches.length,3);
});

test('an SSH banner is not accepted as an HTTP response by the lightweight check',async()=>{
  const sockets=new Set();
  const server=net.createServer(socket=>{
    sockets.add(socket);socket.on('close',()=>sockets.delete(socket));
    socket.end('SSH-2.0-OpenSSH_9.0\r\n');
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
    await assert.rejects(preflight({ip:'127.0.0.1',port:server.address().port,scheme:'http',url:'http://fixture.example/'}),error=>/^HPE_/.test(error.code||''));
  }finally{
    for(const socket of sockets)socket.destroy();
    await new Promise(resolve=>server.close(resolve));
  }
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
