import http from 'node:http';
import https from 'node:https';

// Check a port before paying the cost of a browser. DNS is never consulted.
export function preflight(t, timeoutMs=3000) {
  return new Promise((resolve,reject)=>{
    const agent=t.scheme==='https'?https:http;
    const request=agent.request({host:t.ip,port:t.port,path:'/',method:'GET',agent:false,maxHeaderSize:16384,
      ...(t.scheme==='https'?{servername:t.host,rejectUnauthorized:true}:{}),
      headers:{Host:new URL(t.url).host,'User-Agent':'VM-Monitor/0.1 authorized-site-check',Connection:'close'}},response=>{
      clearTimeout(timer);
      resolve({status:response.statusCode,contentType:String(response.headers['content-type']||'').toLowerCase().slice(0,255)});response.destroy();
    });
    const timer=setTimeout(()=>request.destroy(new Error('HTTP preflight timeout')),timeoutMs);
    request.on('error',error=>{clearTimeout(timer);reject(error);});request.end();
  });
}

export function needsBrowser(result) {
  return !result.contentType || /^(text\/html|application\/xhtml\+xml)(;|$)/i.test(result.contentType);
}
