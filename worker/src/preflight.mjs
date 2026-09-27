import http from 'node:http';
import https from 'node:https';

// Check a port before paying the cost of a browser. DNS is never consulted.
export function preflight(t) {
  return new Promise((resolve,reject)=>{
    const agent=t.scheme==='https'?https:http;
    const request=agent.request({host:t.ip,port:t.port,path:'/',method:'GET',agent:false,
      ...(t.scheme==='https'?{servername:t.host,rejectUnauthorized:true}:{}),
      headers:{Host:new URL(t.url).host,'User-Agent':'VM-Monitor/0.1 authorized-site-check',Connection:'close'}},response=>{
      resolve({status:response.statusCode});response.destroy();
    });
    request.setTimeout(8000,()=>request.destroy(new Error('HTTP preflight timeout')));
    request.on('error',reject);request.end();
  });
}
