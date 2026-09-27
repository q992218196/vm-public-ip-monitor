import fs from 'node:fs/promises';
import path from 'node:path';
import {probe} from './probe.mjs';
import {fileLogger} from './logger.mjs';
import {cleanTemp} from './temp.mjs';

const base = new URL(process.env.MONITOR_URL || 'https://monitor.example.com');
const token = process.env.MONITOR_WORKER_TOKEN || '';
const dataDir = process.env.WORKER_DATA_DIR || '/home/vm-monitor-worker';
const concurrency = Number(process.env.WORKER_CONCURRENCY || 1);
const diskLimitMiB=Number(process.env.WORKER_DISK_LIMIT_MIB||512);
if (base.protocol !== 'https:' && !(process.env.ALLOW_INTERNAL_HTTP === '1' && base.protocol === 'http:')) throw new Error('HTTPS required; explicit internal Docker HTTP opt-in available');
if (token.length < 32 || !Number.isInteger(concurrency) || concurrency < 1 || concurrency > 4) throw new Error('Configure worker token and concurrency 1..4');
if(!Number.isInteger(diskLimitMiB)||diskLimitMiB<128||diskLimitMiB>65536)throw new Error('WORKER_DISK_LIMIT_MIB must be 128..65536');
await fs.mkdir(path.join(dataDir,'tmp'), {recursive:true, mode:0o700});
const log=fileLogger(dataDir);
await cleanTemp(path.join(dataDir,'tmp'));
process.env.TMPDIR = path.join(dataDir,'tmp');process.env.TMP = process.env.TMPDIR;process.env.TEMP = process.env.TMPDIR;
process.env.HOME=path.join(dataDir,'home');process.env.XDG_CACHE_HOME=path.join(dataDir,'cache');
await fs.mkdir(process.env.HOME,{recursive:true,mode:0o700});await fs.mkdir(process.env.XDG_CACHE_HOME,{recursive:true,mode:0o700});
let stopped = false;process.on('SIGTERM',()=>{stopped=true;});process.on('SIGINT',()=>{stopped=true;});
const sleep = ms => new Promise(resolve=>setTimeout(resolve,ms));
async function api(route, body) {
  const r = await fetch(new URL(`/api/v1/worker/${route}`,base), {method:'POST',redirect:'error',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json',Accept:'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(20000)});
  if (!r.ok) throw new Error(`API ${r.status}`);return r.json();
}
async function loop() {
  while(!stopped) {
    try {
      const {task} = await api('claim',{});if(!task){await sleep(5000);continue;}
      let result;try{result=await probe(task,{dataDir,diskLimitBytes:diskLimitMiB*1024*1024});}catch(e){result={status:'failed',error:String(e.message).slice(0,1000)};}
      await api(`tasks/${task.id}/complete`,{lease_token:task.lease_token,...result});
      await log(JSON.stringify({task:task.id,status:result.status}));
    } catch(e) {await log(String(e.message));await sleep(10000);}
  }
}
await Promise.all(Array.from({length:concurrency},loop));
