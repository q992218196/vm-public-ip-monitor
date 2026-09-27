import fs from 'node:fs/promises';
import path from 'node:path';
export function fileLogger(dir) {
  const filename=path.join(dir,'worker.log');let tail=Promise.resolve();
  return message=>{tail=tail.then(async()=>{
    const size=await fs.stat(filename).then(s=>s.size).catch(()=>0);
    if(size>8*1024*1024){await fs.rm(filename+'.1',{force:true});await fs.rename(filename,filename+'.1');}
    await fs.appendFile(filename,JSON.stringify({time:new Date().toISOString(),message:String(message).slice(0,2000)})+'\n',{mode:0o600});
  }).catch(()=>{});return tail;};
}
