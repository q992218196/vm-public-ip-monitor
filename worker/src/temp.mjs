import fs from 'node:fs/promises';
import path from 'node:path';
export async function directoryBytes(root) {
  let total=0;
  for(const e of await fs.readdir(root,{withFileTypes:true})) {
    const p=path.join(root,e.name);const s=await fs.lstat(p);
    total+=s.isDirectory()&&!s.isSymbolicLink()?await directoryBytes(p):s.size;
  }
  return total;
}
export async function cleanTemp(root) {
  const entries=await fs.readdir(root,{withFileTypes:true});
  for(const e of entries) {
    if(!/^playwright[-_]/.test(e.name))continue;
    const p=path.resolve(root,e.name);
    if(path.dirname(p)!==path.resolve(root))throw new Error('Unexpected temporary path');
    const s=await fs.lstat(p);
    if(Date.now()-s.mtimeMs>10*60*1000)await fs.rm(p,{recursive:s.isDirectory()&&!s.isSymbolicLink(),force:true});
  }
}
