// Claim loops are bounded to twice browser concurrency; this gate keeps cheap
// HTTP checks separate from expensive browser processes without an unbounded queue.
export function renderGate(limit, waitMs=65000) {
  let active=0;
  const pending=[];
  const release=()=>{
    active--;
    const next=pending.shift();
    if(next){clearTimeout(next.timer);active++;next.resolve(releaseOnce());}
  };
  const releaseOnce=()=>{let done=false;return()=>{if(!done){done=true;release();}};};
  return ()=>new Promise((resolve,reject)=>{
    if(active<limit){active++;resolve(releaseOnce());return;}
    const item={resolve,timer:null};
    item.timer=setTimeout(()=>{const i=pending.indexOf(item);if(i>=0)pending.splice(i,1);reject(new Error('Browser queue wait timeout'));},waitMs);
    pending.push(item);
  });
}
