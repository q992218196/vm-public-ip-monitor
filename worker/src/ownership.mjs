import {Resolver} from 'node:dns/promises';
import ipaddr from 'ipaddr.js';

const normalize = value => {try{return ipaddr.process(value.replace(/^\[|\]$/g,'')).toNormalizedString();}catch{return null;}};
async function systemResolve(host) {
  const resolver = new Resolver({timeout: 1500, tries: 1});
  const timer = setTimeout(()=>resolver.cancel(), 4000);
  try {
    const replies = await Promise.allSettled([resolver.resolve4(host), resolver.resolve6(host)]);
    const addresses = replies.flatMap(reply => reply.status==='fulfilled' ? reply.value : []);
    const uncertain = replies.some(reply => reply.status==='rejected' && !['ENODATA','ENOTFOUND'].includes(reply.reason?.code));
    return {addresses, uncertain};
  } finally {clearTimeout(timer);}
}

export function createOwnershipChecker({resolve=systemResolve, clock=Date.now, maxEntries=512}={}) {
  const cache = new Map();
  return async task => {
    const host = (task.host || task.ip).toLowerCase().replace(/\.$/,'');
    const checkedAt = new Date(clock()).toISOString();
    const base = {host, checked_at: checkedAt, addresses: [], limitations: 'DNS 指向只能证明当前解析关系；CDN、隐藏源站或人工登记需要单独核实。'};
    if (task.source==='manual') return {ownership_status:'manual',ownership_evidence:{...base,method:'administrator_registered'}};
    if (normalize(host)) return {ownership_status:normalize(host)===normalize(task.ip)?'ip_only':'dns_mismatch',ownership_evidence:{...base,method:'literal_ip_comparison'}};
    let item=cache.get(host);
    if (!item || item.expires <= clock()) {
      if(cache.size>=maxEntries)cache.delete(cache.keys().next().value);
      item={expires:clock()+600000,promise:Promise.resolve().then(()=>resolve(host)).catch(()=>({addresses:[],uncertain:true}))};
      cache.set(host,item);
    }
    const answer=await item.promise;
    if(answer.uncertain)item.expires=Math.min(item.expires,clock()+30000);
    const addresses=[...new Set(answer.addresses.filter(address=>normalize(address)))];
    const matched=addresses.find(address=>normalize(address)===normalize(task.ip));
    const retained=matched?[matched,...addresses.filter(address=>address!==matched)].slice(0,16):addresses.slice(0,16);
    return {ownership_status:matched?'dns_match':answer.uncertain?'dns_unknown':'dns_mismatch',ownership_evidence:{...base,method:'dns_A_AAAA',addresses:retained,addresses_truncated:addresses.length>16}};
  };
}
export const verifyOwnership=createOwnershipChecker();
