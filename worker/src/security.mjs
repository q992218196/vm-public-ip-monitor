import ipaddr from 'ipaddr.js';

export function publicIP(value) {
  if (typeof value !== 'string' || value.includes('%') || !ipaddr.isValid(value)) return false;
  let a = ipaddr.parse(value);
  if (a.kind() === 'ipv6' && a.isIPv4MappedAddress()) a = a.toIPv4Address();
  // Also rejects documentation, transition, multicast and metadata addresses.
  return a.range() === 'unicast';
}

export function target(task) {
  if (!publicIP(task.ip)) throw new Error('Only globally routable target IPs are accepted');
  if (!Number.isInteger(task.port) || task.port < 1 || task.port > 65535) throw new Error('Invalid port');
  if (!['http', 'https'].includes(task.scheme)) throw new Error('Invalid scheme');
  let host = task.host || task.ip;
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (host.length > 253 || (!ipaddr.isValid(host) && !host.split('.').every(x => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(x)))) throw new Error('Invalid hostname');
  host = host.toLowerCase();
  const u = new URL(`${task.scheme}://${host.includes(':') ? `[${host}]` : host}:${task.port}/`);
  return {ip: task.ip, host, port: task.port, scheme: task.scheme, url: u.href, origin: u.origin};
}

export function permittedURL(value, t) {
  try {const u = new URL(value); return !u.username && !u.password && u.origin === t.origin;} catch {return false;}
}
