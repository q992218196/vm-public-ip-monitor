import http from 'node:http';
import net from 'node:net';
import {permittedURL} from './security.mjs';

// An origin-specific CONNECT/HTTP proxy pins all sockets to the approved IP.
// It never resolves names supplied by a page and never follows off-origin links.
// Use an additional network firewall around the browser container in production.
export async function pinnedProxy(t) {
  const sockets = new Set(); let bytes = 0; let denied = 0;
  const limit = 12 * 1024 * 1024;
  function track(s) {
    sockets.add(s); s.on('close', () => sockets.delete(s));
    s.setTimeout(15000, () => s.destroy());
    return s;
  }
  function account(chunk) { bytes += chunk.length; if (bytes > limit) for (const s of sockets) s.destroy(); }
  const server = http.createServer((req, res) => {
    if (t.scheme !== 'http' || !permittedURL(req.url, t) || !['GET','HEAD','POST','OPTIONS'].includes(req.method)) {denied++;res.writeHead(403);res.end();return;}
    const url = new URL(req.url);
    const headers = {...req.headers, host: url.host};
    delete headers['proxy-authorization']; delete headers['proxy-connection'];
    const upstream = http.request({host: t.ip, port: t.port, path: url.pathname + url.search, method: req.method, headers, agent: false}, r => {
      res.writeHead(r.statusCode, r.headers);r.on('data', account);r.pipe(res);
    });
    upstream.on('socket', track);upstream.on('error', () => {if(!res.headersSent)res.writeHead(502);res.end();});
    req.on('data', account); req.pipe(upstream);
  });
  server.on('connection', track);
  server.on('connect', (req, client, head) => {
    let u;try {u = new URL(`https://${req.url}`);} catch {client.destroy();return;}
    if (t.scheme !== 'https' || !permittedURL(u.href, t)) {denied++;client.end('HTTP/1.1 403 Forbidden\r\n\r\n');return;}
    const remote = track(net.connect({host: t.ip, port: t.port}, () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) remote.write(head);
      remote.on('data', account);client.on('data', account);client.pipe(remote);remote.pipe(client);
    }));
    remote.on('error', () => client.destroy());client.on('error', () => remote.destroy());
    client.on('close', () => remote.destroy());remote.on('close', () => client.destroy());
  });
  await new Promise((resolve, reject) => {server.once('error', reject);server.listen(0, '127.0.0.1', resolve);});
  return {address: `http://127.0.0.1:${server.address().port}`, stats: () => ({bytes, denied}), close: async () => {for (const s of sockets)s.destroy();await new Promise(resolve => server.close(resolve));}};
}
