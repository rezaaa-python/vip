//
// -----------------------------------------------------------
// 🚀 VLESS Proxy Worker - Final & Fully-Featured Script 🚀
// -----------------------------------------------------------
// This version includes server-side DNS resolution for proxy hosts
// and robust error handling for all network information lookups.
//

import { connect } from 'cloudflare:sockets';

// --- CONFIGURATION ---
const Config = {
  proxyIPs: ['nima.nscl.ir:443'], 
  scamalytics: {
    username: 'revilseptember',
    apiKey: 'b2fc368184deb3d8ac914bd776b8215fe899dd8fef69fbaba77511acfbdeca0d',
    baseUrl: 'https://api12.scamalytics.com/v3/',
  },
  fromEnv(env) {
    const selectedProxyIP = env.PROXYIP || this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
    const [proxyHost, proxyPort = '443'] = selectedProxyIP.split(':');
    return {
      proxyAddress: selectedProxyIP,
      proxyHost: proxyHost,
      proxyPort: parseInt(proxyPort, 10),
      scamalytics: {
        username: env.SCAMALYTICS_USERNAME || this.scamalytics.username,
        apiKey: env.SCAMALYTICS_API_KEY || this.scamalytics.apiKey,
        baseUrl: env.SCAMALYTICS_BASEURL || this.scamalytics.baseUrl,
      },
    };
  },
};

const CONST = {
  WS_READY_STATE_OPEN: 1,
  WS_READY_STATE_CLOSING: 2,
};

// --- MAIN FETCH HANDLER ---
export default {
  async fetch(request, env, ctx) {
    try {
      if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
        return handleWebSocket(request, env, ctx);
      }
      const url = new URL(request.url);
      const cfg = Config.fromEnv(env);

      if (url.pathname === '/api/network-info') {
        return handleNetworkInfo(request, cfg);
      }

      if (!env.DB || !env.KV) return new Response('Service Unavailable: D1 or KV binding is not configured.', { status: 503 });
      if (!env.ADMIN_KEY) console.error('CRITICAL: ADMIN_KEY secret is not set in environment variables.');
      
      if (url.pathname.startsWith('/admin')) return handleAdminRoutes(request, env);
      
      const parts = url.pathname.slice(1).split('/');
      let userID;
      if ((parts[0] === 'xray' || parts[0] === 'sb') && parts.length > 1) {
        userID = parts[1];
        if (await isValidUser(userID, env, ctx)) return handleIpSubscription(parts[0], userID, url.hostname);
      } else if (parts.length === 1 && isValidUUID(parts[0])) {
        userID = parts[0];
      }
      
      if (userID && await isValidUser(userID, env, ctx)) {
        return handleConfigPage(userID, url.hostname, cfg.proxyAddress);
      }
      
      return new Response('404 Not Found. Please use your unique user ID in the URL.', { status: 404 });
    } catch (err) {
      console.error('Unhandled Exception:', err);
      return new Response('Internal Server Error', { status: 500 });
    }
  },
};

// --- SMART API ENDPOINT FOR NETWORK INFO (ENHANCED) ---
async function handleNetworkInfo(request, config) {
    const clientIp = request.headers.get('CF-Connecting-IP');
    const proxyHost = config.proxyHost;

    // --- Helper to resolve domain to IP if needed ---
    const resolveHostToIp = async (host) => {
        // Check if it's already an IP address
        if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(host) || host.includes(':')) {
            return host;
        }
        try {
            // Use DNS-over-HTTPS for resolution
            const response = await fetch(`https://dns.google/resolve?name=${host}&type=A`);
            if (!response.ok) return host; // Fallback to host
            const data = await response.json();
            if (data.Answer && data.Answer.length > 0) {
                return data.Answer[0].data;
            }
        } catch (e) {
            console.error(`DNS resolution failed for ${host}:`, e);
        }
        return host; // Fallback to original host
    };

    // Helper to fetch IP details
    const getIpDetails = async (ip) => {
        if (!ip) return null;
        try {
            // Using a reliable provider
            const response = await fetch(`https://ipinfo.io/${ip}/json`);
            if (!response.ok) throw new Error(`ipinfo.io status: ${response.status}`);
            const data = await response.json();
            return {
                ip: data.ip,
                city: data.city,
                country: data.country,
                isp: data.org,
            };
        } catch (error) {
            console.error(`Failed to fetch details for IP ${ip}:`, error);
            return { ip };
        }
    };

    // Helper to get Scamalytics data
    const getScamalyticsDetails = async (ip) => {
        if (!ip) return null;
        if (!config.scamalytics.apiKey || !config.scamalytics.username) {
            console.warn("Scamalytics credentials are not set in environment variables. Risk score will be unavailable.");
            return null;
        }
        try {
            const url = `${config.scamalytics.baseUrl}${config.scamalytics.username}/?key=${config.scamalytics.apiKey}&ip=${ip}`;
            const response = await fetch(url);
            if (!response.ok) throw new Error(`Scamalytics status: ${response.status}`);
            const data = await response.json();
            return (data.status === 'ok') ? { score: data.score, risk: data.risk } : null;
        } catch (error) {
            console.error(`Failed to fetch Scamalytics for IP ${ip}:`, error);
            return null;
        }
    };

    // Resolve proxy host to IP first
    const proxyIp = await resolveHostToIp(proxyHost);
    
    // Fetch all data in parallel for maximum speed
    const [clientDetails, proxyDetails, scamalyticsData] = await Promise.all([
        getIpDetails(clientIp),
        getIpDetails(proxyIp),
        getScamalyticsDetails(clientIp)
    ]);
    
    const responseData = {
        client: {
            ...clientDetails,
            risk: scamalyticsData,
        },
        proxy: {
            host: config.proxyAddress,
            ...proxyDetails
        }
    };
    
    return new Response(JSON.stringify(responseData), {
        headers: { 
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*' 
        },
    });
}


// --- WEBSOCKET & PROXY LOGIC (Unchanged) ---
async function handleWebSocket(request, env, ctx) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  const log = (info, event) => console.log(`[WS] ${info}`, event || '');
  const earlyDataHeader = request.headers.get('Sec-WebSocket-Protocol') || '';
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  
  let remoteSocketWrapper = { value: null };
  let isHeaderProcessed = false;

  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk, controller) {
      if (isHeaderProcessed && remoteSocketWrapper.value) {
        const writer = remoteSocketWrapper.value.writable.getWriter();
        try {
          await writer.write(chunk);
        } finally {
          writer.releaseLock();
        }
        return;
      }

      const { hasError, message, addressRemote, portRemote, rawDataIndex, ProtocolVersion, isUDP } = await processVlessHeader(chunk, env, ctx);

      if (hasError) {
        log(`VLESS Header Error: ${message}`);
        return controller.error(new Error(message));
      }
      if (isUDP) {
        log('UDP is not supported.');
        return controller.error(new Error('UDP not supported'));
      }
      
      const initialClientData = chunk.slice(rawDataIndex);
      
      const remoteSocket = await handleTCPOutbound({
        addressRemote,
        portRemote,
        vlessResponseHeader: new Uint8Array([ProtocolVersion[0], 0]),
        initialClientData,
        webSocket,
        log: (msg, ev) => console.log(`[${addressRemote}:${portRemote}] ${msg}`, ev || ''),
      });

      if (!remoteSocket) {
        return controller.error(new Error('Failed to establish remote connection.'));
      }
      
      remoteSocketWrapper.value = remoteSocket;
      isHeaderProcessed = true;

      remoteSocket.readable
        .pipeTo(new WritableStream({
          write(chunk) {
            if (webSocket.readyState === CONST.WS_READY_STATE_OPEN) {
              webSocket.send(chunk);
            }
          },
          close: () => log('Remote socket readable stream closed.'),
          abort: (err) => log('Remote socket readable stream aborted:', err),
        }))
        .catch(err => log('Error piping remote to WebSocket:', err));
    },
    abort: (err) => log('WebSocket readable stream aborted:', err),
  }))
  .catch(err => {
    log('WebSocket pipeline failed:', err);
    safeCloseWebSocket(webSocket);
  });

  return new Response(null, { status: 101, webSocket: client });
}

async function handleTCPOutbound({ addressRemote, portRemote, vlessResponseHeader, initialClientData, webSocket, log }) {
  try {
    const remoteSocket = await connect({ hostname: addressRemote, port: portRemote });
    if (webSocket.readyState === CONST.WS_READY_STATE_OPEN) {
      webSocket.send(vlessResponseHeader);
    }
    const writer = remoteSocket.writable.getWriter();
    await writer.write(initialClientData);
    writer.releaseLock();
    return remoteSocket;
  } catch (error) {
    log(`Connection to ${addressRemote}:${portRemote} failed`, error);
    safeCloseWebSocket(webSocket, 1011, `Proxy connection failed: ${error.message}`);
    return null;
  }
}

// --- VLESS & UTILITY FUNCTIONS (Unchanged) ---
async function processVlessHeader(vlessBuffer, env, ctx) {
  if (vlessBuffer.byteLength < 24) return { hasError: true, message: 'Invalid VLESS header' };
  const dataView = new DataView(vlessBuffer);
  const version = dataView.getUint8(0);
  const uuid = stringify(new Uint8Array(vlessBuffer.slice(1, 17)));

  if (!await isValidUser(uuid, env, ctx)) return { hasError: true, message: 'Invalid user' };

  const optLength = dataView.getUint8(17);
  const command = dataView.getUint8(18 + optLength);
  const portIndex = 18 + optLength + 1;
  const portRemote = dataView.getUint16(portIndex);
  const addressType = dataView.getUint8(portIndex + 2);

  let addressRemote, rawDataIndex;
  switch (addressType) {
    case 1:
      addressRemote = new Uint8Array(vlessBuffer.slice(portIndex + 3, portIndex + 7)).join('.');
      rawDataIndex = portIndex + 7;
      break;
    case 2:
      const addressLength = dataView.getUint8(portIndex + 3);
      addressRemote = new TextDecoder().decode(vlessBuffer.slice(portIndex + 4, portIndex + 4 + addressLength));
      rawDataIndex = portIndex + 4 + addressLength;
      break;
    case 3:
      const ipv6 = Array.from({ length: 8 }, (_, i) => dataView.getUint16(portIndex + 3 + i * 2).toString(16)).join(':');
      addressRemote = `[${ipv6}]`;
      rawDataIndex = portIndex + 19;
      break;
    default:
      return { hasError: true, message: `Invalid addressType: ${addressType}` };
  }

  return {
    hasError: false, addressRemote, portRemote, rawDataIndex,
    ProtocolVersion: new Uint8Array([version]), isUDP: command === 2,
  };
}

const isValidUUID = (uuid) => /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);

async function isValidUser(userID, env, ctx) {
    if (!isValidUUID(userID)) return false;
    const cacheKey = `user:${userID}`;
    const cached = await env.KV.get(cacheKey);
    if (cached === 'valid') return true;
    if (cached === 'invalid') return false;
    try {
        const now = Math.floor(Date.now() / 1000);
        const stmt = env.DB.prepare('SELECT expiration_timestamp, status FROM users WHERE id = ?');
        const user = await stmt.bind(userID).first();
        if (!user || user.expiration_timestamp < now || user.status !== 'active') {
            await env.KV.put(cacheKey, 'invalid', { expirationTtl: 3600 });
            return false;
        }
        ctx.waitUntil(env.DB.prepare('UPDATE users SET last_accessed = ? WHERE id = ?').bind(now, userID).run());
        await env.KV.put(cacheKey, 'valid', { expiration: user.expiration_timestamp });
        return true;
    } catch (e) {
        console.error('D1 query failed in isValidUser:', e);
        return false;
    }
}

function makeReadableWebSocketStream(webSocket, earlyData, log) {
  let readableStreamCancel = false;
  return new ReadableStream({
    start(controller) {
      webSocket.addEventListener('message', (event) => { if (!readableStreamCancel) controller.enqueue(event.data); });
      webSocket.addEventListener('close', () => { if (!readableStreamCancel) controller.close(); });
      webSocket.addEventListener('error', (err) => { if (!readableStreamCancel) controller.error(err); });
      const { earlyData: parsedEarlyData, error } = base64ToArrayBuffer(earlyData);
      if (error) controller.error(error);
      else if (parsedEarlyData) controller.enqueue(parsedEarlyData);
    },
    cancel() { readableStreamCancel = true; safeCloseWebSocket(webSocket); },
  });
}

function safeCloseWebSocket(socket, code, reason) {
  try {
    if (socket.readyState === CONST.WS_READY_STATE_OPEN || socket.readyState === CONST.WS_READY_STATE_CLOSING) {
      socket.close(code, reason);
    }
  } catch (error) { console.error('safeCloseWebSocket error:', error); }
}

const byteToHex = Array.from({ length: 256 }, (_, i) => (i + 0x100).toString(16).slice(1));
function stringify(arr) {
  const uuid = (
    byteToHex[arr[0]]+byteToHex[arr[1]]+byteToHex[arr[2]]+byteToHex[arr[3]]+'-'+
    byteToHex[arr[4]]+byteToHex[arr[5]]+'-'+
    byteToHex[arr[6]]+byteToHex[arr[7]]+'-'+
    byteToHex[arr[8]]+byteToHex[arr[9]]+'-'+
    byteToHex[arr[10]]+byteToHex[arr[11]]+byteToHex[arr[12]]+byteToHex[arr[13]]+byteToHex[arr[14]]+byteToHex[arr[15]]
  ).toLowerCase();
  if (!isValidUUID(uuid)) throw new TypeError('Invalid UUID');
  return uuid;
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { earlyData: null, error: null };
    try {
        const binaryStr = atob(base64Str.replace(/-/g, '+').replace(/_/g, '/'));
        const buffer = new ArrayBuffer(binaryStr.length);
        const view = new Uint8Array(buffer);
        for (let i = 0; i < binaryStr.length; i++) view[i] = binaryStr.charCodeAt(i);
        return { earlyData: buffer, error: null };
    } catch (error) { return { earlyData: null, error }; }
}

// --- LINK GENERATION, ADMIN PANEL, HTML/CSS/JS (All Unchanged) ---
// --- Paste the unchanged functions from the previous correct script here ---
// --- For brevity, they are omitted, but you need them for the script to be complete ---
// --- The getPageScript() function from the previous response is the correct one to use ---

function generateRandomPath(length = 12, query = '') {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) result += chars.charAt(Math.floor(Math.random() * chars.length));
  return `/${result}${query ? `?${query}` : ''}`;
}

const CORE_PRESETS = {
  xray: { tls: { path: () => generateRandomPath(12, 'ed=2048'), security: 'tls', fp: 'chrome', alpn: 'http/1.1', extra: {} } },
  sb: { tls: { path: () => generateRandomPath(18), security: 'tls', fp: 'firefox', alpn: 'h3', extra: {ed: 2560} } },
};

function createVlessLink({ userID, address, port, host, path, security, sni, fp, alpn, extra = {}, name }) {
  const params = new URLSearchParams({ type: 'ws', host, path, ...extra });
  if (security) params.set('security', security);
  if (sni) params.set('sni', sni);
  if (fp) params.set('fp', fp);
  if (alpn) params.set('alpn', alpn);
  return `vless://${userID}@${address}:${port}?${params.toString()}#${encodeURIComponent(name)}`;
}

function buildLink({ core, userID, hostName, address, port, tag }) {
  const p = CORE_PRESETS[core].tls;
  return createVlessLink({
    userID, address, port,
    host: hostName,
    path: p.path(),
    security: p.security,
    sni: hostName,
    fp: p.fp,
    alpn: p.alpn,
    extra: p.extra,
    name: `${tag}-TLS`,
  });
}

const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

async function handleIpSubscription(core, userID, hostName) {
  const mainDomains = [ hostName, 'www.speedtest.net', 'cdnjs.com' ];
  const httpsPorts = [443, 8443, 2053, 2083, 2087, 2096];
  let links = mainDomains.map((domain, i) => buildLink({ core, userID, hostName, address: domain, port: pick(httpsPorts), tag: `D${i + 1}` }));
  try {
    const r = await fetch('https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/Cloudflare-IPs.json');
    if (r.ok) {
      const json = await r.json();
      const ips = [...(json.ipv4 || []), ...(json.ipv6 || [])].slice(0, 10).map(x => x.ip);
      links.push(...ips.map((ip, i) => buildLink({ core, userID, hostName, address: ip.includes(':') ? `[${ip}]` : ip, port: pick(httpsPorts), tag: `IP${i + 1}` })));
    }
  } catch (e) { console.error('Failed to fetch IP list:', e); }
  return new Response(btoa(links.join('\n')), { headers: { 'Content-Type': 'text/plain;charset=utf-8' } });
}

async function handleAdminRoutes(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace('/admin', '');
  if (request.method === 'GET' && (path === '/login' || path === '/')) return new Response(getAdminLoginHTML(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  if (request.method === 'GET' && path === '/dashboard') return new Response(getAdminDashboardHTML(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  const authKey = request.headers.get('Authorization');
  if (authKey !== env.ADMIN_KEY) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  try {
    if (request.method === 'POST' && path === '/api/users') {
      const { id, expiration_date, expiration_time, notes = '' } = await request.json();
      if (!id || !expiration_date || !expiration_time || !isValidUUID(id)) return Response.json({ error: 'Missing or invalid parameters' }, { status: 400 });
      const expirationTimestamp = Math.floor(new Date(`${expiration_date}T${expiration_time}:00Z`).getTime() / 1000);
      const now = Math.floor(Date.now() / 1000);
      await env.DB.prepare('INSERT INTO users (id, expiration_timestamp, created_at, status, notes) VALUES (?, ?, ?, ?, ?)').bind(id, expirationTimestamp, now, 'active', notes).run();
      await env.KV.delete(`user:${id}`);
      return Response.json({ success: true });
    }
    if (request.method === 'GET' && path === '/api/users') {
      const { results } = await env.DB.prepare('SELECT * FROM users ORDER BY created_at DESC').all();
      return Response.json(results);
    }
    if (request.method === 'DELETE' && path.startsWith('/api/users/')) {
      const id = path.substring('/api/users/'.length);
      if (!isValidUUID(id)) return Response.json({ error: 'Invalid UUID format' }, { status: 400 });
      await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
      await env.KV.delete(`user:${id}`);
      return Response.json({ success: true });
    }
  } catch (e) {
    return Response.json({ error: `An internal server error occurred: ${e.message}` }, { status: 500 });
  }
  return new Response('Admin endpoint not found', { status: 404 });
}

function handleConfigPage(userID, hostName, proxyAddress) {
  return new Response(generateBeautifulConfigPage(userID, hostName), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

function generateBeautifulConfigPage(userID, hostName) {
  const dream = buildLink({ core: 'xray', userID, hostName, address: hostName, port: 443, tag: `${hostName}-Xray` });
  const freedom = buildLink({ core: 'sb', userID, hostName, address: hostName, port: 443, tag: `${hostName}-Singbox` });
  const subXrayUrl = `https://${hostName}/xray/${userID}`;
  const subSbUrl = `https://${hostName}/sb/${userID}`;
  const clientUrls = {
    clashMeta: `clash://install-config?url=${encodeURIComponent(`https://revil-sub.pages.dev/sub/clash-meta?url=${subSbUrl}`)}`,
    hiddify: `hiddify://install-config?url=${encodeURIComponent(subXrayUrl)}`,
    v2rayng: `v2rayng://install-config?url=${encodeURIComponent(subXrayUrl)}`,
    exclave: `sn://subscription?url=${encodeURIComponent(subSbUrl)}`,
  };
  return `<!doctype html><html lang="en"><head><meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" /><title>VLESS Proxy Configuration</title><link rel="icon" href="https://raw.githubusercontent.com/NiREvil/zizifn/refs/heads/Legacy/assets/favicon.png" type="image/png"><style>${getPageCSS()}</style></head><body>${getPageHTML({ dream, freedom }, clientUrls)}<script>${getPageScript()}</script></body></html>`;
}

function getAdminLoginHTML() { return `<!DOCTYPE html><html><head><title>Admin Login</title><style>body{display:flex;justify-content:center;align-items:center;height:100vh;background:#1a1a1a;font-family:sans-serif;margin:0;}div{padding:2rem;background:#2a2a2a;border-radius:8px;color:white;text-align:center;}input,button{width:100%;padding:10px;margin-top:10px;border-radius:5px;border:1px solid #444;background:#333;color:white;box-sizing:border-box;}button{cursor:pointer;background:#007bff;}p{color:red;}</style></head><body><div><h2>Admin Login</h2><input type="password" id="admin-key" placeholder="Enter Admin Key"><button onclick="login()">Login</button><p id="error-message"></p></div><script>async function login(){const key=document.getElementById('admin-key').value;const e=document.getElementById('error-message');if(!key)return e.textContent='Key cannot be empty.';try{const r=await fetch('/admin/api/users',{headers:{'Authorization':key}});if(r.ok){localStorage.setItem('admin_key',key);window.location.href='/admin/dashboard';}else if(r.status===401)e.textContent='Invalid Key.';else e.textContent='An unknown error occurred.';}catch(t){e.textContent='Failed to connect.';}}document.getElementById('admin-key').addEventListener('keyup',e=>{if(e.key==='Enter')login();});</script></body></html>`; }
function getAdminDashboardHTML() { return `<!DOCTYPE html><html lang="en"><head><title>Admin Dashboard</title><style>body{background:#1a1a1a;font-family:sans-serif;color:#fff;padding:20px;}.dashboard{max-width:900px;margin:auto;background:#2a2a2a;border-radius:15px;padding:20px;}h1,h2{text-align:center;}.create-section{background:#333;padding:15px;border-radius:10px;margin-bottom:20px;}input,button{padding:8px;margin:5px;border:none;border-radius:5px;background:#444;color:#fff;}button{background:#007bff;cursor:pointer;}table{width:100%;border-collapse:collapse;}th,td{padding:10px;text-align:left;border-bottom:1px solid #444;word-break:break-all;}.expired{color:#ff5252;}</style></head><body><div class="dashboard"><h1>Admin Dashboard</h1><div class="create-section"><h2>Create User</h2><input type="text" id="new-id" placeholder="User ID (UUID)"><button onclick="generateUUID()">Generate</button><input type="date" id="exp-date"><input type="time" id="exp-time"><input type="text" id="notes" placeholder="Notes"><button onclick="createUser()">Create</button></div><h2>User List</h2><table id="user-table"><thead><tr><th>ID</th><th>Expiry</th><th>Created</th><th>Status</th><th>Notes</th><th>Actions</th></tr></thead><tbody></tbody></table></div><script>const adminKey=localStorage.getItem('admin_key');if(!adminKey)window.location.href='/admin/login';const apiHeaders={'Content-Type':'application/json','Authorization':adminKey};async function api(e,t={}){const s=await fetch('/admin/api'+e,{...t,headers:apiHeaders});if(s.status===401)return window.location.href='/admin/login';return s}function generateUUID(){document.getElementById('new-id').value=crypto.randomUUID()}async function createUser(){const e=document.getElementById('new-id').value,t=document.getElementById('exp-date').value,s=document.getElementById('exp-time').value,n=document.getElementById('notes').value;if(!e||!t||!s)return alert('Fill required fields.');(await api('/users',{method:'POST',body:JSON.stringify({id:e,expiration_date:t,expiration_time:s,notes:n})})).ok?loadUsers():alert('Error creating user.')}async function loadUsers(){const e=await(await api('/users')).json(),t=document.querySelector('#user-table tbody');t.innerHTML='';const s=Date.now()/1000;e.forEach(e=>{const n=new Date(e.expiration_timestamp*1000).toLocaleString(),i=new Date(e.created_at*1000).toLocaleDateString(),a=e.expiration_timestamp>s&&e.status==='active'?'':'expired';t.innerHTML+=\`<tr><td>\${e.id}</td><td class="\${a}">\${n}</td><td>\${i}</td><td class="\${a}">\${e.status}</td><td>\${e.notes||''}</td><td><button onclick="deleteUser('\${e.id}')">Delete</button></td></tr>\`})}async function deleteUser(e){if(confirm('Delete user?')&&(await api(\`/users/\${e}\`,{method:'DELETE'})).ok)loadUsers();else alert('Error deleting user.')}window.onload=()=>{generateUUID();loadUsers()};</script></body></html>`; }
function getPageCSS() { return `*{margin:0;padding:0;box-sizing:border-box}body{font-family:sans-serif;background-color:#1e1e1e;color:#e0e0e0;padding:2rem;line-height:1.5}.container{max-width:800px;margin:auto;background:#2a2a2a;padding:2rem;border-radius:8px}.header{text-align:center;margin-bottom:2rem}h1{color:#fff}.config-card{background:#333;border-radius:8px;padding:1.5rem;margin-bottom:1.5rem}.config-title{display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;border-bottom:1px solid #444;padding-bottom:.5rem}h2{font-size:1.2rem}.config-content pre{background:#252525;padding:1rem;border-radius:5px;word-break:break-all;white-space:pre-wrap;font-size:.9rem}.button{padding:.5rem 1rem;border:none;border-radius:5px;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:.5rem}.copy-btn{background:#555;color:#fff}.client-btn{background:#007bff;color:#fff}.client-buttons{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-top:1rem}.ip-info-grid{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem}.ip-info-section .label{font-size:.8rem;color:#aaa}.ip-info-section .value{font-size:1rem;color:#fff}.skeleton{display:inline-block;height:1em;width:120px;background:linear-gradient(90deg,#3a3a3a 25%,#4a4a4a 50%,#3a3a3a 75%);background-size:200% 100%;animation:loading 1.5s infinite;border-radius:4px}.badge{padding:.2em .6em;font-size:.8em;border-radius:10px}.badge-yes{background-color:rgba(76,175,80,.2);color:#4caf50}.badge-no{background-color:rgba(244,67,54,.2);color:#f44354}.badge-warning{background-color:rgba(255,152,0,.2);color:#ff9800}.badge-neutral{background-color:rgba(144,144,144,.2);color:#9e9e9e}@keyframes loading{0%{background-position:200% 0}100%{background-position:-200% 0}}`; }
function getPageHTML(configs, clientUrls) { return `<div class="container"><div class="header"><h1>VLESS Proxy Configuration</h1><p>Copy the configuration or import directly into your client</p></div><div class="config-card"><div class="config-title"><h2>Network Information</h2> <button id="refresh-ip-info" class="button copy-btn">Refresh</button></div><div class="ip-info-grid"><div class="ip-info-section"><h3>Proxy Server</h3><p class="label">Proxy Host</p><p class="value" id="proxy-host"><span class="skeleton"></span></p><p class="label">IP Address</p><p class="value" id="proxy-ip"><span class="skeleton"></span></p><p class="label">Location</p><p class="value" id="proxy-location"><span class="skeleton"></span></p><p class="label">ISP Provider</p><p class="value" id="proxy-isp"><span class="skeleton"></span></p></div><div class="ip-info-section"><h3>Your Connection</h3><p class="label">Your IP</p><p class="value" id="client-ip"><span class="skeleton"></span></p><p class="label">Location</p><p class="value" id="client-location"><span class="skeleton"></span></p><p class="label">ISP Provider</p><p class="value" id="client-isp"><span class="skeleton"></span></p><p class="label">Risk Score</p><p class="value" id="client-proxy"><span class="skeleton"></span></p></div></div></div><div class="config-card"><div class="config-title"><h2>Xray Core Clients</h2><button class="button copy-btn" onclick="copyToClipboard(this, '${configs.dream}')">Copy</button></div><div class="config-content"><pre>${configs.dream}</pre></div><div class="client-buttons"><a href="${clientUrls.hiddify}" class="button client-btn">Import to Hiddify</a><a href="${clientUrls.v2rayng}" class="button client-btn">Import to V2rayNG</a></div></div><div class="config-card"><div class="config-title"><h2>Sing-Box Core Clients</h2><button class="button copy-btn" onclick="copyToClipboard(this, '${configs.freedom}')">Copy</button></div><div class="config-content"><pre>${configs.freedom}</pre></div><div class="client-buttons"><a href="${clientUrls.clashMeta}" class="button client-btn">Import to Clash Meta</a><a href="${clientUrls.exclave}" class="button client-btn">Import to Exclave</a></div></div></div>`; }
function getPageScript() { return `function copyToClipboard(t,e){const n=t.innerHTML;navigator.clipboard.writeText(e).then(()=>{t.textContent="Copied!",t.disabled=!0,setTimeout(()=>{t.innerHTML=n,t.disabled=!1},1200)})}function updateDisplay(t){const e=t.proxy||{};document.getElementById("proxy-host").textContent=e.host||"N/A",document.getElementById("proxy-ip").textContent=e.ip||"N/A",document.getElementById("proxy-isp").textContent=e.isp||"N/A";const n=[e.city,e.country].filter(Boolean).join(", ");document.getElementById("proxy-location").textContent=n||"N/A";const o=t.client||{};document.getElementById("client-ip").textContent=o.ip||"N/A",document.getElementById("client-isp").textContent=o.isp||"N/A";const d=[o.city,o.country].filter(Boolean).join(", ");document.getElementById("client-location").textContent=d||"N/A";const i=o.risk;let c="Unknown",l="badge-neutral";i&&void 0!==i.score&&(c=\`\${i.score} - \${i.risk.charAt(0).toUpperCase()+i.risk.slice(1)}\`,{low:"badge-yes",medium:"badge-warning",high:"badge-no","very high":"badge-no"}[i.risk.toLowerCase()]);document.getElementById("client-proxy").innerHTML=\`<span class="badge \${l}">\${c}</span>\`}async function loadNetworkInfo(){try{const t=await fetch("/api/network-info");if(!t.ok)throw new Error(\`API request failed: \${t.status}\`);const e=await t.json();updateDisplay(e)}catch(t){console.error("Failed to load network info:",t),updateDisplay({client:{},proxy:{}})}}document.getElementById("refresh-ip-info")?.addEventListener("click",function(){const t=this;t.disabled=!0;const e=t=>{["host","ip","location","isp","proxy"].forEach(e=>{const n=document.getElementById(\`\${t}-\${e}\`);n&&(n.innerHTML='<span class="skeleton"></span>')})};e("proxy"),e("client"),loadNetworkInfo().finally(()=>setTimeout(()=>{t.disabled=!1},500))}),document.addEventListener("DOMContentLoaded",loadNetworkInfo);`; }
