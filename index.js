// ----------------------------------------------------------------    
// 🚀 VLESS Proxy Worker - Unified & Fully-Featured Script 🚀    
// ----------------------------------------------------------------    
// This script combines a VLESS proxy, DNS-over-HTTPS, an admin panel,    
// a network information API, and a server-side rendered UI.    
// It intelligently handles both TCP and UDP VLESS requests.    
//    
    
import { connect } from 'cloudflare:sockets';    
    
// --- CONFIGURATION ---    
// All settings are managed via Environment Variables in the Cloudflare dashboard.    
const Config = {    
  // Fallback/Relay server if PROXYIP is not set    
  defaultProxyIPs: ['nima.nscl.ir:443'],    
    
  // Default upstream DoH server if DOH_UPSTREAM_URL is not set    
  defaultDoHUpstream: 'https://chrome.cloudflare-dns.com/dns-query',    
    
  // Scamalytics API default settings    
  scamalytics: {    
    username: 'revilseptember',    
    apiKey: 'b2fc368184deb3d8ac914bd776b8215fe899dd8fef69fbaba77511acfbdeca0d',    
    baseUrl: 'https://api12.scamalytics.com/v3/',    
  },    
    
  // This function reads settings from the environment variables (env)    
  fromEnv(env) {    
    const proxyIPs = env.PROXYIP ? env.PROXYIP.split(',').map(ip => ip.trim()) : this.defaultProxyIPs;    
    const selectedProxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];    
    const [proxyHost, proxyPort = '443'] = selectedProxyIP.split(':');    
    
    return {    
      proxyAddress: selectedProxyIP,    
      proxyIP: proxyHost,    
      proxyPort: parseInt(proxyPort, 10),    
      dohUpstreamUrl: env.DOH_UPSTREAM_URL || this.defaultDoHUpstream,    
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
      const url = new URL(request.url);    
      const cfg = Config.fromEnv(env);    
    
      // Route for WebSocket (VLESS) connections    
      if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {    
        return handleWebSocket(request, env, ctx);    
      }    
    
      // Handle DNS-over-HTTPS requests    
      if (url.pathname === '/dns-query' && (request.method === 'POST' || request.method === 'GET')) {    
        return handleDnsQuery(request, cfg.dohUpstreamUrl);    
      }    
    
      // Route for the smart network info API    
      if (url.pathname === '/api/network-info') {    
        return handleNetworkInfo(request, cfg);    
      }    
    
      // Routes for Admin Panel, Subscriptions, etc.    
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
    
// --- DNS-OVER-HTTPS (DoH) PROXY FUNCTION ---    
async function handleDnsQuery(request, upstreamUrl) {    
  const url = new URL(request.url);    
  const upstreamWithQuery = new URL(upstreamUrl);    
  upstreamWithQuery.search = url.search;    
    
  const dohRequest = new Request(upstreamWithQuery, {    
    method: request.method,    
    headers: {    
        'Content-Type': 'application/dns-message',    
        'Accept': 'application/dns-message',    
        'User-Agent': request.headers.get('User-Agent') || 'Cloudflare-Worker-DoH-Proxy'    
    },    
    body: request.method === 'POST' ? request.body : null,    
  });    
    
  try {    
    const dohResponse = await fetch(dohRequest);    
    return dohResponse;    
  } catch (e) {    
    console.error('DoH proxy failed:', e);    
    return new Response('DNS query proxy failed', { status: 502 });    
  }    
}    
    
// --- SMART API ENDPOINT FOR NETWORK INFO ---    
async function handleNetworkInfo(request, config) {    
    const clientIp = request.headers.get('CF-Connecting-IP');    
    const proxyHost = config.proxyIP;    
    
    const getIpDetails = async (ip) => {    
        if (!ip) return null;    
        try {    
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
    
    const getScamalyticsDetails = async (ip) => {    
        if (!ip || !config.scamalytics.apiKey || !config.scamalytics.username) return null;    
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
    
    const [clientDetails, proxyDetails, scamalyticsData] = await Promise.all([    
        getIpDetails(clientIp),    
        getIpDetails(proxyHost),    
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
    
    
// --- WEBSOCKET & PROXY LOGIC ---    
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
      
      // *** MERGED FEATURE: INTELLIGENT UDP HANDLING *** // Cloudflare Workers do not support outbound UDP sockets. VLESS UDP packets will be    
      // forwarded over a TCP connection to the destination, which works for many use-cases.    
      if (isUDP) {    
        log(`UDP request for ${addressRemote}:${portRemote} received. Forwarding over TCP.`);    
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
    log('Connecting to destination...');    
    const remoteSocket = await connect({ hostname: addressRemote, port: portRemote });    
    log('Connection successful.');    
    
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
    
// --- VLESS & UTILITY FUNCTIONS ---    
async function processVlessHeader(vlessBuffer, env, ctx) {    
  if (vlessBuffer.byteLength < 24) return { hasError: true, message: 'Invalid VLESS header' };    
  const dataView = new DataView(vlessBuffer);    
  const version = dataView.getUint8(0);    
  const uuid = stringify(new Uint8Array(vlessBuffer.slice(1, 17)));    
    
  if (!await isValidUser(uuid, env, ctx)) return { hasError: true, message: 'Invalid user' };    
    
  const optLength = dataView.getUint8(17);    
  const command = dataView.getUint8(18 + optLength); // 1=TCP, 2=UDP, 3=MUX    
  const portIndex = 18 + optLength + 1;    
  const portRemote = dataView.getUint16(portIndex);    
  const addressType = dataView.getUint8(portIndex + 2);    
    
  let addressRemote, rawDataIndex;    
  switch (addressType) {    
    case 1: // IPv4    
      addressRemote = new Uint8Array(vlessBuffer.slice(portIndex + 3, portIndex + 7)).join('.');    
      rawDataIndex = portIndex + 7;    
      break;    
    case 2: // Domain    
      const addressLength = dataView.getUint8(portIndex + 3);    
      addressRemote = new TextDecoder().decode(vlessBuffer.slice(portIndex + 4, portIndex + 4 + addressLength));    
      rawDataIndex = portIndex + 4 + addressLength;    
      break;    
    case 3: // IPv6    
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
      webSocket.addEventListener('message', (event) => {    
        if (readableStreamCancel) return;    
        controller.enqueue(event.data);    
      });    
      webSocket.addEventListener('close', () => {    
        if (readableStreamCancel) return;    
        controller.close();    
      });    
      webSocket.addEventListener('error', (err) => {    
        if (readableStreamCancel) return;    
        log('WebSocket error', err);    
        controller.error(err);    
      });    
      const { earlyData: parsedEarlyData, error } = base64ToArrayBuffer(earlyData);    
      if (error) {    
        controller.error(error);    
      } else if (parsedEarlyData) {    
        controller.enqueue(parsedEarlyData);    
      }    
    },    
    pull() {},    
    cancel(reason) {    
      log(`ReadableStream cancelled`, reason);    
      readableStreamCancel = true;    
      safeCloseWebSocket(webSocket);    
    },    
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
    
// --- ALL OTHER FUNCTIONS (Admin, UI, Subscriptions) ---    
    
function generateRandomPath(length = 12, query = '') {    
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';    
  let result = '';    
  for (let i = 0; i < length; i++) {    
    result += chars.charAt(Math.floor(Math.random() * chars.length));    
  }    
  return `/${result}${query ? `?${query}` : ''}`;    
}    
    
const CORE_PRESETS = {    
  xray: {    
    tls: { path: () => generateRandomPath(12, 'ed=2048'), security: 'tls', fp: 'chrome', alpn: 'http/1.1', extra: {} },    
    tcp: { path: () => generateRandomPath(12, 'ed=2048'), security: 'none', fp: 'chrome', extra: {} },    
  },    
  sb: {    
    tls: { path: () => generateRandomPath(18), security: 'tls', fp: 'firefox', alpn: 'h3', extra: {ed: 2560} },    
    tcp: { path: () => generateRandomPath(18), security: 'none', fp: 'firefox', extra: {ed: 2560} },    
  },    
};    
    
function makeName(tag, proto) {    
  return `${tag}-${proto.toUpperCase()}`;    
}    
    
function createVlessLink({ userID, address, port, host, path, security, sni, fp, alpn, extra = {}, name }) {    
  const params = new URLSearchParams({ type: 'ws', host, path });    
  if (security) params.set('security', security);    
  if (sni) params.set('sni', sni);    
  if (fp) params.set('fp', fp);    
  if (alpn) params.set('alpn', alpn);    
  for (const [k, v] of Object.entries(extra)) params.set(k, v);    
  return `vless://${userID}@${address}:${port}?${params.toString()}#${encodeURIComponent(name)}`;    
}    
    
function buildLink({ core, proto, userID, hostName, address, port, tag }) {    
  const p = CORE_PRESETS[core][proto];    
  return createVlessLink({    
    userID,    
    address,    
    port,    
    host: hostName,    
    path: p.path(),    
    security: p.security,    
    sni: p.security === 'tls' ? hostName : undefined,    
    fp: p.fp,    
    alpn: p.alpn,    
    extra: p.extra,    
    name: makeName(tag, proto),    
  });    
}    
    
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];    
    
async function handleIpSubscription(core, userID, hostName) {    
  const mainDomains = [    
    hostName, 'creativecommons.org', 'www.speedtest.net',    
    'sky.rethinkdns.com', 'cf.090227.xyz', 'cdnjs.com', 'zula.ir',    
    'cfip.1323123.xyz',    
    'go.inmobi.com', 'singapore.com', 'www.visa.com',    
  ];    
  const httpsPorts = [443, 8443, 2053, 2083, 2087, 2096];    
  const httpPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095];    
  let links = [];    
  const isPagesDeployment = hostName.endsWith('.pages.dev');    
  mainDomains.forEach((domain, i) => {    
    links.push(buildLink({ core, proto: 'tls', userID, hostName, address: domain, port: pick(httpsPorts), tag: `D${i + 1}` }));    
    if (!isPagesDeployment) {    
      links.push(buildLink({ core, proto: 'tcp', userID, hostName, address: domain, port: pick(httpPorts), tag: `D${i + 1}` }));    
    }    
  });    
  try {    
    const r = await fetch('https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/Cloudflare-IPs.json');    
    if (r.ok) {    
      const json = await r.json();    
      const ips = [...(json.ipv4 || []), ...(json.ipv6 || [])].slice(0, 20).map(x => x.ip);    
      ips.forEach((ip, i) => {    
        const formattedAddress = ip.includes(':') ? `[${ip}]` : ip;    
        links.push(buildLink({ core, proto: 'tls', userID, hostName, address: formattedAddress, port: pick(httpsPorts), tag: `IP${i + 1}` }));    
        if (!isPagesDeployment) {    
          links.push(buildLink({ core, proto: 'tcp', userID, hostName, address: formattedAddress, port: pick(httpPorts), tag: `IP${i + 1}` }));    
        }    
      });    
    }    
  } catch (e) { console.error('Failed to fetch IP list:', e); }    
  return new Response(btoa(links.join('\n')), { headers: { 'Content-Type': 'text/plain;charset=utf-8' } });    
}    
    
// --- ADMIN PANEL API & UI ---    
async function handleAdminRoutes(request, env) {    
  const url = new URL(request.url);    
  const path = url.pathname.replace('/admin', '');    
    
  if (request.method === 'GET' && (path === '/login' || path === '/')) {    
    return new Response(getAdminLoginHTML(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });    
  }    
    
  if (request.method === 'GET' && path === '/dashboard') {    
    return new Response(getAdminDashboardHTML(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });    
  }    
    
  const authKey = request.headers.get('Authorization');    
  if (authKey !== env.ADMIN_KEY) {    
    return Response.json({ error: 'Unauthorized' }, { status: 401 });    
  }    
    
  try {    
    if (request.method === 'POST' && path === '/api/users') {    
      const body = await request.json();    
      const { id, expiration_date, expiration_time, notes = '' } = body;    
      if (!id || !expiration_date || !expiration_time || !isValidUUID(id)) {    
        return Response.json({ error: 'Missing or invalid parameters' }, { status: 400 });    
      }    
      const expirationTimestamp = Math.floor(new Date(`${expiration_date}T${expiration_time}:00Z`).getTime() / 1000);    
      const now = Math.floor(Date.now() / 1000);    
    
      await env.DB.prepare(    
        'INSERT INTO users (id, expiration_timestamp, created_at, last_accessed, status, notes, admin_key) VALUES (?, ?, ?, ?, ?, ?, ?)'    
      ).bind(id, expirationTimestamp, now, now, 'active', notes || null, authKey).run();    
    
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
    console.error('Admin API Error:', e);    
    return Response.json({ error: `An internal server error occurred: ${e.message}` }, { status: 500 });    
  }    
    
  return new Response('Admin endpoint not found', { status: 404 });    
}    
    
// --- HTML PAGE GENERATION ---    
function handleConfigPage(userID, hostName, proxyAddress) {    
  const html = generateBeautifulConfigPage(userID, hostName, proxyAddress);    
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });    
}    
    
function generateBeautifulConfigPage(userID, hostName, proxyAddress) {    
  const dream = buildLink({    
    core: 'xray', proto: 'tls', userID, hostName,    
    address: hostName, port: 443, tag: `${hostName}-Xray`,    
  });    
    
  const freedom = buildLink({    
    core: 'sb', proto: 'tls', userID, hostName,    
    address: hostName, port: 443, tag: `${hostName}-Singbox`,    
  });    
    
  const configs = { dream, freedom };    
  const subXrayUrl = `https://${hostName}/xray/${userID}`;    
  const subSbUrl = `https://${hostName}/sb/${userID}`;    
    
  const clientUrls = {    
    clashMeta: `clash://install-config?url=${encodeURIComponent(`https://revil-sub.pages.dev/sub/clash-meta?url=${subSbUrl}&remote_config=&udp=false&ss_uot=false&show_host=false&forced_ws0rtt=true`)}`,    
    hiddify: `hiddify://install-config?url=${encodeURIComponent(subXrayUrl)}`,    
    v2rayng: `v2rayng://install-config?url=${encodeURIComponent(subXrayUrl)}`,    
    exclave: `sn://subscription?url=${encodeURIComponent(subSbUrl)}`,    
  };    
    
  let finalHTML = `    
  <!doctype html>    
  <html lang="en">    
  <head>    
    <meta charset="UTF-8" />    
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />    
    <title>VLESS Proxy Configuration</title>    
    <link rel="icon" href="https://raw.githubusercontent.com/NiREvil/zizifn/refs/heads/Legacy/assets/favicon.png" type="image/png">    
    <link rel="preconnect" href="https://fonts.googleapis.com">    
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>    
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@300..700&display=swap" rel="stylesheet">    
    <style>${getPageCSS()}</style>    
  </head>    
  <body data-proxy-ip="${proxyAddress}">    
    ${getPageHTML(configs, clientUrls)}    
    <script>${getPageScript()}</script>    
  </body>    
  </html>`;    
    
  return finalHTML;    
}    
    
function getAdminLoginHTML() {    
  return `<!DOCTYPE html><html><head><title>Admin Login</title><style>body{display:flex;justify-content:center;align-items:center;height:100vh;background:#1a1a1a;font-family:sans-serif;margin:0;}div{padding:2rem;background:#2a2a2a;border-radius:8px;color:white;text-align:center;}input,button{width:100%;padding:10px;margin-top:10px;border-radius:5px;border:1px solid #444;background:#333;color:white;box-sizing:border-box;}button{cursor:pointer;background:#007bff;}p{color:red;}</style></head><body><div><h2>Admin Login</h2><input type="password" id="admin-key" placeholder="Enter Admin Key"><button onclick="login()">Login</button><p id="error-message"></p></div><script>    
    async function login() {    
        const key = document.getElementById('admin-key').value;    
        const errorP = document.getElementById('error-message');    
        errorP.textContent = '';    
        if (!key) {    
            errorP.textContent = 'Key cannot be empty.';    
            return;    
        }    
        try {    
            const response = await fetch('/admin/api/users', {    
                headers: { 'Authorization': key }    
            });    
            if (response.ok) {    
                localStorage.setItem('admin_key', key);    
                window.location.href = '/admin/dashboard';    
            } else if (response.status === 401) {    
                errorP.textContent = 'Invalid Key. Access Denied.';    
            } else {    
                errorP.textContent = 'An unknown error occurred.';    
            }    
        } catch (err) {    
            errorP.textContent = 'Failed to connect to the server.';    
        }    
    }    
    document.getElementById('admin-key').addEventListener('keyup', (event) => { if (event.key === 'Enter') login(); });    
  </script></body></html>`;    
}    
    
function getAdminDashboardHTML() {    
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Admin Dashboard</title><style>body{background:#1a1a1a;font-family:sans-serif;color:#fff;padding:20px;}.dashboard{max-width:900px;margin:auto;background:#2a2a2a;border-radius:15px;padding:20px;}h1,h2{text-align:center;}.create-section{background:#333;padding:15px;border-radius:10px;margin-bottom:20px;}input,button{padding:8px;margin:5px;border:none;border-radius:5px;background:#444;color:#fff;}button{background:#007bff;cursor:pointer;}table{width:100%;border-collapse:collapse;}th,td{padding:10px;text-align:left;border-bottom:1px solid #444;word-break:break-all;}.expired{color:#ff5252;}</style></head><body><div class="dashboard"><h1>Admin Dashboard</h1><div class="create-section"><h2>Create User</h2><input type="text" id="new-id" placeholder="User ID (UUID)"><button onclick="generateUUID()">Generate</button><input type="date" id="exp-date"><input type="time" id="exp-time"><input type="text" id="notes" placeholder="Notes"><button onclick="createUser()">Create</button></div><div class="user-list"><h2>User List</h2><table id="user-table"><thead><tr><th>ID</th><th>Expiry</th><th>Created</th><th>Status</th><th>Notes</th><th>Actions</th></tr></thead><tbody></tbody></table></div></div><script>    
    const adminKey = localStorage.getItem('admin_key');    
    if (!adminKey) window.location.href = '/admin/login';    
    const apiHeaders = { 'Content-Type': 'application/json', 'Authorization': adminKey };    
    async function apiFetch(endpoint, options={}){const res=await fetch('/admin/api'+endpoint,{...options,headers:apiHeaders});if(res.status===401){alert('Unauthorized!');window.location.href='/admin/login';}return res;}    
    function generateUUID(){document.getElementById('new-id').value=crypto.randomUUID();}    
    async function createUser(){const id=document.getElementById('new-id').value;const date=document.getElementById('exp-date').value;const time=document.getElementById('exp-time').value;const notes=document.getElementById('notes').value;if(!id||!date||!time)return alert('Fill required fields.');const res=await apiFetch('/users',{method:'POST',body:JSON.stringify({id,expiration_date:date,expiration_time:time,notes})});if(res.ok){alert('User created!');loadUsers();}else{alert('Error creating user.');}}    
    async function loadUsers(){const res=await apiFetch('/users');const users=await res.json();const tbody=document.getElementById('user-table').querySelector('tbody');tbody.innerHTML='';const now=Date.now()/1000;users.forEach(u=>{const expiry=new Date(u.expiration_timestamp*1000).toLocaleString();const created=new Date(u.created_at*1000).toLocaleDateString();const statusClass=u.expiration_timestamp>now&&u.status==='active'?'':'expired';tbody.innerHTML+=\`<tr><td>\${u.id}</td><td class="\${statusClass}">\${expiry}</td><td>\${created}</td><td class="\${statusClass}">\${u.status}</td><td>\${u.notes||''}</td><td><button onclick="deleteUser('\${u.id}')">Delete</button></td></tr>\`;});}    
    async function deleteUser(id){if(!confirm('Delete user?'))return;const res=await apiFetch(\`/users/\${id}\`,{method:'DELETE'});if(res.ok){alert('User deleted!');loadUsers();}else{alert('Error deleting user.');}}    
    window.onload=()=>{generateUUID();loadUsers();};    
  </script></body></html>`;    
}    
    
function getPageCSS() {    
  return `    
      * {    
        margin: 0;    
        padding: 0;    
        box-sizing: border-box;    
      }    
     @font-face {    
     font-family: "Aldine 401 BT Web";    
     src: url("https://pub-7a3b428c76aa411181a0f4dd7fa9064b.r2.dev/Aldine401_Mersedeh.woff2") format("woff2");    
     font-weight: 400; font-style: normal; font-display: swap;    
   }    
   @font-face {    
     font-family: "Styrene B LC";    
     src: url("https://pub-7a3b428c76aa411181a0f4dd7fa9064b.r2.dev/StyreneBLC-Regular.woff2") format("woff2");    
     font-weight: 400; font-style: normal; font-display: swap;    
   }    
   @font-face {    
     font-family: "Styrene B LC";    
     src: url("https://pub-7a3b428c76aa411181a0f4dd7fa9064b.r2.dev/StyreneBLC-Medium.woff2") format("woff2");    
     font-weight: 500; font-style: normal; font-display: swap;    
   }    
      :root {    
        --background-primary: #2a2421; --background-secondary: #35302c; --background-tertiary: #413b35;    
        --border-color: #5a4f45; --border-color-hover: #766a5f; --text-primary: #e5dfd6; --text-secondary: #b3a89d;    
        --text-accent: #ffffff; --accent-primary: #be9b7b; --accent-secondary: #d4b595; --accent-tertiary: #8d6e5c;    
        --accent-primary-darker: #8a6f56; --button-text-primary: #2a2421; --button-text-secondary: var(--text-primary);    
        --shadow-color: rgba(0, 0, 0, 0.35); --shadow-color-accent: rgba(190, 155, 123, 0.4);    
        --border-radius: 8px; --transition-speed: 0.2s; --transition-speed-fast: 0.1s; --transition-speed-medium: 0.3s; --transition-speed-long: 0.6s;    
        --status-success: #70b570; --status-error: #e05d44; --status-warning: #e0bc44; --status-info: #4f90c4;    
        --serif: "Aldine 401 BT Web", "Times New Roman", Times, Georgia, ui-serif, serif;    
     --sans-serif: "Styrene B LC", -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, "Noto Color Emoji", sans-serif;    
     --mono-serif: "Fira Code", Cantarell, "Courier Prime", monospace;    
   }    
      body {    
        font-family: var(--sans-serif); font-size: 16px; font-weight: 400; font-style: normal;    
        background-color: var(--background-primary); color: var(--text-primary);    
        padding: 3rem; line-height: 1.5; -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale;    
      }    
      .container {    
        max-width: 800px; margin: 20px auto; padding: 0 12px; border-radius: var(--border-radius);    
        box-shadow: 0 6px 15px rgba(0, 0, 0, 0.2), 0 0 25px 8px var(--shadow-color-accent);    
        transition: box-shadow var(--transition-speed-medium) ease;    
      }    
      .container:hover { box-shadow: 0 8px 20px rgba(0, 0, 0, 0.25), 0 0 35px 10px var(--shadow-color-accent); }    
      .header { text-align: center; margin-bottom: 40px; padding-top: 30px; }    
      .header h1 { font-family: var(--serif); font-weight: 400; font-size: 1.8rem; color: var(--text-accent); margin-top: 0px; margin-bottom: 2px; }    
      .header p { color: var(--text-secondary); font-size: 0.6rem; font-weight: 400; }    
      .config-card {    
        background: var(--background-secondary); border-radius: var(--border-radius); padding: 20px; margin-bottom: 24px;    
        border: 1px solid var(--border-color);    
        transition: border-color var(--transition-speed) ease, box-shadow var(--transition-speed) ease;    
      }    
      .config-card:hover { border-color: var(--border-color-hover); box-shadow: 0 4px 8px var(--shadow-color); }    
      .config-title {    
        font-family: var(--serif); font-size: 1.6rem; font-weight: 400; color: var(--accent-secondary);    
        margin-bottom: 16px; padding-bottom: 13px; border-bottom: 1px solid var(--border-color);    
        display: flex; align-items: center; justify-content: space-between;    
      }    
      .config-title .refresh-btn {    
        position: relative; overflow: hidden; display: flex; align-items: center; gap: 4px;    
        font-family: var(--serif); font-size: 12px; padding: 6px 12px; border-radius: 6px;    
        color: var(--accent-secondary); background-color: var(--background-tertiary); border: 1px solid var(--border-color);    
        cursor: pointer;    
        transition: background-color var(--transition-speed) ease, border-color var(--transition-speed) ease, color var(--transition-speed) ease, transform var(--transition-speed) ease, box-shadow var(--transition-speed) ease;    
      }    
      .config-title .refresh-btn::before {    
        content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 100%;    
        background: linear-gradient(120deg, transparent, rgba(255, 255, 255, 0.2), transparent);    
        transform: translateX(-100%); transition: transform var(--transition-speed-long) ease; z-index: 1;    
      }    
      .config-title .refresh-btn:hover {    
        letter-spacing: 0.5px; font-weight: 600; background-color: #4d453e; color: var(--accent-primary);    
        border-color: var(--border-color-hover); transform: translateY(-2px); box-shadow: 0 4px 8px var(--shadow-color);    
      }    
      .config-title .refresh-btn:hover::before { transform: translateX(100%); }    
      .config-title .refresh-btn:active { transform: translateY(0px) scale(0.98); box-shadow: none; }    
      .refresh-icon { width: 12px; height: 12px; stroke: currentColor; }    
      .config-content {    
        position: relative; background: var(--background-tertiary); border-radius: var(--border-radius);    
        padding: 16px; margin-bottom: 20px; border: 1px solid var(--border-color);    
      }    
      .config-content pre {    
        overflow-x: auto; font-family: var(--mono-serif); font-size: 7px; color: var(--text-primary);    
        margin: 0; white-space: pre-wrap; word-break: break-all;    
      }    
      .button {    
        display: inline-flex; align-items: center; justify-content: center; gap: 8px;    
        padding: 8px 16px; border-radius: var(--border-radius); font-size: 15px; font-weight: 500;    
        cursor: pointer; border: 1px solid var(--border-color); background-color: var(--background-tertiary);    
        color: var(--button-text-secondary);    
        transition: background-color var(--transition-speed) ease, border-color var(--transition-speed) ease, color var(--transition-speed) ease, transform var(--transition-speed) ease, box-shadow var(--transition-speed) ease;    
        -webkit-tap-highlight-color: transparent; touch-action: manipulation; text-decoration: none; overflow: hidden; z-index: 1;    
      }    
      .button:focus-visible { outline: 2px solid var(--accent-primary); outline-offset: 2px; }    
      .button:disabled { opacity: 0.6; cursor: not-allowed; transform: none; box-shadow: none; transition: opacity var(--transition-speed) ease; }    
      .copy-buttons {    
        position: relative; display: flex; gap: 4px; overflow: hidden; align-self: center;    
        font-family: var(--serif); font-size: 13px; padding: 6px 12px; border-radius: 6px;    
        color: var(--accent-secondary); border: 1px solid var(--border-color);    
        transition: background-color var(--transition-speed) ease, border-color var(--transition-speed) ease, color var(--transition-speed) ease, transform var(--transition-speed) ease, box-shadow var(--transition-speed) ease;    
      }    
      .copy-buttons::before, .client-btn::before {    
        content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 100%;    
        background: linear-gradient(120deg, transparent, rgba(255, 255, 255, 0.2), transparent);    
        transform: translateX(-100%); transition: transform var(--transition-speed-long) ease; z-index: -1;    
      }    
      .copy-buttons:hover::before, .client-btn:hover::before { transform: translateX(100%); }    
      .copy-buttons:hover {    
        background-color: #4d453e; letter-spacing: 0.5px; font-weight: 600;    
        border-color: var(--border-color-hover); transform: translateY(-2px); box-shadow: 0 4px 8px var(--shadow-color);    
      }    
      .copy-buttons:active { transform: translateY(0px) scale(0.98); box-shadow: none; }    
      .copy-icon { width: 12px; height: 12px; stroke: currentColor; }    
      .client-buttons { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; margin-top: 16px; }    
      .client-btn {    
        width: 100%; background-color: var(--accent-primary); color: var(--background-tertiary);    
        border-radius: 6px; border-color: var(--accent-primary-darker); position: relative; overflow: hidden;    
        transition: all 0.3s cubic-bezier(0.2, 0.8, 0.2, 1); box-shadow: 0 2px 5px rgba(0, 0, 0, 0.15);    
      }    
      .client-btn::after {    
        content: ''; position: absolute; bottom: -5px; left: 0; width: 100%; height: 5px;    
        background: linear-gradient(90deg, var(--accent-tertiary), var(--accent-secondary));    
        opacity: 0; transition: all 0.3s ease; z-index: 0;    
      }    
      .client-btn:hover {    
        text-transform: uppercase; letter-spacing: 0.3px; transform: translateY(-3px);    
        background-color: var(--accent-secondary); color: var(--button-text-primary);    
        box-shadow: 0 5px 15px rgba(190, 155, 123, 0.5); border-color: var(--accent-secondary);    
      }    
      .client-btn:hover::after { opacity: 1; bottom: 0; }    
      .client-btn:active { transform: translateY(0) scale(0.98); box-shadow: 0 2px 3px rgba(0, 0, 0, 0.2); background-color: var(--accent-primary-darker); }    
      .client-btn .client-icon { position: relative; z-index: 2; transition: transform 0.3s ease; }    
      .client-btn:hover .client-icon { transform: rotate(15deg) scale(1.1); }    
      .client-btn .button-text { position: relative; z-index: 2; transition: letter-spacing 0.3s ease; }    
      .client-btn:hover .button-text { letter-spacing: 0.5px; }    
   .client-icon { width: 18px; height: 18px; border-radius: 6px; background-color: var(--background-secondary); display: flex; align-items: center; justify-content: center; flex-shrink: 0; }    
   .client-icon svg { width: 14px; height: 14px; fill: var(--accent-secondary); }    
   .button.copied { background-color: var(--accent-secondary) !important; color: var(--background-tertiary) !important; }    
   .button.error { background-color: #c74a3b !important; color: var(--text-accent) !important; }    
   .footer { text-align: center; margin-top: 20px; padding-bottom: 40px; color: var(--text-secondary); font-size: 8px; }    
   .footer p { margin-bottom: 0px; }    
   ::-webkit-scrollbar { width: 8px; height: 8px; }    
   ::-webkit-scrollbar-track { background: var(--background-primary); border-radius: 4px; }    
   ::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 4px; border: 2px solid var(--background-primary); }    
   ::-webkit-scrollbar-thumb:hover { background: var(--border-color-hover); }    
   * { scrollbar-width: thin; scrollbar-color: var(--border-color) var(--background-primary); }    
   .ip-info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 24px; }    
   .ip-info-section { background-color: var(--background-tertiary); border-radius: var(--border-radius); padding: 16px; border: 1px solid var(--border-color); display: flex; flex-direction: column; gap: 20px; }    
   .ip-info-header { display: flex; align-items: center; gap: 10px; border-bottom: 1px solid var(--border-color); padding-bottom: 10px; }    
   .ip-info-header svg { width: 20px; height: 20px; stroke: var(--accent-secondary); }    
   .ip-info-header h3 { font-family: var(--serif); font-size: 18px; font-weight: 400; color: var(--accent-secondary); margin: 0; }    
   .ip-info-content { display: flex; flex-direction: column; gap: 10px; }    
   .ip-info-item { display: flex; flex-direction: column; gap: 2px; }    
   .ip-info-item .label { font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; }    
   .ip-info-item .value { font-size: 14px; color: var(--text-primary); word-break: break-all; line-height: 1.4; }    
   .badge { display: inline-flex; align-items: center; justify-content: center; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px; }    
   .badge-yes { background-color: rgba(112, 181, 112, 0.15); color: var(--status-success); border: 1px solid rgba(112, 181, 112, 0.3); }    
   .badge-no { background-color: rgba(224, 93, 68, 0.15); color: var(--status-error); border: 1px solid rgba(224, 93, 68, 0.3); }    
   .badge-neutral { background-color: rgba(79, 144, 196, 0.15); color: var(--status-info); border: 1px solid rgba(79, 144, 196, 0.3); }    
   .badge-warning { background-color: rgba(224, 188, 68, 0.15); color: var(--status-warning); border: 1px solid rgba(224, 188, 68, 0.3); }    
   .skeleton { display: block; background: linear-gradient(90deg, var(--background-tertiary) 25%, var(--background-secondary) 50%, var(--background-tertiary) 75%); background-size: 200% 100%; animation: loading 1.5s infinite; border-radius: 4px; height: 16px; }    
   @keyframes loading { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }    
   .country-flag { display: inline-block; width: 18px; height: auto; max-height: 14px; margin-right: 6px; vertical-align: middle; border-radius: 2px; }    
   @media (max-width: 768px) {    
     body { padding: 20px; } .container { padding: 0 14px; width: min(100%, 768px); }    
     .ip-info-grid { grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 18px; }    
     .header h1 { font-size: 1.8rem; } .header p { font-size: 0.7rem }    
     .ip-info-section { padding: 14px; gap: 18px; } .ip-info-header h3 { font-size: 16px; }    
     .ip-info-header { gap: 8px; } .ip-info-content { gap: 8px; }    
     .ip-info-item .label { font-size: 11px; } .ip-info-item .value { font-size: 13px; }    
     .config-card { padding: 16px; } .config-title { font-size: 18px; }    
     .config-title .refresh-btn { font-size: 11px; } .config-content pre { font-size: 12px; }    
     .client-buttons { grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); }    
     .button { font-size: 12px; } .copy-buttons { font-size: 11px; }    
   }    
   @media (max-width: 480px) {    
     body { padding: 16px; } .container { padding: 0 12px; width: min(100%, 390px); }    
     .header h1 { font-size: 20px; } .header p { font-size: 8px; }    
     .ip-info-section { padding: 14px; gap: 16px; }    
     .ip-info-grid { grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; }    
     .ip-info-header h3 { font-size: 14px; } .ip-info-header { gap: 6px; } .ip-info-content { gap: 6px; }    
     .ip-info-item .label { font-size: 9px; } .ip-info-item .value { font-size: 11px; }    
     .badge { padding: 2px 6px; font-size: 10px; border-radius: 10px; }    
     .config-card { padding: 10px; } .config-title { font-size: 16px; }    
     .config-title .refresh-btn { font-size: 10px; } .config-content { padding: 12px; }    
     .config-content pre { font-size: 10px; }    
     .client-buttons { grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); }    
     .button { padding: 4px 8px; font-size: 11px; } .copy-buttons { font-size: 10px; }    
     .footer { font-size: 10px; }    
   }    
   @media (max-width: 359px) {    
         body { padding: 12px; font-size: 14px; } .container { max-width: 100%; padding: 8px; }    
         .header h1 { font-size: 16px; } .header p { font-size: 6px; }    
         .ip-info-section { padding: 12px; gap: 12px; }    
         .ip-info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }    
         .ip-info-header h3 { font-size: 13px; } .ip-info-header { gap: 4px; } .ip-info-content { gap: 4px; }    
         .ip-info-header svg { width: 16px; height: 16px; } .ip-info-item .label { font-size: 8px; }    
 .ip-info-item .value { font-size: 10px; } .badge { padding: 1px 4px; font-size: 9px; border-radius: 8px; }    
         .config-card { padding: 8px; } .config-title { font-size: 13px; } .config-title .refresh-btn { font-size: 9px; }    
         .config-content { padding: 8px; } .config-content pre { font-size: 8px; }    
 .client-buttons { grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); }    
         .button { padding: 3px 6px; font-size: 10px; } .copy-buttons { font-size: 9px; } .footer { font-size: 7px; }    
       }    
    
       @media (min-width: 360px) { .container { max-width: 95%; } }    
       @media (min-width: 480px) { .container { max-width: 90%; } }    
       @media (min-width: 640px) { .container { max-width: 600px; } }    
       @media (min-width: 768px) { .container { max-width: 720px; } }    
       @media (min-width: 1024px) { .container { max-width: 800px; } }    
  `;    
}    
    
function getPageHTML(configs, clientUrls) {    
  return `    
    <div class="container">    
      <div class="header">    
        <h1>VLESS Proxy Configuration</h1>    
        <p>Copy the configuration or import directly into your client</p>    
      </div>    
    
      <div class="config-card">    
        <div class="config-title">    
          <span>Network Information</span>    
          <button id="refresh-ip-info" class="refresh-btn" aria-label="Refresh IP information">    
            <svg class="refresh-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">    
              <path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2" />    
            </svg>    
            Refresh    
          </button>    
        </div>    
        <div class="ip-info-grid">    
          <div class="ip-info-section">    
            <div class="ip-info-header">    
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">    
                <path d="M15.5 2H8.6c-.4 0-.8.2-1.1.5-.3.3-.5.7-.5 1.1v16.8c0 .4.2.8.5 1.1.3.3.7.5 1.1.5h6.9c.4 0 .8-.2 1.1-.5.3-.3.5-.7.5-1.1V3.6c0-.4-.2-.8-.5-1.1-.3-.3-.7-.5-1.1-.5z" />    
                <circle cx="12" cy="18" r="1" />    
              </svg>    
              <h3>Proxy Server</h3>    
            </div>    
            <div class="ip-info-content">    
              <div class="ip-info-item"><span class="label">Proxy Host</span><span class="value" id="proxy-host"><span class="skeleton" style="width: 150px"></span></span></div>    
              <div class="ip-info-item"><span class="label">IP Address</span><span class="value" id="proxy-ip"><span class="skeleton" style="width: 120px"></span></span></div>    
              <div class="ip-info-item"><span class="label">Location</span><span class="value" id="proxy-location"><span class="skeleton" style="width: 100px"></span></span></div>    
              <div class="ip-info-item"><span class="label">ISP Provider</span><span class="value" id="proxy-isp"><span class="skeleton" style="width: 140px"></span></span></div>    
            </div>    
          </div>    
          <div class="ip-info-section">    
            <div class="ip-info-header">    
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">    
                <path d="M20 16V7a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v9m16 0H4m16 0 1.28 2.55a1 1 0 0 1-.9 1.45H3.62a1 1 0 0 1-.9-1.45L4 16" />    
              </svg>    
              <h3>Your Connection</h3>    
            </div>    
            <div class="ip-info-content">    
              <div class="ip-info-item"><span class="label">Your IP</span><span class="value" id="client-ip"><span class="skeleton" style="width: 110px"></span></span></div>    
              <div class="ip-info-item"><span class="label">Location</span><span class="value" id="client-location"><span class="skeleton" style="width: 90px"></span></span></div>    
              <div class="ip-info-item"><span class="label">ISP Provider</span><span class="value" id="client-isp"><span class="skeleton" style="width: 130px"></span></span></div>    
              <div class="ip-info-item"><span class="label">Risk Score</span><span class="value" id="client-proxy"><span class="skeleton" style="width: 100px"></span></span></div>    
            </div>    
          </div>    
        </div>    
      </div>    
    
      <div class="config-card">    
        <div class="config-title">    
          <span>Xray Core Clients</span>    
          <button class="button copy-buttons" onclick="copyToClipboard(this, '${configs.dream}')">    
            <svg class="copy-icon" xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>    
            Copy    
          </button>    
        </div>    
        <div class="config-content"><pre id="xray-config">${configs.dream}</pre></div>    
        <div class="client-buttons">    
          <a href="${clientUrls.hiddify}" class="button client-btn">    
            <span class="client-icon"><svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" /></svg></span>    
            <span class="button-text">Import to Hiddify</span>    
          </a>    
          <a href="${clientUrls.v2rayng}" class="button client-btn">    
            <span class="client-icon"><svg viewBox="0 0 24 24"><path d="M12 2L4 5v6c0 5.5 3.5 10.7 8 12.3 4.5-1.6 8-6.8 8-12.3V5l-8-3z" /></svg></span>    
            <span class="button-text">Import to V2rayNG</span>    
          </a>    
        </div>    
      </div>    
    
      <div class="config-card">    
        <div class="config-title">    
          <span>Sing-Box Core Clients</span>    
          <button class="button copy-buttons" onclick="copyToClipboard(this, '${configs.freedom}')">    
            <svg class="copy-icon" xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>    
            Copy    
          </button>    
        </div>    
        <div class="config-content"><pre id="singbox-config">${configs.freedom}</pre></div>    
        <div class="client-buttons">    
          <a href="${clientUrls.clashMeta}" class="button client-btn">    
            <span class="client-icon"><svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" /></svg></span>    
            <span class="button-text">Import to Clash Meta</span>    
          </a>    
          <a href="${clientUrls.exclave}" class="button client-btn">    
            <span class="client-icon"><svg viewBox="0 0 24 24"><path d="M20,8h-3V6c0-1.1-0.9-2-2-2H9C7.9,4,7,4.9,7,6v2H4C2.9,8,2,8.9,2,10v9c0,1.1,0.9,2,2,2h16c1.1,0,2-0.9,2-2v-9 C22,8.9,21.1,8,20,8z M9,6h6v2H9V6z M20,19H4v-2h16V19z M20,15H4v-5h3v1c0,0.55,0.45,1,1,1h1.5c0.28,0,0.5-0.22,0.5-0.5v-0.5h4v0.5 c0,0.28,0.22,0.5,0.5,0.5H16c0.55,0,1-0.45,1-1v-1h3V15z" /><circle cx="8.5" cy="13.5" r="1" /><circle cx="15.5" cy="13.5" r="1" /><path d="M12,15.5c-0.55,0-1-0.45-1-1h2C13,15.05,12.55,15.5,12,15.5z" /></svg></span>    
            <span class="button-text">Import to Exclave</span>    
          </a>    
        </div>    
      </div>    
    
      <div class="footer">    
        <p>© <span id="current-year">${new Date().getFullYear()}</span> REvil - All Rights Reserved</p>    
        <p>Secure. Private. Fast.</p>    
      </div>    
    </div>    
  `;    
}    
    
function getPageScript() {    
  return `    
      function copyToClipboard(button, text) {    
        const originalHTML = button.innerHTML;    
        navigator.clipboard.writeText(text).then(() => {    
          button.innerHTML = \`<svg class="copy-icon" xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg> Copied!\`;    
          button.classList.add("copied");    
          button.disabled = true;    
          setTimeout(() => {    
            button.innerHTML = originalHTML;    
            button.classList.remove("copied");    
            button.disabled = false;    
          }, 1200);    
        }).catch(err => {    
          console.error("Failed to copy text: ", err);    
        });    
      }    
    
      function updateDisplay(data) {    
        // Update Proxy Info    
        const proxy = data.proxy || {};    
        document.getElementById('proxy-host').textContent = proxy.host || 'N/A';    
        document.getElementById('proxy-ip').textContent = proxy.ip || 'N/A';    
        document.getElementById('proxy-isp').textContent = proxy.isp || 'N/A';    
        const p_loc = [proxy.city, proxy.country].filter(Boolean).join(', ');    
        const p_flag = proxy.country ? \`<img src="https://flagcdn.com/w20/\${proxy.country.toLowerCase()}.png" class="country-flag" alt="\${proxy.country}"> \` : '';    
        document.getElementById('proxy-location').innerHTML = (p_loc) ? \`\${p_flag}\${p_loc}\` : 'N/A';    
    
        // Update Client Info    
        const client = data.client || {};    
        document.getElementById('client-ip').textContent = client.ip || 'N/A';    
        document.getElementById('client-isp').textContent = client.isp || 'N/A';    
        const c_loc = [client.city, client.country].filter(Boolean).join(', ');    
        const c_flag = client.country ? \`<img src="https://flagcdn.com/w20/\${client.country.toLowerCase()}.png" class="country-flag" alt="\${client.country}"> \` : '';    
        document.getElementById('client-location').innerHTML = (c_loc) ? \`\${c_flag}\${c_loc}\` : 'N/A';    
    
        // Update Risk Score Badge    
        const risk = client.risk;    
        let riskText = "Unknown";    
        let badgeClass = "badge-neutral";    
        if (risk && risk.score !== undefined) {    
            riskText = \`\${risk.score} - \${risk.risk.charAt(0).toUpperCase() + risk.risk.slice(1)}\`;    
            switch (risk.risk.toLowerCase()) {    
                case "low": badgeClass = "badge-yes"; break;    
                case "medium": badgeClass = "badge-warning"; break;    
                case "high": case "very high": badgeClass = "badge-no"; break;    
            }    
        }    
        document.getElementById('client-proxy').innerHTML = \`<span class="badge \${badgeClass}">\${riskText}</span>\`;    
      }    
    
      async function loadNetworkInfo() {    
        try {    
            const response = await fetch('/api/network-info');    
            if (!response.ok) throw new Error(\`API request failed with status \${response.status}\`);    
            const data = await response.json();    
            updateDisplay(data);    
        } catch (error) {    
            console.error('Failed to load network info:', error);    
            const errorData = { client: {}, proxy: { host: document.body.getAttribute('data-proxy-ip') } };    
            updateDisplay(errorData);    
        }    
      }    
    
      document.getElementById('refresh-ip-info')?.addEventListener('click', function() {    
        const button = this;    
        const icon = button.querySelector('.refresh-icon');    
        button.disabled = true;    
        if (icon) icon.style.animation = 'spin 1s linear infinite';    
    
        const resetToSkeleton = (prefix) => {    
          const elementsToReset = ['ip', 'location', 'isp'];    
          if (prefix === 'proxy') elementsToReset.push('host');    
          if (prefix === 'client') elementsToReset.push('proxy');    
          elementsToReset.forEach(key => {    
            const element = document.getElementById(\`\${prefix}-\${key}\`);    
            if (element) element.innerHTML = \`<span class="skeleton" style="width: 120px;"></span>\`;    
          });    
        };    
    
        resetToSkeleton('proxy');    
        resetToSkeleton('client');    
        loadNetworkInfo().finally(() => setTimeout(() => {    
          button.disabled = false; if (icon) icon.style.animation = '';    
        }, 500));    
      });    
    
      const style = document.createElement('style');    
      style.textContent = \`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }\`;    
      document.head.appendChild(style);    
    
      document.addEventListener('DOMContentLoaded', loadNetworkInfo);    
  `;    
}
