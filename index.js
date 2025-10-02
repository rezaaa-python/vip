// --------------------------------------------------------------------------------
// 🚀 Gemini-Enhanced VLESS Proxy Worker 🚀
// --------------------------------------------------------------------------------
// This intelligent script provides a robust VLESS proxy with an integrated
// DNS-over-HTTPS (DoH) resolver to fix connectivity issues, a dynamic network
// information panel, and a full-featured admin dashboard for user management.
//
// Main Features:
// - Fixes "DNS Probe" & "No Internet" errors by handling DNS via DoH.
// - Server-side rendered configuration page with easy setup instructions.
// - Smart API endpoint for real-time network and IP risk analysis.
// - Built-in Admin Panel for creating and managing users (requires D1 & KV).
// - Optimized for speed, security, and reliability on the Cloudflare network.
// --------------------------------------------------------------------------------

import { connect } from 'cloudflare:sockets';

// --- CONFIGURATION ---
// All settings are managed via Environment Variables in the Cloudflare dashboard for security.
const Config = {
    // Fallback/Relay server if PROXYIP environment variable is not set.
    defaultProxyIPs: ['nima.nscl.ir:443'],

    // Default upstream DoH server if DOH_UPSTREAM_URL environment variable is not set.
    defaultDoHUpstream: 'https://chrome.cloudflare-dns.com/dns-query',

    // Scamalytics API default settings
    scamalytics: {
        username: 'revilseptember',
        apiKey: 'b2fc368184deb3d8ac914bd776b8215fe899dd8fef69fbaba77511acfbdeca0d',
        baseUrl: 'https://api12.scamalytics.com/v3/',
    },

    // Function to read settings from environment variables (env)
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

            // Route for DNS-over-HTTPS (DoH) requests to fix connectivity
            if (url.pathname === '/dns-query' && ['POST', 'GET'].includes(request.method)) {
                return handleDnsQuery(request, cfg.dohUpstreamUrl);
            }

            // Route for the smart network info API
            if (url.pathname === '/api/network-info') {
                return handleNetworkInfo(request, cfg);
            }

            // --- Routes for Admin Panel & Subscriptions ---
            if (url.pathname.startsWith('/admin')) {
                 if (!env.DB || !env.KV || !env.ADMIN_KEY) {
                    return new Response('Admin panel is not configured. D1, KV, or ADMIN_KEY binding is missing.', { status: 503 });
                 }
                 if (!env.ADMIN_KEY) console.error('CRITICAL: ADMIN_KEY secret is not set in environment variables.');
                 return handleAdminRoutes(request, env);
            }

            const parts = url.pathname.slice(1).split('/');
            let userID;

            if ((parts[0] === 'xray' || parts[0] === 'sb') && parts.length > 1) {
                userID = parts[1];
            } else if (parts.length === 1 && isValidUUID(parts[0])) {
                userID = parts[0];
            }

            if (userID) {
                 if (env.DB && env.KV && !(await isValidUser(userID, env, ctx))) {
                    return new Response('Invalid or expired user ID.', { status: 403 });
                 }
                if (parts[0] === 'xray' || parts[0] === 'sb') {
                    return handleIpSubscription(parts[0], userID, url.hostname);
                }
                return handleConfigPage(userID, url.hostname, cfg.proxyAddress);
            }

            return new Response('Not Found. Please use your unique user ID in the URL path.', { status: 404 });

        } catch (err) {
            console.error('Unhandled Exception:', err.stack || err);
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
        if (!dohResponse.ok) {
            console.error(`DoH upstream error: ${dohResponse.status} ${dohResponse.statusText}`);
            return new Response('DNS upstream server returned an error.', { status: 502 });
        }
        return dohResponse;
    } catch (e) {
        console.error('DoH proxy failed:', e);
        return new Response('DNS query proxy failed.', { status: 502 });
    }
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

            if (isUDP) {
                log(`UDP traffic to ${addressRemote}:${portRemote} blocked. Configure client DNS to use this worker's /dns-query endpoint.`);
                return;
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

    if (env.DB && env.KV && !(await isValidUser(uuid, env, ctx))) {
         return { hasError: true, message: 'Invalid user' };
    }

    const optLength = dataView.getUint8(17);
    const command = dataView.getUint8(18 + optLength); // 1=TCP, 2=UDP
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
    const dohUrl = `https://${hostName}/dns-query`;

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
        ${getPageHTML(configs, clientUrls, dohUrl)}
        <script>${getPageScript()}</script>
    </body>
    </html>`;

    return finalHTML;
}

function getPageHTML(configs, clientUrls, dohUrl) {
    return `
    <div class="container">
        <div class="header">
            <h1>VLESS Proxy Configuration</h1>
            <p>Your secure connection is ready. Follow the steps below.</p>
        </div>

        <div class="config-card">
            <div class="config-title">
                <span>Step 1: Critical DNS Setup</span>
            </div>
            <p class="card-description">To prevent connection errors, copy this DNS link and set it as the "Remote DNS" or "DoH URL" in your VPN app's settings.</p>
            <div class="config-content"><pre id="doh-url">${dohUrl}</pre></div>
            <div class="button-group">
                <button class="button client-btn" onclick="copyToClipboard(this, '${dohUrl}')">
                    <span class="button-text">Copy DoH Link</span>
                </button>
            </div>
        </div>

        <div class="config-card">
            <div class="config-title">
                <span>Step 2: Xray Core Clients</span>
                <button class="button copy-buttons" onclick="copyToClipboard(this, '${configs.dream}')">Copy</button>
            </div>
            <div class="config-content"><pre>${configs.dream}</pre></div>
            <div class="client-buttons">
                <a href="${clientUrls.hiddify}" class="button client-btn">Import to Hiddify</a>
                <a href="${clientUrls.v2rayng}" class="button client-btn">Import to V2rayNG</a>
            </div>
        </div>

        <div class="config-card">
            <div class="config-title">
                <span>Step 2: Sing-Box Core Clients</span>
                <button class="button copy-buttons" onclick="copyToClipboard(this, '${configs.freedom}')">Copy</button>
            </div>
            <div class="config-content"><pre>${configs.freedom}</pre></div>
            <div class="client-buttons">
                <a href="${clientUrls.clashMeta}" class="button client-btn">Import to Clash Meta</a>
                <a href="${clientUrls.exclave}" class="button client-btn">Import to Exclave</a>
            </div>
        </div>

        <div class="config-card">
            <div class="config-title">
                <span>Network Information</span>
                <button id="refresh-ip-info" class="refresh-btn">Refresh</button>
            </div>
            <div class="ip-info-grid">
                <div class="ip-info-section">
                    <div class="ip-info-header"><h3>Proxy Server</h3></div>
                    <div class="ip-info-content">
                        <div class="ip-info-item"><span class="label">Host</span><span class="value" id="proxy-host"><span class="skeleton"></span></span></div>
                        <div class="ip-info-item"><span class="label">Location</span><span class="value" id="proxy-location"><span class="skeleton"></span></span></div>
                        <div class="ip-info-item"><span class="label">ISP</span><span class="value" id="proxy-isp"><span class="skeleton"></span></span></div>
                    </div>
                </div>
                <div class="ip-info-section">
                    <div class="ip-info-header"><h3>Your Connection</h3></div>
                    <div class="ip-info-content">
                        <div class="ip-info-item"><span class="label">IP</span><span class="value" id="client-ip"><span class="skeleton"></span></span></div>
                        <div class="ip-info-item"><span class="label">Location</span><span class="value" id="client-location"><span class="skeleton"></span></span></div>
                        <div class="ip-info-item"><span class="label">Risk Score</span><span class="value" id="client-proxy"><span class="skeleton"></span></span></div>
                    </div>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>© ${new Date().getFullYear()} REvil - All Rights Reserved</p>
        </div>
    </div>`;
}

// --- HELPER & UTILITY FUNCTIONS ---
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
        byteToHex[arr[0]] + byteToHex[arr[1]] + byteToHex[arr[2]] + byteToHex[arr[3]] + '-' +
        byteToHex[arr[4]] + byteToHex[arr[5]] + '-' +
        byteToHex[arr[6]] + byteToHex[arr[7]] + '-' +
        byteToHex[arr[8]] + byteToHex[arr[9]] + '-' +
        byteToHex[arr[10]] + byteToHex[arr[11]] + byteToHex[arr[12]] + byteToHex[arr[13]] + byteToHex[arr[14]] + byteToHex[arr[15]]
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
        tls: { path: () => generateRandomPath(18), security: 'tls', fp: 'firefox', alpn: 'h3', extra: { ed: 2560 } },
        tcp: { path: () => generateRandomPath(18), security: 'none', fp: 'firefox', extra: { ed: 2560 } },
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
      :root {
        --background-primary: #1a1a1a; --background-secondary: #2a2a2a; --background-tertiary: #333;
        --border-color: #444; --border-color-hover: #555; --text-primary: #e0e0e0; --text-secondary: #9e9e9e;
        --text-accent: #ffffff; --accent-primary: #007bff; --accent-secondary: #3391ff;
        --shadow-color: rgba(0, 0, 0, 0.35); --shadow-color-accent: rgba(0, 123, 255, 0.4);
        --border-radius: 8px; --transition-speed: 0.2s;
        --status-success: #70b570; --status-error: #e05d44; --status-warning: #e0bc44;
        --sans-serif: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
        --mono-serif: "Fira Code", monospace;
      }
      body {
        font-family: var(--sans-serif); font-size: 16px; background-color: var(--background-primary); color: var(--text-primary);
        padding: 2rem; line-height: 1.6;
      }
      .container {
        max-width: 800px; margin: 20px auto;
      }
      .header { text-align: center; margin-bottom: 40px; }
      .header h1 { font-size: 2.2rem; color: var(--text-accent); margin-bottom: 8px; }
      .header p { color: var(--text-secondary); font-size: 1rem; }
      .config-card {
        background: var(--background-secondary); border-radius: var(--border-radius); padding: 24px; margin-bottom: 24px;
        border: 1px solid var(--border-color);
      }
      .config-title {
        font-size: 1.5rem; font-weight: 600; color: var(--accent-secondary);
        margin-bottom: 16px; padding-bottom: 16px; border-bottom: 1px solid var(--border-color);
        display: flex; align-items: center; justify-content: space-between;
      }
      .card-description {
        color: var(--text-secondary);
        margin-bottom: 16px;
      }
      .config-content {
        background: var(--background-tertiary); border-radius: var(--border-radius);
        padding: 16px; margin-bottom: 20px; border: 1px solid var(--border-color);
      }
      .config-content pre {
        overflow-x: auto; font-family: var(--mono-serif); font-size: 0.8rem; color: var(--text-primary);
        margin: 0; white-space: pre-wrap; word-break: break-all;
      }
      .button-group {
        display: flex; justify-content: flex-end;
      }
      .button {
        display: inline-flex; align-items: center; justify-content: center; gap: 8px;
        padding: 10px 18px; border-radius: var(--border-radius); font-size: 1rem; font-weight: 500;
        cursor: pointer; border: none; text-decoration: none;
        transition: background-color var(--transition-speed) ease, transform var(--transition-speed) ease;
      }
      .copy-buttons {
        background-color: var(--background-tertiary); color: var(--text-primary); border: 1px solid var(--border-color);
      }
      .copy-buttons:hover {
          background-color: #4d4d4d;
      }
      .client-buttons { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
      .client-btn {
        width: 100%; background-color: var(--accent-primary); color: var(--text-accent);
      }
      .client-btn:hover { background-color: var(--accent-secondary); }
      .button.copied { background-color: var(--status-success) !important; color: var(--text-accent) !important; }
      .footer { text-align: center; margin-top: 40px; padding-bottom: 20px; color: var(--text-secondary); font-size: 0.8rem; }
      .ip-info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 24px; }
      .ip-info-section { background-color: var(--background-tertiary); border-radius: var(--border-radius); padding: 16px; }
      .ip-info-header h3 { font-size: 1.1rem; color: var(--accent-secondary); margin: 0 0 12px 0; padding-bottom: 8px; border-bottom: 1px solid var(--border-color); }
      .ip-info-item { display: flex; justify-content: space-between; margin-bottom: 8px; }
      .ip-info-item .label { color: var(--text-secondary); }
      .ip-info-item .value { color: var(--text-primary); word-break: break-all; }
      .skeleton { display: inline-block; background: linear-gradient(90deg, var(--background-tertiary) 25%, #4d4d4d 50%, var(--background-tertiary) 75%); background-size: 200% 100%; animation: loading 1.5s infinite; border-radius: 4px; height: 16px; width: 120px; }
      @keyframes loading { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }
      .refresh-btn { background-color: transparent; border: 1px solid var(--border-color); color: var(--text-primary); padding: 6px 12px; font-size: 0.9rem; }
   `;
}

function getPageScript() {
    return `
      function copyToClipboard(button, text) {
        const originalHTML = button.innerHTML;
        navigator.clipboard.writeText(text).then(() => {
          button.innerHTML = 'Copied!';
          button.classList.add("copied");
          setTimeout(() => {
            button.innerHTML = originalHTML;
            button.classList.remove("copied");
          }, 1500);
        }).catch(err => console.error("Failed to copy text: ", err));
      }

      function updateDisplay(data) {
        const setContent = (id, value) => {
            const el = document.getElementById(id);
            if (el) el.innerHTML = value || 'N/A';
        };
        setContent('proxy-host', data.proxy?.host);
        setContent('proxy-location', [data.proxy?.city, data.proxy?.country].filter(Boolean).join(', '));
        setContent('proxy-isp', data.proxy?.isp);
        setContent('client-ip', data.client?.ip);
        setContent('client-location', [data.client?.city, data.client?.country].filter(Boolean).join(', '));
        let riskText = 'Unknown';
        if (data.client?.risk?.score !== undefined) {
            riskText = \`\${data.client.risk.score} - \${data.client.risk.risk}\`;
        }
        setContent('client-proxy', riskText);
      }

      async function loadNetworkInfo() {
        try {
            const response = await fetch('/api/network-info');
            if (!response.ok) throw new Error('API request failed');
            const data = await response.json();
            updateDisplay(data);
        } catch (error) {
            console.error('Failed to load network info:', error);
            updateDisplay({ client: {}, proxy: { host: document.body.getAttribute('data-proxy-ip') } });
        }
      }

      document.getElementById('refresh-ip-info')?.addEventListener('click', function() {
        const elements = document.querySelectorAll('.ip-info-item .value');
        elements.forEach(el => el.innerHTML = '<span class="skeleton"></span>');
        loadNetworkInfo();
      });

      document.addEventListener('DOMContentLoaded', loadNetworkInfo);
  `;
}
