/**
 * Minimalist SOCKS5 Client & Tor Local Proxy Connector
 * Built exclusively on Node.js native modules (node:net, node:tls, node:http, node:https)
 * Supports SOCKS5h (remote DNS resolution through Tor) with graceful timeout handling.
 */

import net from 'node:net';
import tls from 'node:tls';

export interface TorProxyStatus {
  available: boolean;
  host: string;
  port: number;
  latencyMs?: number;
  error?: string;
}

export interface Socks5HttpResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
}

export function parseProxyAddress(proxyStr?: string): { host: string; port: number } {
  if (!proxyStr || typeof proxyStr !== 'string') {
    return { host: '127.0.0.1', port: 9050 };
  }
  const cleaned = proxyStr.trim().replace(/^socks5h?:\/\//i, '');
  const parts = cleaned.split(':');
  const host = parts[0]?.trim() || '127.0.0.1';
  const port = parseInt(parts[1] || '9050', 10);
  return {
    host,
    port: Number.isFinite(port) && port > 0 && port <= 65535 ? port : 9050,
  };
}

/**
 * Check if a local Tor SOCKS5 proxy is listening and responsive
 */
export async function checkTorProxyHealth(
  host: string = '127.0.0.1',
  port: number = 9050,
  timeoutMs: number = 1000
): Promise<TorProxyStatus> {
  if (process.env.OSINT_OFFLINE_MODE === '1') {
    return {
      available: false,
      host,
      port,
      error: 'Mode hors ligne actif',
    };
  }

  const startTime = Date.now();

  return new Promise<TorProxyStatus>((resolve) => {
    let settled = false;
    const socket = new net.Socket();

    const finish = (result: TorProxyStatus) => {
      if (!settled) {
        settled = true;
        try {
          socket.destroy();
        } catch {}
        resolve(result);
      }
    };

    socket.setTimeout(timeoutMs);

    socket.once('connect', () => {
      // Send SOCKS5 greeting: Version 5, 1 auth method, 0x00 (No Auth)
      socket.write(Buffer.from([0x05, 0x01, 0x00]));
    });

    socket.once('data', (chunk: Buffer) => {
      if (chunk.length >= 2 && chunk[0] === 0x05 && chunk[1] === 0x00) {
        finish({
          available: true,
          host,
          port,
          latencyMs: Date.now() - startTime,
        });
      } else {
        finish({
          available: false,
          host,
          port,
          error: 'Reponse SOCKS5 invalide',
        });
      }
    });

    socket.once('timeout', () => {
      finish({
        available: false,
        host,
        port,
        error: 'Delai de connexion depasse',
      });
    });

    socket.once('error', (err: Error) => {
      finish({
        available: false,
        host,
        port,
        error: err.message,
      });
    });

    try {
      socket.connect(port, host);
    } catch (err: any) {
      finish({
        available: false,
        host,
        port,
        error: err?.message || 'Erreur de connexion',
      });
    }
  });
}

/**
 * Perform an HTTP/HTTPS GET request routed through a SOCKS5h proxy (remote DNS resolution)
 */
export async function fetchViaSocks5(
  targetUrl: string,
  proxyHost: string = '127.0.0.1',
  proxyPort: number = 9050,
  timeoutMs: number = 8000,
  customHeaders: Record<string, string> = {}
): Promise<Socks5HttpResponse> {
  const parsed = new URL(targetUrl);
  const isHttps = parsed.protocol === 'https:';
  const targetHost = parsed.hostname;
  const targetPort = parsed.port ? parseInt(parsed.port, 10) : isHttps ? 443 : 80;
  const requestPath = `${parsed.pathname || '/'}${parsed.search || ''}`;

  return new Promise<Socks5HttpResponse>((resolve, reject) => {
    let settled = false;
    const rawSocket = new net.Socket();
    let activeStream: net.Socket | tls.TLSSocket = rawSocket;

    const fail = (err: Error) => {
      if (!settled) {
        settled = true;
        try {
          activeStream.destroy();
          rawSocket.destroy();
        } catch {}
        reject(err);
      }
    };

    const timer = setTimeout(() => {
      fail(new Error(`Delai SOCKS5 depasse apres ${timeoutMs}ms`));
    }, timeoutMs);

    rawSocket.once('error', fail);

    rawSocket.connect(proxyPort, proxyHost, () => {
      // Step 1: SOCKS5 greeting (VER=0x05, NMETHODS=0x01, METHOD=0x00)
      rawSocket.write(Buffer.from([0x05, 0x01, 0x00]));

      rawSocket.once('data', (greetingResp: Buffer) => {
        if (greetingResp.length < 2 || greetingResp[0] !== 0x05 || greetingResp[1] !== 0x00) {
          fail(new Error('Echec de negociation initiale SOCKS5'));
          return;
        }

        // Step 2: SOCKS5 CONNECT with Domain Name (ATYP=0x03) for remote Tor DNS resolution
        const hostBuf = Buffer.from(targetHost, 'utf-8');
        const portBuf = Buffer.alloc(2);
        portBuf.writeUInt16BE(targetPort, 0);

        const connectReq = Buffer.concat([
          Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]),
          hostBuf,
          portBuf,
        ]);

        rawSocket.write(connectReq);

        rawSocket.once('data', (connectResp: Buffer) => {
          if (connectResp.length < 2 || connectResp[0] !== 0x05 || connectResp[1] !== 0x00) {
            const repCode = connectResp.length >= 2 ? connectResp[1] : -1;
            fail(new Error(`Echec de connexion au tunnel SOCKS5 (code ${repCode})`));
            return;
          }

          const sendHttpRequest = (stream: net.Socket | tls.TLSSocket) => {
            const headers: Record<string, string> = {
              Host: targetHost,
              'User-Agent':
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
              Accept: 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
              'Accept-Language': 'fr,fr-FR;q=0.9,en;q=0.8',
              Connection: 'close',
              ...customHeaders,
            };

            const headerLines = Object.entries(headers)
              .map(([k, v]) => `${k}: ${v}`)
              .join('\r\n');

            const rawHttpReq = `GET ${requestPath} HTTP/1.1\r\n${headerLines}\r\n\r\n`;
            stream.write(rawHttpReq);

            const chunks: Buffer[] = [];
            stream.on('data', (chunk: Buffer) => {
              chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
            });

            stream.once('end', () => {
              if (settled) return;
              settled = true;
              clearTimeout(timer);
              try {
                stream.destroy();
              } catch {}

              const fullBuffer = Buffer.concat(chunks).toString('utf-8');
              const splitIdx = fullBuffer.indexOf('\r\n\r\n');
              if (splitIdx === -1) {
                resolve({ statusCode: 200, headers: {}, body: fullBuffer });
                return;
              }

              const rawHead = fullBuffer.slice(0, splitIdx);
              const rawBody = fullBuffer.slice(splitIdx + 4);
              const headLines = rawHead.split('\r\n');
              const statusLine = headLines[0] || '';
              const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d{3})/);
              const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : 200;

              const respHeaders: Record<string, string> = {};
              for (let i = 1; i < headLines.length; i++) {
                const sep = headLines[i].indexOf(':');
                if (sep > 0) {
                  const k = headLines[i].slice(0, sep).trim().toLowerCase();
                  const v = headLines[i].slice(sep + 1).trim();
                  respHeaders[k] = v;
                }
              }

              resolve({
                statusCode,
                headers: respHeaders,
                body: rawBody,
              });
            });
          };

          if (isHttps) {
            const tlsSocket = tls.connect({
              socket: rawSocket,
              servername: targetHost,
              rejectUnauthorized: false,
            });
            activeStream = tlsSocket;
            tlsSocket.once('error', fail);
            tlsSocket.once('secureConnect', () => {
              sendHttpRequest(tlsSocket);
            });
          } else {
            sendHttpRequest(rawSocket);
          }
        });
      });
    });
  });
}
