/**
 * Ahmia Dark Web Gateway & Tor SOCKS5 Adapter
 * Queries Ahmia Clearnet gateway (https://ahmia.fi) or Ahmia Tor Onion service
 * via local SOCKS5 proxy (127.0.0.1:9050) simultaneously across email, username, and phone.
 *
 * ZERO HYPHEN RULE IN FRENCH TEXT:
 * All French user facing strings strictly exclude hyphens (-, –, —).
 */

import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import { fileURLToPath } from 'node:url';
import {
  IToolAdapter,
  ToolExecutionContext,
  ToolHealth,
  ToolResult,
  UnifiedLeak,
} from '../types.js';
import {
  checkTorProxyHealth,
  fetchViaSocks5,
  parseProxyAddress,
} from '../network/socks5.js';

export interface DarkWebSearchResult {
  id: string;
  query: string;
  title: string;
  onionUrl: string;
  snippet: string;
  lastSeen?: string;
  extractedAt: string;
  routingMode: 'tor_socks5' | 'clearnet' | 'offline_fixture';
}

const AHMIA_CLEARNET_BASE = 'https://ahmia.fi/search/?q=';
const AHMIA_ONION_BASE =
  'http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q=';

function stripHyphensFr(text: string): string {
  return String(text || '')
    .replace(/[-–—]/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .trim();
}

function decodeHtmlEntities(raw: string): string {
  return String(raw || '')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .trim();
}

export class AhmiaAdapter implements IToolAdapter {
  readonly name = 'ahmia' as const;
  private defaultTorProxy: string;

  constructor(defaultTorProxy: string = '127.0.0.1:9050') {
    this.defaultTorProxy = defaultTorProxy;
  }

  async checkHealth(): Promise<ToolHealth> {
    const { host, port } = parseProxyAddress(this.defaultTorProxy);
    const torStatus = await checkTorProxyHealth(host, port, 800);

    if (torStatus.available) {
      return {
        installed: true,
        version: 'Passerelle Ahmia et Tunnel Tor SOCKS5 actif',
        path: `socks5://${host}:${port}`,
        sessionValid: true,
      };
    }

    return {
      installed: true,
      version: 'Passerelle Ahmia Clearnet active (Tor local optionnel)',
      path: 'https://ahmia.fi',
      sessionValid: true,
    };
  }

  /**
   * Parse Ahmia HTML search results (<li class="result">...</li>)
   */
  public parseAhmiaHtml(
    html: string,
    query: string,
    routingMode: 'tor_socks5' | 'clearnet' | 'offline_fixture' = 'clearnet'
  ): DarkWebSearchResult[] {
    if (!html || typeof html !== 'string') return [];

    const results: DarkWebSearchResult[] = [];
    const liRegex = /<li[^>]*class=["'][^"']*result[^"']*["'][^>]*>([\s\S]*?)<\/li>/gi;
    let match: RegExpExecArray | null;
    let index = 0;

    while ((match = liRegex.exec(html)) !== null) {
      const block = match[1];

      // Title inside <h4>...</h4>
      const h4Match = block.match(/<h4[^>]*>([\s\S]*?)<\/h4>/i);
      const rawTitle = h4Match ? decodeHtmlEntities(h4Match[1]) : 'Service cache Tor reference';

      // Onion URL inside <cite>...</cite> or href="...onion..."
      const citeMatch = block.match(/<cite[^>]*>([\s\S]*?)<\/cite>/i);
      const hrefMatch = block.match(/href=["']([^"']*\.onion[^"']*)["']/i);
      let onionUrl = citeMatch
        ? decodeHtmlEntities(citeMatch[1])
        : hrefMatch
          ? hrefMatch[1]
          : '';
      if (onionUrl && !onionUrl.startsWith('http://') && !onionUrl.startsWith('https://')) {
        onionUrl = `http://${onionUrl}`;
      }
      if (!onionUrl) {
        onionUrl = 'http://servicehidden.onion';
      }

      // Snippet inside <p>...</p>
      const pMatch = block.match(/<p[^>]*>([\s\S]*?)<\/p>/i);
      const rawSnippet = pMatch
        ? decodeHtmlEntities(pMatch[1])
        : `Correspondance detectee pour la cible ${query}`;

      // Last seen inside <span class="lastSeen">...</span>
      const seenMatch = block.match(/<span[^>]*class=["'][^"']*lastSeen[^"']*["'][^>]*>([\s\S]*?)<\/span>/i);
      const lastSeen = seenMatch ? stripHyphensFr(decodeHtmlEntities(seenMatch[1])) : undefined;

      index++;
      results.push({
        id: `ahmia_${Buffer.from(`${query}_${onionUrl}_${index}`).toString('hex').slice(0, 12)}`,
        query,
        title: stripHyphensFr(rawTitle) || 'Service cache Tor',
        onionUrl,
        snippet: stripHyphensFr(rawSnippet),
        lastSeen,
        extractedAt: new Date().toISOString(),
        routingMode,
      });
    }

    return results;
  }

  /**
   * Load deterministic offline fixtures for testing or offline mode
   */
  private loadOfflineFixtures(query: string): DarkWebSearchResult[] {
    try {
      const currentDir = path.dirname(fileURLToPath(import.meta.url));
      const rootCandidates = [
        path.resolve(currentDir, '..', '..', '..'),
        path.resolve(currentDir, '..', '..', '..', '..'),
        process.cwd(),
      ];

      for (const root of rootCandidates) {
        const fixturePath = path.join(root, 'data', 'fixtures', 'darkweb_breach_fixtures.json');
        if (fs.existsSync(fixturePath)) {
          const parsed = JSON.parse(fs.readFileSync(fixturePath, 'utf-8'));
          const items = parsed?.ahmia?.default || [];
          return items.map((item: any, idx: number) => ({
            id: `ahmia_fix_${Buffer.from(`${query}_${idx}`).toString('hex').slice(0, 10)}`,
            query,
            title: stripHyphensFr(item.title || 'Archive Dark Web'),
            onionUrl: item.onionUrl || 'http://archive.onion',
            snippet: stripHyphensFr(`${item.snippet || 'Mention detectee'} (${query})`),
            lastSeen: stripHyphensFr(item.lastSeen || '2026/11/01'),
            extractedAt: new Date().toISOString(),
            routingMode: 'offline_fixture' as const,
          }));
        }
      }
    } catch {}

    return [
      {
        id: `ahmia_fallback_${Buffer.from(query).toString('hex').slice(0, 10)}`,
        query,
        title: 'Indexation Dark Web Onion Archive',
        onionUrl: 'http://indexarchive7x9k2m.onion/search',
        snippet: stripHyphensFr(`Correspondance d indexation pour ${query} sur passerelle Tor`),
        lastSeen: '2026/11/01',
        extractedAt: new Date().toISOString(),
        routingMode: 'offline_fixture',
      },
    ];
  }

  /**
   * Perform an HTTP GET over clearnet using native node:https
   */
  private fetchClearnet(url: string, timeoutMs: number = 7000): Promise<string> {
    return new Promise((resolve, reject) => {
      const req = https.get(
        url,
        {
          headers: {
            'User-Agent':
              'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'fr,fr-FR;q=0.9,en;q=0.8',
          },
          timeout: timeoutMs,
        },
        (res) => {
          if (res.statusCode && res.statusCode >= 400) {
            res.resume();
            reject(new Error(`Statut HTTP ${res.statusCode}`));
            return;
          }
          const chunks: Buffer[] = [];
          res.on('data', (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
          res.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
        }
      );

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Delai de requete Ahmia depasse'));
      });
      req.on('error', reject);
    });
  }

  /**
   * Query Ahmia for a single search term with optional Tor SOCKS5 proxy support
   */
  public async query(
    term: string,
    options?: { torProxy?: string; useTorProxy?: boolean; offline?: boolean }
  ): Promise<DarkWebSearchResult[]> {
    const cleanTerm = (term || '').trim();
    if (!cleanTerm) return [];

    if (process.env.OSINT_OFFLINE_MODE === '1' || options?.offline === true) {
      return this.loadOfflineFixtures(cleanTerm);
    }

    const proxyAddr = options?.torProxy || this.defaultTorProxy;
    const { host, port } = parseProxyAddress(proxyAddr);

    // 1. Try Tor SOCKS5 proxy if enabled or available
    if (options?.useTorProxy !== false) {
      const torHealth = await checkTorProxyHealth(host, port, 800);
      if (torHealth.available) {
        try {
          const onionTargetUrl = `${AHMIA_ONION_BASE}${encodeURIComponent(cleanTerm)}`;
          const resp = await fetchViaSocks5(onionTargetUrl, host, port, 7000);
          if (resp.statusCode >= 200 && resp.statusCode < 400 && resp.body) {
            return this.parseAhmiaHtml(resp.body, cleanTerm, 'tor_socks5');
          }
        } catch {
          // Graceful fallback to Clearnet gateway
        }
      }
    }

    // 2. Clearnet gateway fallback
    try {
      const clearnetUrl = `${AHMIA_CLEARNET_BASE}${encodeURIComponent(cleanTerm)}`;
      const html = await this.fetchClearnet(clearnetUrl, 7000);
      return this.parseAhmiaHtml(html, cleanTerm, 'clearnet');
    } catch {
      return [];
    }
  }

  /**
   * Execute Dark Web search across all provided targets (email, username, phone)
   */
  async execute(context: ToolExecutionContext): Promise<ToolResult> {
    const startTime = Date.now();
    const searchTerms: string[] = [];

    if (context.email && context.email.trim()) {
      searchTerms.push(context.email.trim());
    }
    if (context.username && context.username.trim()) {
      searchTerms.push(context.username.trim());
    }
    if (context.phone && context.phone.trim()) {
      searchTerms.push(context.phone.trim());
    }

    if (searchTerms.length === 0) {
      return {
        toolName: this.name,
        success: false,
        durationMs: Date.now() - startTime,
        rawOutput: null,
        error: 'Aucune cible fournie pour la recherche Dark Web Ahmia',
        accounts: [],
        leaks: [],
      };
    }

    context.onProgress?.('Interrogation de la passerelle Dark Web Ahmia en cours...', 25);

    const allResults: DarkWebSearchResult[] = [];
    const leaks: UnifiedLeak[] = [];

    const queryPromises = searchTerms.map((term) =>
      this.query(term, {
        torProxy: context.options?.torProxy,
        useTorProxy: context.options?.useTorProxy,
        offline: context.options?.offline,
      })
    );

    const settled = await Promise.allSettled(queryPromises);
    for (const item of settled) {
      if (item.status === 'fulfilled' && Array.isArray(item.value)) {
        allResults.push(...item.value);
      }
    }

    for (const res of allResults) {
      leaks.push({
        id: res.id,
        target: res.query,
        sourceTool: 'ahmia',
        breachName: stripHyphensFr(`Dark Web (.onion) : ${res.title}`),
        breachDate: res.lastSeen,
        dataClasses: ['Indexation Dark Web (.onion)', 'Mention publique Tor'],
        details: stripHyphensFr(
          `${res.snippet} | Adresse Onion : ${res.onionUrl}`
        ),
        category: 'darkweb',
        severity: 'high',
        metadata: {
          onionUrl: res.onionUrl,
          pageTitle: res.title,
          snippet: res.snippet,
          lastSeen: res.lastSeen,
          routingMode: res.routingMode,
        },
      });
    }

    context.onProgress?.(
      `Recherche Dark Web Ahmia terminee (${leaks.length} mention(s) detectee(s))`,
      100
    );

    return {
      toolName: this.name,
      success: true,
      durationMs: Date.now() - startTime,
      rawOutput: {
        queries: searchTerms,
        resultsCount: allResults.length,
        items: allResults,
      },
      accounts: [],
      leaks,
    };
  }
}
