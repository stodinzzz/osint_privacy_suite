/**
 * XposedOrNot Public Data Breach & Exposed Pastes Adapter
 * Queries https://api.xposedornot.com/v1/breach-analytics without requiring a mandatory API key,
 * while supporting an optional user configured API key in headers.
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

function stripHyphensFr(text: string): string {
  return String(text || '')
    .replace(/[-–—]/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .trim();
}

export class XposedOrNotAdapter implements IToolAdapter {
  readonly name = 'xposedornot' as const;

  async checkHealth(): Promise<ToolHealth> {
    return {
      installed: true,
      version: 'API v1 Publique Sans Cle Obligatoire',
      path: 'https://api.xposedornot.com/v1',
      sessionValid: true,
    };
  }

  /**
   * Load deterministic offline fixtures for testing or offline mode
   */
  private loadOfflineFixtures(email: string): UnifiedLeak[] {
    const cleanEmail = email.trim();
    const leaks: UnifiedLeak[] = [];

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
          const breaches = parsed?.xposedornot?.breaches || [];
          const pastes = parsed?.xposedornot?.pastes || [];

          for (const b of breaches) {
            const breachTitle = stripHyphensFr(b.breach || 'Base de donnees compromise');
            const dateNormalized = String(b.breachedDate || '2024/01/01').replace(/[-–—]/g, '/');
            const classes = Array.isArray(b.exposedData)
              ? b.exposedData.map((c: string) => stripHyphensFr(c))
              : ['Email addresses', 'Passwords'];

            leaks.push({
              id: `xon_breach_${Buffer.from(`${cleanEmail}_${breachTitle}`).toString('hex').slice(0, 10)}`,
              target: cleanEmail,
              sourceTool: 'xposedornot',
              breachName: breachTitle,
              breachDate: dateNormalized,
              dataClasses: classes,
              details: stripHyphensFr(
                b.details || `Fuite publique recensee par XposedOrNot sur le domaine ${b.domain || 'inconnu'}`
              ),
              category: 'breach',
              severity: classes.some((c: string) => /password|mot de passe/i.test(c))
                ? 'critical'
                : 'high',
              metadata: {
                routingMode: 'offline_fixture',
              },
            });
          }

          for (const p of pastes) {
            const pasteTitle = stripHyphensFr(`Paste expose (${p.source || 'Pastebin'})`);
            const dateNormalized = String(p.date || '2025/08/14').replace(/[-–—]/g, '/');
            leaks.push({
              id: `xon_paste_${Buffer.from(`${cleanEmail}_${p.pasteId || pasteTitle}`).toString('hex').slice(0, 10)}`,
              target: cleanEmail,
              sourceTool: 'xposedornot',
              breachName: pasteTitle,
              breachDate: dateNormalized,
              dataClasses: Array.isArray(p.exposedData)
                ? p.exposedData.map((c: string) => stripHyphensFr(c))
                : ['Email addresses', 'Paste dump'],
              details: stripHyphensFr(
                p.details || `Mention detectee dans un document public partage (${p.pasteId || 'archive'})`
              ),
              category: 'paste',
              severity: 'high',
              metadata: {
                pasteSource: stripHyphensFr(p.source || 'Pastebin'),
                routingMode: 'offline_fixture',
              },
            });
          }

          return leaks;
        }
      }
    } catch {}

    return [
      {
        id: `xon_default_${Buffer.from(cleanEmail).toString('hex').slice(0, 10)}`,
        target: cleanEmail,
        sourceTool: 'xposedornot',
        breachName: 'Canva',
        breachDate: '2019/05/24',
        dataClasses: ['Email addresses', 'Passwords', 'Usernames'],
        details: 'Fuite de base de donnees recensee par XposedOrNot.',
        category: 'breach',
        severity: 'critical',
        metadata: {
          routingMode: 'offline_fixture',
        },
      },
    ];
  }

  /**
   * Perform HTTPS JSON request to XposedOrNot API
   */
  private fetchJson(url: string, apiKey?: string, timeoutMs: number = 7000): Promise<any> {
    return new Promise((resolve, reject) => {
      const headers: Record<string, string> = {
        'User-Agent': 'OSINTPrivacySuite/1.0 (macOS arm64)',
        Accept: 'application/json',
      };
      if (apiKey && apiKey.trim().length > 0) {
        headers['x-api-key'] = apiKey.trim();
      }

      const req = https.get(url, { headers, timeout: timeoutMs }, (res) => {
        if (res.statusCode === 404) {
          res.resume();
          resolve(null);
          return;
        }
        if (res.statusCode && res.statusCode >= 400) {
          res.resume();
          reject(new Error(`Statut HTTP ${res.statusCode}`));
          return;
        }
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
        res.on('end', () => {
          try {
            const raw = Buffer.concat(chunks).toString('utf-8');
            resolve(raw ? JSON.parse(raw) : null);
          } catch (err) {
            reject(err);
          }
        });
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Delai de requete XposedOrNot depasse'));
      });
      req.on('error', reject);
    });
  }

  /**
   * Parse XposedOrNot API payload into UnifiedLeak[]
   */
  public parseAnalyticsPayload(payload: any, email: string): UnifiedLeak[] {
    if (!payload || typeof payload !== 'object') return [];
    const leaks: UnifiedLeak[] = [];
    const cleanEmail = email.trim();

    // 1. Parse ExposedBreaches.breaches_details
    const detailsList =
      payload?.ExposedBreaches?.breaches_details ||
      payload?.breaches_details ||
      [];

    if (Array.isArray(detailsList)) {
      for (const item of detailsList) {
        if (!item || typeof item !== 'object') continue;
        const name = stripHyphensFr(item.breach || item.name || 'Breche XposedOrNot');
        const rawData = item.xposed_data || item.exposedData || 'Identifiants et courriel';
        const dataClasses = Array.isArray(rawData)
          ? rawData.map((d: any) => stripHyphensFr(String(d)))
          : String(rawData)
              .split(/[;,]/)
              .map((s) => stripHyphensFr(s))
              .filter(Boolean);

        const dateStr = String(item.xposed_date || item.breachedDate || '').replace(/[-–—]/g, '/');
        const detailsText = stripHyphensFr(
          item.details || item.description || `Compromission recensee sur ${item.domain || name}`
        );

        leaks.push({
          id: `xon_${Buffer.from(`${cleanEmail}_${name}`).toString('hex').slice(0, 12)}`,
          target: cleanEmail,
          sourceTool: 'xposedornot',
          breachName: name,
          breachDate: dateStr || undefined,
          dataClasses: dataClasses.length > 0 ? dataClasses : ['Email addresses'],
          details: detailsText,
          category: 'breach',
          severity: dataClasses.some((c) => /password|mot de passe|hash/i.test(c))
            ? 'critical'
            : 'high',
          metadata: {
            routingMode: 'clearnet',
          },
        });
      }
    }

    // 2. Fallback simple Breaches list (from check-email endpoint)
    const simpleBreaches = payload?.Breaches?.Breached || payload?.breaches?.[0] || [];
    if (leaks.length === 0 && Array.isArray(simpleBreaches)) {
      for (const bName of simpleBreaches) {
        if (!bName) continue;
        const cleanName = stripHyphensFr(String(bName));
        leaks.push({
          id: `xon_chk_${Buffer.from(`${cleanEmail}_${cleanName}`).toString('hex').slice(0, 12)}`,
          target: cleanEmail,
          sourceTool: 'xposedornot',
          breachName: cleanName,
          dataClasses: ['Email addresses', 'Credentials'],
          details: stripHyphensFr(`Compte compromis dans la breche publique ${cleanName}`),
          category: 'breach',
          severity: 'high',
          metadata: {
            routingMode: 'clearnet',
          },
        });
      }
    }

    // 3. Parse ExposedPastes
    const pastesList =
      payload?.ExposedPastes?.pastes_details ||
      payload?.PastesSummary?.pastes_details ||
      payload?.ExposedPastes?.Pastes ||
      [];

    if (Array.isArray(pastesList)) {
      for (const p of pastesList) {
        if (!p) continue;
        const pasteId = typeof p === 'object' ? p.pasteId || p.id || 'paste' : String(p);
        const pasteDate =
          typeof p === 'object' && p.xposed_date
            ? String(p.xposed_date).replace(/[-–—]/g, '/')
            : undefined;
        const label = stripHyphensFr(`Paste public ${pasteId}`);

        leaks.push({
          id: `xon_paste_${Buffer.from(`${cleanEmail}_${pasteId}`).toString('hex').slice(0, 12)}`,
          target: cleanEmail,
          sourceTool: 'xposedornot',
          breachName: label,
          breachDate: pasteDate,
          dataClasses: ['Email addresses', 'Paste exposition'],
          details: stripHyphensFr(
            `Cible referencee dans une archive publique de texte (${pasteId})`
          ),
          category: 'paste',
          severity: 'high',
          metadata: {
            pasteSource: stripHyphensFr(String(pasteId)),
            routingMode: 'clearnet',
          },
        });
      }
    }

    return leaks;
  }

  /**
   * Direct query helper for email
   */
  public async query(
    email: string,
    options?: { apiKey?: string; offline?: boolean }
  ): Promise<UnifiedLeak[]> {
    const cleanEmail = (email || '').trim();
    if (!cleanEmail || !cleanEmail.includes('@')) return [];

    if (process.env.OSINT_OFFLINE_MODE === '1' || options?.offline === true) {
      return this.loadOfflineFixtures(cleanEmail);
    }

    try {
      const analyticsUrl = `https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(cleanEmail)}`;
      const payload = await this.fetchJson(analyticsUrl, options?.apiKey, 7000);
      if (payload) {
        return this.parseAnalyticsPayload(payload, cleanEmail);
      }
      return [];
    } catch {
      return [];
    }
  }

  async execute(context: ToolExecutionContext): Promise<ToolResult> {
    const startTime = Date.now();
    const email = context.email?.trim();

    if (!email || !email.includes('@')) {
      return {
        toolName: this.name,
        success: false,
        durationMs: Date.now() - startTime,
        rawOutput: null,
        error: 'Adresse electronique requise pour la verification XposedOrNot',
        accounts: [],
        leaks: [],
      };
    }

    context.onProgress?.('Verification des breches et pastes sur XposedOrNot...', 30);

    const apiKey =
      context.options?.xonApiKey ||
      context.options?.apiKeys?.xon ||
      context.options?.apiKeys?.xposedornot;

    const leaks = await this.query(email, {
      apiKey,
      offline: context.options?.offline,
    });

    context.onProgress?.(
      `Analyse XposedOrNot terminee (${leaks.length} exposition(s) identifiee(s))`,
      100
    );

    return {
      toolName: this.name,
      success: true,
      durationMs: Date.now() - startTime,
      rawOutput: {
        target: email,
        leaksCount: leaks.length,
        authenticatedKeyUsed: Boolean(apiKey && String(apiKey).trim().length > 0),
        leaks,
      },
      accounts: [],
      leaks,
    };
  }
}
