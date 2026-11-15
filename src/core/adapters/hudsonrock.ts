/**
 * Hudson Rock Cavalier Infostealer Intelligence Adapter
 * Queries https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email
 * and search-by-username without requiring a mandatory API key, while supporting
 * optional user configured API keys.
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

export interface InfostealerInfectionEntry {
  stealerFamily: string;
  dateCompromised: string;
  computerName: string;
  operatingSystem: string;
  compromisedCount: number;
  compromisedServices: string[];
}

export interface InfostealerReport {
  identifier: string;
  type: 'email' | 'username';
  compromised: boolean;
  infections: InfostealerInfectionEntry[];
  leaks: UnifiedLeak[];
}

function stripHyphensFr(text: string): string {
  return String(text || '')
    .replace(/[-–—]/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .trim();
}

export class HudsonRockAdapter implements IToolAdapter {
  readonly name = 'hudsonrock' as const;

  async checkHealth(): Promise<ToolHealth> {
    return {
      installed: true,
      version: 'Cavalier Infostealer OSINT v2',
      path: 'https://cavalier.hudsonrock.com/api/json/v2/osint-tools',
      sessionValid: true,
    };
  }

  /**
   * Load deterministic offline fixtures for testing or offline mode
   */
  private loadOfflineFixtures(identifier: string, type: 'email' | 'username'): InfostealerReport {
    const cleanId = identifier.trim();
    const infections: InfostealerInfectionEntry[] = [];
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
          const stealers = parsed?.hudsonrock?.stealers || [];

          for (const s of stealers) {
            const family = stripHyphensFr(s.stealerFamily || 'LummaC2');
            const dateStr = String(s.dateCompromised || '2025/11/18').slice(0, 10).replace(/[-–—]/g, '/');
            const compName = stripHyphensFr(s.computerName || 'POSTE_UTILISATEUR');
            const osName = stripHyphensFr(s.operatingSystem || 'macOS');
            const services = Array.isArray(s.compromisedServices) ? s.compromisedServices : ['github.com'];
            const count =
              (Number(s.totalCorporateServices) || 0) + (Number(s.totalUserServices) || services.length);

            infections.push({
              stealerFamily: family,
              dateCompromised: dateStr,
              computerName: compName,
              operatingSystem: osName,
              compromisedCount: count,
              compromisedServices: services,
            });

            leaks.push({
              id: `hr_${Buffer.from(`${cleanId}_${family}_${compName}`).toString('hex').slice(0, 12)}`,
              target: cleanId,
              sourceTool: 'hudsonrock',
              breachName: stripHyphensFr(`Infection Infostealer ${family}`),
              breachDate: dateStr,
              dataClasses: [
                'Mots de passe navigateur',
                'Jetons de session actifs',
                'Empreinte machine',
                'Journaux Infostealer',
              ],
              details: stripHyphensFr(
                `Machine ${compName} (${osName}) infectee par le logiciel espion ${family} (${count} services compromis : ${services.join(', ')})`
              ),
              category: 'infostealer',
              severity: 'critical',
              metadata: {
                stealerFamily: family,
                computerName: compName,
                operatingSystem: osName,
                infectionDate: dateStr,
                compromisedCount: count,
                compromisedServices: services,
                routingMode: 'offline_fixture',
              },
            });
          }

          return {
            identifier: cleanId,
            type,
            compromised: infections.length > 0,
            infections,
            leaks,
          };
        }
      }
    } catch {}

    const fallbackEntry: InfostealerInfectionEntry = {
      stealerFamily: 'LummaC2',
      dateCompromised: '2025/11/18',
      computerName: 'WORKSTATION_OSX',
      operatingSystem: 'macOS',
      compromisedCount: 4,
      compromisedServices: ['github.com', 'spotify.com'],
    };

    return {
      identifier: cleanId,
      type,
      compromised: true,
      infections: [fallbackEntry],
      leaks: [
        {
          id: `hr_default_${Buffer.from(cleanId).toString('hex').slice(0, 10)}`,
          target: cleanId,
          sourceTool: 'hudsonrock',
          breachName: 'Infection Infostealer LummaC2',
          breachDate: '2025/11/18',
          dataClasses: ['Mots de passe navigateur', 'Jetons de session actifs', 'Journaux Infostealer'],
          details: stripHyphensFr(
            `Machine WORKSTATION_OSX infectee par le logiciel espion LummaC2 pour la cible ${cleanId}`
          ),
          category: 'infostealer',
          severity: 'critical',
          metadata: {
            stealerFamily: 'LummaC2',
            computerName: 'WORKSTATION_OSX',
            operatingSystem: 'macOS',
            infectionDate: '2025/11/18',
            compromisedCount: 4,
            compromisedServices: ['github.com', 'spotify.com'],
            routingMode: 'offline_fixture',
          },
        },
      ],
    };
  }

  /**
   * Perform HTTPS JSON GET to Hudson Rock Cavalier OSINT endpoint
   */
  private fetchCavalierJson(url: string, apiKey?: string, timeoutMs: number = 7000): Promise<any> {
    return new Promise((resolve, reject) => {
      const headers: Record<string, string> = {
        'User-Agent': 'OSINTPrivacySuite/1.0 (macOS arm64)',
        Accept: 'application/json',
      };
      if (apiKey && apiKey.trim().length > 0) {
        headers['api-key'] = apiKey.trim();
      }

      const req = https.get(url, { headers, timeout: timeoutMs }, (res) => {
        if (res.statusCode === 404) {
          res.resume();
          resolve({ stealers: [] });
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
            resolve(raw ? JSON.parse(raw) : { stealers: [] });
          } catch (err) {
            reject(err);
          }
        });
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Delai de requete Hudson Rock depasse'));
      });
      req.on('error', reject);
    });
  }

  /**
   * Parse Cavalier response JSON into InfostealerReport
   */
  public parseCavalierPayload(
    payload: any,
    identifier: string,
    type: 'email' | 'username'
  ): InfostealerReport {
    const cleanId = identifier.trim();
    const stealersList = Array.isArray(payload?.stealers) ? payload.stealers : [];
    const infections: InfostealerInfectionEntry[] = [];
    const leaks: UnifiedLeak[] = [];

    for (let i = 0; i < stealersList.length; i++) {
      const item = stealersList[i];
      if (!item || typeof item !== 'object') continue;

      const family = stripHyphensFr(
        item.stealer_family || item.stealerFamily || 'Infostealer Malware'
      );
      const rawDate = item.date_compromised || item.dateCompromised || '';
      const dateStr = rawDate ? String(rawDate).slice(0, 10).replace(/[-–—]/g, '/') : 'Date inconnue';
      const compName = stripHyphensFr(
        item.computer_name || item.computerName || 'Poste compromis'
      );
      const osName = stripHyphensFr(
        item.operating_system || item.operatingSystem || 'Systeme inconnu'
      );
      const count =
        (Number(item.total_corporate_services) || 0) +
        (Number(item.total_user_services) || 0) +
        (Number(item.credentials_count) || 0) || 1;

      const services: string[] = Array.isArray(item.top_passwords)
        ? item.top_passwords.map((s: any) => String(s))
        : Array.isArray(item.compromisedServices)
          ? item.compromisedServices.map((s: any) => String(s))
          : [];

      infections.push({
        stealerFamily: family,
        dateCompromised: dateStr,
        computerName: compName,
        operatingSystem: osName,
        compromisedCount: count,
        compromisedServices: services,
      });

      leaks.push({
        id: `hr_${Buffer.from(`${cleanId}_${family}_${i}`).toString('hex').slice(0, 12)}`,
        target: cleanId,
        sourceTool: 'hudsonrock',
        breachName: stripHyphensFr(`Infection Infostealer ${family}`),
        breachDate: dateStr,
        dataClasses: [
          'Mots de passe navigateur',
          'Jetons de session actifs',
          'Empreinte machine',
          'Journaux Infostealer',
        ],
        details: stripHyphensFr(
          `Poste ${compName} (${osName}) compromis par ${family} (${count} acces exfiltres)`
        ),
        category: 'infostealer',
        severity: 'critical',
        metadata: {
          stealerFamily: family,
          computerName: compName,
          operatingSystem: osName,
          infectionDate: dateStr,
          compromisedCount: count,
          compromisedServices: services,
          routingMode: 'clearnet',
        },
      });
    }

    return {
      identifier: cleanId,
      type,
      compromised: infections.length > 0,
      infections,
      leaks,
    };
  }

  /**
   * Query Hudson Rock Cavalier by identifier (email or username)
   */
  public async query(
    identifier: string,
    type: 'email' | 'username' = 'email',
    options?: { apiKey?: string; offline?: boolean }
  ): Promise<InfostealerReport> {
    const cleanId = (identifier || '').trim();
    if (!cleanId) {
      return { identifier: '', type, compromised: false, infections: [], leaks: [] };
    }

    if (process.env.OSINT_OFFLINE_MODE === '1' || options?.offline === true) {
      return this.loadOfflineFixtures(cleanId, type);
    }

    try {
      const endpoint =
        type === 'email'
          ? `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=${encodeURIComponent(cleanId)}`
          : `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username=${encodeURIComponent(cleanId)}`;

      const payload = await this.fetchCavalierJson(endpoint, options?.apiKey, 7000);
      return this.parseCavalierPayload(payload, cleanId, type);
    } catch {
      return { identifier: cleanId, type, compromised: false, infections: [], leaks: [] };
    }
  }

  async execute(context: ToolExecutionContext): Promise<ToolResult> {
    const startTime = Date.now();
    const queries: Array<{ id: string; type: 'email' | 'username' }> = [];

    if (context.email && context.email.trim()) {
      queries.push({ id: context.email.trim(), type: 'email' });
    }
    if (context.username && context.username.trim()) {
      queries.push({ id: context.username.trim(), type: 'username' });
    }

    if (queries.length === 0) {
      return {
        toolName: this.name,
        success: false,
        durationMs: Date.now() - startTime,
        rawOutput: null,
        error: 'Courriel ou pseudonyme requis pour l analyse Infostealer Hudson Rock',
        accounts: [],
        leaks: [],
      };
    }

    context.onProgress?.('Interrogation des journaux Infostealer Hudson Rock Cavalier...', 30);

    const apiKey =
      context.options?.cavalierApiKey ||
      context.options?.apiKeys?.hudsonrock ||
      context.options?.apiKeys?.cavalier;

    const reports: InfostealerReport[] = [];
    const allLeaks: UnifiedLeak[] = [];

    const settled = await Promise.allSettled(
      queries.map((q) =>
        this.query(q.id, q.type, {
          apiKey,
          offline: context.options?.offline,
        })
      )
    );

    for (const item of settled) {
      if (item.status === 'fulfilled' && item.value) {
        reports.push(item.value);
        allLeaks.push(...item.value.leaks);
      }
    }

    context.onProgress?.(
      `Analyse Infostealer Hudson Rock terminee (${allLeaks.length} compromission(s) detectee(s))`,
      100
    );

    return {
      toolName: this.name,
      success: true,
      durationMs: Date.now() - startTime,
      rawOutput: {
        reports,
        totalInfections: allLeaks.length,
        authenticatedKeyUsed: Boolean(apiKey && String(apiKey).trim().length > 0),
      },
      accounts: [],
      leaks: allLeaks,
    };
  }
}
