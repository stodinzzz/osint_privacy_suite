/**
 * Unit Tests for Dark Web & Data Breach Intelligence (Milestone 2 & 3)
 * Validates AhmiaAdapter, XposedOrNotAdapter, HudsonRockAdapter, SOCKS5 proxy utilities,
 * RiskEngine weighting for Infostealers & Dark Web .onion mentions, ReportExporter,
 * AuditComparator leak diffs, and SQLite leak metadata persistence.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  AhmiaAdapter,
  XposedOrNotAdapter,
  HudsonRockAdapter,
  parseProxyAddress,
  checkTorProxyHealth,
  calculateRiskScore,
  generateStandaloneHtmlReport,
  compareAudits,
  ToolOrchestrator,
} from '../../src/core/index.js';
import { createStorageEngine } from '../../src/storage/database.js';

describe('Dark Web & Breach Intelligence Adapters (Offline Fixtures)', () => {
  beforeEach(() => {
    process.env.OSINT_OFFLINE_MODE = '1';
  });

  it('AhmiaAdapter extracts Dark Web .onion mentions in offline fixture mode', async () => {
    const adapter = new AhmiaAdapter();
    const health = await adapter.checkHealth();
    expect(health.installed).toBe(true);

    const res = await adapter.execute({
      email: 'alice.dupont@example.com',
      username: 'alicedupont',
      options: { offline: true },
    });

    expect(res.success).toBe(true);
    expect(res.toolName).toBe('ahmia');
    expect(res.leaks.length).toBeGreaterThanOrEqual(2);

    const onionLeak = res.leaks[0];
    expect(onionLeak.category).toBe('darkweb');
    expect(['high', 'critical']).toContain(onionLeak.severity);
    expect(onionLeak.metadata?.onionUrl).toContain('.onion');
    expect(onionLeak.details).not.toMatch(/[-–—]/);
  });

  it('XposedOrNotAdapter extracts breaches and pastes in offline fixture mode', async () => {
    const adapter = new XposedOrNotAdapter();
    const health = await adapter.checkHealth();
    expect(health.installed).toBe(true);

    const res = await adapter.execute({
      email: 'alice.dupont@example.com',
      options: { offline: true },
    });

    expect(res.success).toBe(true);
    expect(res.toolName).toBe('xposedornot');
    expect(res.leaks.length).toBeGreaterThanOrEqual(3);

    const categories = res.leaks.map((l) => l.category);
    expect(categories).toContain('breach');
    expect(categories).toContain('paste');

    for (const leak of res.leaks) {
      expect(leak.details).not.toMatch(/[-–—]/);
    }
  });

  it('HudsonRockAdapter extracts infostealer infections for email and username in offline mode', async () => {
    const adapter = new HudsonRockAdapter();
    const health = await adapter.checkHealth();
    expect(health.installed).toBe(true);

    const res = await adapter.execute({
      email: 'alice.dupont@example.com',
      username: 'alicedupont',
      options: { offline: true },
    });

    expect(res.success).toBe(true);
    expect(res.toolName).toBe('hudsonrock');
    expect(res.leaks.length).toBeGreaterThanOrEqual(2);

    const stealerLeak = res.leaks[0];
    expect(stealerLeak.category).toBe('infostealer');
    expect(stealerLeak.severity).toBe('critical');
    expect(stealerLeak.metadata?.stealerFamily).toBeTruthy();
    expect(stealerLeak.metadata?.computerName).toBeTruthy();
    expect(stealerLeak.details).not.toMatch(/[-–—]/);
  });

  it('SOCKS5 utility parses proxy addresses and handles unreachable local Tor port gracefully', async () => {
    const parsed = parseProxyAddress('socks5://127.0.0.1:9050');
    expect(parsed.host).toBe('127.0.0.1');
    expect(parsed.port).toBe(9050);

    const deadCheck = await checkTorProxyHealth('127.0.0.1', 59999, 200);
    expect(deadCheck.available).toBe(false);
  });

  it('RiskEngine weights Infostealer (32 pts) and Dark Web .onion (20 pts) findings and generates zero-hyphen French recommendations', () => {
    const risk = calculateRiskScore(
      [],
      [
        {
          id: 'leak_hr_1',
          target: 'alice@example.com',
          sourceTool: 'hudsonrock',
          breachName: 'Infection Infostealer (RedLine)',
          dataClasses: ['sessions', 'passwords', 'cookies'],
          details: 'Poste infecte par RedLine Stealer',
          category: 'infostealer',
          severity: 'critical',
          metadata: {
            stealerFamily: 'RedLine',
            computerName: 'MACBOOK PRO',
          },
        },
        {
          id: 'leak_ahmia_1',
          target: 'alice@example.com',
          sourceTool: 'ahmia',
          breachName: 'Indexation Dark Web : Forum Dump',
          dataClasses: ['email', 'mention dark web'],
          details: 'Mention sur un service cache .onion',
          category: 'darkweb',
          severity: 'critical',
          metadata: {
            onionUrl: 'http://exampledarkweb2345.onion/dump',
          },
        },
      ]
    );

    expect(risk.breakdown.leaksScore).toBe(52);
    expect(risk.breakdown.criticalLeaksCount).toBe(2);
    expect(risk.score).toBe(52);
    expect(risk.level).toBe('elevated');
    expect(risk.recommendations.length).toBeGreaterThanOrEqual(2);

    for (const rec of risk.recommendations) {
      expect(rec.title).not.toMatch(/[-–—]/);
      expect(rec.description).not.toMatch(/[-–—]/);
    }
  });

  it('ReportExporter renders Dark Web .onion and Infostealer details with zero hyphens in French labels', () => {
    const leaks = [
      {
        id: 'leak_hr_1',
        target: 'alice@example.com',
        sourceTool: 'hudsonrock',
        breachName: 'Infection Infostealer (LummaC2)',
        dataClasses: ['sessions', 'passwords'],
        details: 'Compromission par LummaC2',
        category: 'infostealer' as const,
        severity: 'critical' as const,
        metadata: { stealerFamily: 'LummaC2' },
      },
      {
        id: 'leak_ahmia_1',
        target: 'alice@example.com',
        sourceTool: 'ahmia',
        breachName: 'Indexation Dark Web Onion',
        dataClasses: ['email'],
        details: 'Indexation Tor',
        category: 'darkweb' as const,
        severity: 'critical' as const,
        metadata: { onionUrl: 'http://abcdef1234567890.onion/paste' },
      },
    ];
    const risk = calculateRiskScore([], leaks);
    const html = generateStandaloneHtmlReport(
      { id: 'scan_dw_1', target_email: 'alice@example.com' },
      [],
      leaks,
      risk
    );

    expect(html).toContain('LummaC2');
    expect(html).toContain('Index Dark Web Tor');
    expect(html).toContain('abcdef1234567890.onion');
  });

  it('AuditComparator computes differential tracking for leaks and Dark Web alerts', () => {
    const comp = compareAudits(
      {
        accounts: [],
        leaks: [
          {
            id: 'l1',
            target: 'alice@example.com',
            sourceTool: 'xposedornot',
            breachName: 'OldBreach',
            dataClasses: ['email'],
            details: 'Ancienne breche',
          },
        ],
      },
      {
        accounts: [],
        leaks: [
          {
            id: 'l1',
            target: 'alice@example.com',
            sourceTool: 'xposedornot',
            breachName: 'OldBreach',
            dataClasses: ['email'],
            details: 'Ancienne breche',
          },
          {
            id: 'l2',
            target: 'alice@example.com',
            sourceTool: 'hudsonrock',
            breachName: 'Infection Infostealer (RedLine)',
            dataClasses: ['passwords'],
            details: 'Nouvelle alerte infostealer',
            category: 'infostealer',
          },
        ],
      }
    );

    expect(comp.leakStats?.newLeaksCount).toBe(1);
    expect(comp.leakStats?.persistentLeaksCount).toBe(1);
    expect(comp.leakStats?.resolvedLeaksCount).toBe(0);
    expect(comp.newlyExposedLeaks?.[0]?.sourceTool).toBe('hudsonrock');
  });

  it('StorageEngine persists and restores category, severity, and metadata on UnifiedLeak', () => {
    const storage = createStorageEngine(':memory:');
    const scanId = storage.createScan({
      title: 'Audit Dark Web',
      targetEmail: 'alice@example.com',
      status: 'completed',
    });

    storage.saveLeaks(scanId, [
      {
        id: 'leak_dw_persist',
        target: 'alice@example.com',
        sourceTool: 'ahmia',
        breachName: 'Service Cache Onion',
        dataClasses: ['email', 'mention dark web'],
        details: 'Mention Tor',
        category: 'darkweb',
        severity: 'critical',
        metadata: {
          onionUrl: 'http://torhiddenservice.onion/list',
          routingMode: 'offline_fixture',
        },
      },
    ]);

    const loadedLeaks = storage.getLeaksByScan(scanId);
    expect(loadedLeaks.length).toBe(1);
    expect(loadedLeaks[0].category).toBe('darkweb');
    expect(loadedLeaks[0].severity).toBe('critical');
    expect(loadedLeaks[0].metadata?.onionUrl).toBe('http://torhiddenservice.onion/list');
    storage.close();
  });

  it('ToolOrchestrator executes Ahmia, XposedOrNot, and HudsonRock in parallel and normalizes results', async () => {
    const orchestrator = new ToolOrchestrator();
    const res = await orchestrator.runScan(
      {
        email: 'alice.dupont@example.com',
        username: 'alicedupont',
        options: { offline: true },
      },
      ['ahmia', 'xposedornot', 'hudsonrock']
    );

    expect(res.summary.totalTools).toBe(3);
    expect(res.summary.successfulTools).toBe(3);
    expect(res.leaks.length).toBeGreaterThanOrEqual(5);
  });
});
