/**
 * Tool Orchestrator
 * Asynchronous, parallel execution engine for OSINT adapters with progress streaming and resilience
 */

import crypto from 'node:crypto';
import {
  ExtendedTool,
  IToolAdapter,
  OrchestratorProgressEvent,
  OrchestratorResult,
  OrchestratorTargets,
  SupportedTool,
  ToolHealth,
  ToolResult,
} from './types.js';
import { HoleheAdapter } from './adapters/holehe.js';
import { MaigretAdapter } from './adapters/maigret.js';
import { IgnorantAdapter } from './adapters/ignorant.js';
import { H8mailAdapter } from './adapters/h8mail.js';
import { GHuntAdapter } from './adapters/ghunt.js';
import { SpiderfootAdapter } from './adapters/spiderfoot.js';
import { AhmiaAdapter } from './adapters/ahmia.js';
import { XposedOrNotAdapter } from './adapters/xposedornot.js';
import { HudsonRockAdapter } from './adapters/hudsonrock.js';
import { Normalizer } from './normalizer.js';

export type ProgressListener = (event: OrchestratorProgressEvent) => void;

export interface OrchestratorOptions {
  adapters?: Partial<Record<ExtendedTool, IToolAdapter>>;
  defaultToolTimeoutMs?: number;
}

export class ToolOrchestrator {
  private adapters: Map<ExtendedTool, IToolAdapter> = new Map();
  private explicitAdapterKeys: Set<ExtendedTool> | null = null;
  private defaultToolTimeoutMs: number;
  private activeScans: Map<string, { abortController: AbortController; tools?: ExtendedTool[] }> = new Map();

  constructor(options: OrchestratorOptions = {}) {
    this.defaultToolTimeoutMs = options.defaultToolTimeoutMs ?? 60_000;
    if (options.adapters && Object.keys(options.adapters).length > 0) {
      this.explicitAdapterKeys = new Set(Object.keys(options.adapters) as ExtendedTool[]);
    }

    // Register provided adapters or instantiate defaults
    const defaultAdapters: Record<ExtendedTool, IToolAdapter> = {
      holehe: new HoleheAdapter(),
      maigret: new MaigretAdapter(),
      ignorant: new IgnorantAdapter(),
      h8mail: new H8mailAdapter(),
      ghunt: new GHuntAdapter(),
      spiderfoot: new SpiderfootAdapter(),
      ahmia: new AhmiaAdapter(),
      xposedornot: new XposedOrNotAdapter(),
      hudsonrock: new HudsonRockAdapter(),
    };

    const finalAdapters = { ...defaultAdapters, ...options.adapters };

    for (const [toolName, adapter] of Object.entries(finalAdapters)) {
      this.registerAdapter(toolName as ExtendedTool, adapter);
    }
  }

  /**
   * Register or replace an adapter
   */
  registerAdapter(name: ExtendedTool, adapter: IToolAdapter): void {
    this.adapters.set(name, adapter);
  }

  /**
   * Get an adapter by name
   */
  getAdapter(name: ExtendedTool): IToolAdapter | undefined {
    return this.adapters.get(name);
  }

  /**
   * Check health of all registered core CLI tools (or all tools if includeExtended is true)
   */
  async checkAllHealth(includeExtended = false): Promise<Record<ExtendedTool, ToolHealth>> {
    const coreSet = new Set<ExtendedTool>([
      'holehe',
      'maigret',
      'ignorant',
      'h8mail',
      'ghunt',
      'spiderfoot',
    ]);
    const results: Partial<Record<ExtendedTool, ToolHealth>> = {};
    const promises: Promise<void>[] = [];

    for (const [name, adapter] of this.adapters.entries()) {
      if (!includeExtended && !coreSet.has(name)) {
        continue;
      }
      promises.push(
        adapter
          .checkHealth()
          .then((health) => {
            results[name] = health;
          })
          .catch((err: any) => {
            results[name] = {
              installed: false,
              error: err?.message ?? 'Health check threw an error',
            };
          })
      );
    }

    await Promise.all(promises);
    return results as Record<ExtendedTool, ToolHealth>;
  }

  /**
   * Cancel an in-flight scan (or all active scans if scanId === '*')
   */
  cancelScan(scanId: string): boolean {
    if (scanId === '*') {
      let cancelledAny = false;
      for (const id of Array.from(this.activeScans.keys())) {
        if (this.cancelScan(id)) cancelledAny = true;
      }
      return cancelledAny;
    }
    const scan = this.activeScans.get(scanId);
    if (scan) {
      scan.abortController.abort();
      if (scan.tools) {
        for (const tool of scan.tools) {
          const adapter = this.adapters.get(tool);
          if (adapter) {
            try {
              if (typeof (adapter as any).abort === 'function') {
                (adapter as any).abort();
              } else if (typeof (adapter as any).abortActiveProcesses === 'function') {
                (adapter as any).abortActiveProcesses('SIGTERM');
              }
            } catch {}
          }
        }
      }
      this.activeScans.delete(scanId);
      return true;
    }
    return false;
  }

  /**
   * Run parallel OSINT scan across selected tools with live progress reporting
   */
  async runScan(
    targets: OrchestratorTargets,
    selectedTools?: ExtendedTool[],
    onProgress?: ProgressListener
  ): Promise<OrchestratorResult> {
    const scanId = `scan_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const startedAt = new Date().toISOString();
    const startTime = Date.now();

    const abortController = new AbortController();
    // Determine candidate tools
    const toolsToRun = this.determineToolsToRun(targets, selectedTools);
    this.activeScans.set(scanId, { abortController, tools: toolsToRun });

    const emitEvent = (
      tool: ExtendedTool,
      status: 'queued' | 'running' | 'completed' | 'failed' | 'skipped',
      progress?: number,
      message?: string
    ) => {
      onProgress?.({
        scanId,
        tool,
        status,
        progress,
        message,
        timestamp: new Date().toISOString(),
      });
    };

    // Initialize progress for all candidate tools
    for (const tool of toolsToRun) {
      emitEvent(tool, 'queued', 0, 'Waiting in execution queue');
    }

    const toolResults: Partial<Record<ExtendedTool, ToolResult>> = {};

    // Execute in parallel via Promise.allSettled
    const executionPromises = toolsToRun.map(async (tool) => {
      if (abortController.signal.aborted) {
        emitEvent(tool, 'skipped', 0, 'Scan was cancelled');
        return;
      }

      const adapter = this.adapters.get(tool);
      if (!adapter) {
        emitEvent(tool, 'failed', 0, `No adapter registered for ${tool}`);
        toolResults[tool] = {
          toolName: tool,
          success: false,
          durationMs: 0,
          rawOutput: null,
          error: `Adapter ${tool} not found`,
          accounts: [],
          leaks: [],
        };
        return;
      }

      // Check target eligibility
      if (!this.isTargetEligible(tool, targets)) {
        emitEvent(tool, 'skipped', 0, `Missing required target input for ${tool}`);
        toolResults[tool] = {
          toolName: tool,
          success: false,
          durationMs: 0,
          rawOutput: null,
          error: `Missing required target input for ${tool}`,
          accounts: [],
          leaks: [],
        };
        return;
      }

      emitEvent(tool, 'running', 10, `Starting ${tool}...`);

      try {
        const timeoutMs = targets.options?.[`${tool}TimeoutMs`] ?? this.defaultToolTimeoutMs;

        // Wrap execution with timeout
        const toolResult = await this.executeWithTimeout(
          adapter,
          {
            email: targets.email,
            username: targets.username,
            phone: targets.phone,
            options: targets.options,
            onProgress: (msg: string, percent?: number) => {
              emitEvent(tool, 'running', percent ?? 50, msg);
            },
          },
          timeoutMs,
          abortController.signal
        );

        toolResults[tool] = toolResult;

        if (toolResult.success) {
          emitEvent(tool, 'completed', 100, `Completed successfully in ${toolResult.durationMs}ms`);
        } else {
          emitEvent(tool, 'failed', 100, toolResult.error ?? 'Tool execution failed');
        }
      } catch (err: any) {
        const errMsg = err?.message ?? `Unknown error in ${tool}`;
        emitEvent(tool, 'failed', 100, errMsg);
        toolResults[tool] = {
          toolName: tool,
          success: false,
          durationMs: 0,
          rawOutput: null,
          error: errMsg,
          accounts: [],
          leaks: [],
        };
      }
    });

    await Promise.allSettled(executionPromises);
    this.activeScans.delete(scanId);

    // Normalize and deduplicate aggregated results
    const resultsList = Object.values(toolResults) as ToolResult[];
    const { accounts, leaks } = Normalizer.normalizeResults(resultsList);

    const completedAt = new Date().toISOString();
    const durationMs = Date.now() - startTime;

    const successfulTools = resultsList.filter((r) => r.success).length;
    const failedTools = resultsList.filter((r) => !r.success).length;

    return {
      scanId,
      startedAt,
      completedAt,
      durationMs,
      targets,
      toolResults,
      accounts,
      leaks,
      summary: {
        totalTools: toolsToRun.length,
        successfulTools,
        failedTools,
        totalAccountsFound: accounts.length,
        totalLeaksFound: leaks.length,
      },
    };
  }

  private determineToolsToRun(
    targets: OrchestratorTargets,
    selectedTools?: ExtendedTool[]
  ): ExtendedTool[] {
    const allTools: ExtendedTool[] = [
      'holehe',
      'maigret',
      'ignorant',
      'h8mail',
      'ghunt',
      'spiderfoot',
      'ahmia',
      'xposedornot',
      'hudsonrock',
    ];

    if (selectedTools && selectedTools.length > 0) {
      return selectedTools.filter((t) => allTools.includes(t));
    }

    // Default: choose tools matching provided targets
    const candidates: ExtendedTool[] = [];
    if (targets.email) {
      candidates.push('holehe', 'h8mail', 'ghunt', 'spiderfoot', 'ahmia', 'xposedornot', 'hudsonrock');
    }
    if (targets.username) {
      if (!candidates.includes('maigret')) candidates.push('maigret');
      if (!candidates.includes('h8mail')) candidates.push('h8mail');
      if (!candidates.includes('spiderfoot')) candidates.push('spiderfoot');
      if (!candidates.includes('ahmia')) candidates.push('ahmia');
      if (!candidates.includes('hudsonrock')) candidates.push('hudsonrock');
    }
    if (targets.phone) {
      if (!candidates.includes('ignorant')) candidates.push('ignorant');
      if (!candidates.includes('spiderfoot')) candidates.push('spiderfoot');
      if (!candidates.includes('ahmia')) candidates.push('ahmia');
    }

    const coreTools: ExtendedTool[] = [
      'holehe',
      'maigret',
      'ignorant',
      'h8mail',
      'ghunt',
      'spiderfoot',
    ];

    const filteredCandidates = this.explicitAdapterKeys
      ? candidates.filter((t) => this.explicitAdapterKeys!.has(t))
      : candidates;

    return filteredCandidates.length > 0 ? filteredCandidates : coreTools;
  }

  private isTargetEligible(tool: ExtendedTool, targets: OrchestratorTargets): boolean {
    switch (tool) {
      case 'holehe':
        return Boolean(targets.email && targets.email.includes('@'));
      case 'maigret':
        return Boolean(targets.username && targets.username.trim().length > 0);
      case 'ignorant':
        return Boolean(targets.phone && targets.phone.trim().length > 0);
      case 'h8mail':
        return Boolean(targets.email || targets.username);
      case 'ghunt':
        return Boolean(targets.email && targets.email.includes('@'));
      case 'spiderfoot':
        return Boolean(targets.email || targets.username || targets.phone || targets.options?.domain);
      case 'ahmia':
        return Boolean(
          (targets.email && targets.email.trim().length > 0) ||
            (targets.username && targets.username.trim().length > 0) ||
            (targets.phone && targets.phone.trim().length > 0)
        );
      case 'xposedornot':
        return Boolean(targets.email && targets.email.includes('@'));
      case 'hudsonrock':
        return Boolean(
          (targets.email && targets.email.includes('@')) ||
            (targets.username && targets.username.trim().length > 0)
        );
      default:
        return false;
    }
  }

  private async executeWithTimeout(
    adapter: IToolAdapter,
    context: any,
    timeoutMs: number,
    abortSignal: AbortSignal
  ): Promise<ToolResult> {
    if (abortSignal.aborted) {
      throw new Error('Scan was aborted before execution');
    }

    const toolAbortController = new AbortController();
    const enrichedContext = {
      ...context,
      signal: toolAbortController.signal,
    };

    const killActiveProcesses = () => {
      try {
        if (typeof (adapter as any).abort === 'function') {
          (adapter as any).abort();
        } else if (typeof (adapter as any).abortActiveProcesses === 'function') {
          (adapter as any).abortActiveProcesses('SIGTERM');
        }
      } catch {}
    };

    return new Promise<ToolResult>((resolve, reject) => {
      let settled = false;

      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          abortSignal.removeEventListener('abort', onAbort);
          toolAbortController.abort();
          killActiveProcesses();
          resolve({
            toolName: adapter.name,
            success: false,
            durationMs: timeoutMs,
            rawOutput: null,
            error: `Tool execution timed out after ${timeoutMs}ms`,
            accounts: [],
            leaks: [],
          });
        }
      }, timeoutMs);

      const onAbort = () => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          toolAbortController.abort();
          killActiveProcesses();
          resolve({
            toolName: adapter.name,
            success: false,
            durationMs: 0,
            rawOutput: null,
            error: 'Execution cancelled by user',
            accounts: [],
            leaks: [],
          });
        }
      };

      abortSignal.addEventListener('abort', onAbort, { once: true });

      adapter
        .execute(enrichedContext)
        .then((result) => {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            abortSignal.removeEventListener('abort', onAbort);
            resolve(result);
          }
        })
        .catch((err) => {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            abortSignal.removeEventListener('abort', onAbort);
            reject(err);
          }
        });
    });
  }
}
