// Handles platform events: autoplan on push, comment commands, the Apply
// button, and cleanup when a PR closes.
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { rmSync, mkdirSync, readFileSync, existsSync, realpathSync, readdirSync, statSync } from 'node:fs';
import { AsyncLocalStorage } from 'node:async_hooks';
import type { ServerConfig, RepoPolicy, Action } from './config.ts';
import type { VcsAdapter, VcsEvent, Repo, PullRequestState, Comparison, Annotation, CloneAuth } from './vcs/types.ts';
import { Store, type Run, type Grant } from './store.ts';
import { parseCommand, helpText, toolArgs, TOOL_ACTION, EDITS_STATE, type Command } from './commands.ts';
import { loadRepoConfig, loadRepoConfigFrom, emptyRepoConfig, type RepoConfig } from './repoConfig.ts';
import { discoverProjects, affectedProjects, terragruntDependencies, mockedDependencies, unappliedDependencies, type Project } from './discovery.ts';
import {
  repoPolicyFor, rulesFor, ruleMatches, checkPermission, applyBlockers, matchesPrincipal, type Lookup, type EffectiveRules,
} from './policy.ts';
import { renderComment, renderCheck, renderApplyReport, aiLines, parseApplyResult, providersOf, cmdBlock, fence, tail, type ProjectView, type CommentLinks } from './render.ts';
import { repoLinks, platformForHost } from './links.ts';
import { avatarSource, roundAvatarPath } from './avatars.ts';
import { plan as runPlan, apply as runApply, runTool, engineLabel, toolEnv, gitAuthEnv, type ToolResolver, type ToolSet } from './runner.ts';
import { checkout as gitCheckout, checkoutBranch as gitCheckoutBranch } from './git.ts';
import { adopt, adoptBody, adoptBranch, type AdoptTarget, type AdoptResult } from './adopt.ts';
import { log } from './log.ts';
import { evaluateRules, runCommands, stricter, type PolicyConfig, type PolicyResult } from './policies.ts';
import { matchGlob } from './glob.ts';
import { metrics } from './metrics.ts';
import { scanSecrets, secretNote } from './secrets.ts';
import { securityFindings } from './security-rules.ts';
import { assessRisk, extraApprovalFor, isProduction, type Risk } from './risk.ts';
import { raiseRisk, resolveAi, label, important, type Ai, type AiResult, type AiSettings, type AiFeature, type CodeComment } from './ai.ts';
import { activeFreezes, protectedHits } from './freeze.ts';
import { changeFingerprint, countApprovals, staleFor, staleText } from './safety.ts';
import { stricterMode, DEFAULT_SIZE_LIMITS, type StaleBaseMode, type SecretScanMode, type RiskConfig, type FreezeConfig, type ProtectedConfig, type SecretPattern } from './safety-config.ts';
import { locate } from './blame.ts';
import { notifyText } from './notify.ts';
import { LiveLogs, type LiveWriter } from './live.ts';
import { sensitiveValues, hideValues } from './sensitive.ts';
import type { PlanSummary } from './render.ts';

export const MARKER = '<!-- teriac:summary -->';

// Serializes work per key (one PR at a time) while other PRs run in parallel.
export class KeyedQueue {
  private tails = new Map<string, Promise<unknown>>();
  run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.tails.get(key) ?? Promise.resolve();
    const next = prev.catch(() => {}).then(fn);
    this.tails.set(key, next);
    next.finally(() => { if (this.tails.get(key) === next) this.tails.delete(key); }).catch(() => {});
    return next;
  }
  get size() { return this.tails.size; }
  async idle() { while (this.tails.size) await Promise.allSettled([...this.tails.values()]); }
}

// Caps how many terraform processes run at once across the server.
export class Semaphore {
  private active = 0;
  private waiting: (() => void)[] = [];
  private max: number;
  constructor(max: number) { this.max = max; }
  async use<T>(fn: () => Promise<T>): Promise<T> {
    if (this.active >= this.max) await new Promise<void>(r => this.waiting.push(r));
    this.active++;
    try { return await fn(); } finally {
      this.active--;
      this.waiting.shift()?.();
    }
  }
}

// Shares the server's run slots fairly between PRs (and drift checks).
// - at most `max` runs at once in total;
// - one PR (group) holds at most `perGroup` of them, so others always get a slot;
// - a freed slot goes to the waiting group with the fewest runs going.
export class FairScheduler {
  private max: number;
  private perGroup: number;
  private active = 0;
  private running = new Map<string, number>();
  private waiting: { group: string; go: () => void; drop: (e: Error) => void }[] = [];

  constructor(max: number, perGroup: number) {
    this.max = Math.max(1, max);
    this.perGroup = Math.max(1, Math.min(perGroup, this.max));
  }

  private count(g: string) { return this.running.get(g) ?? 0; }
  private fits(g: string) { return this.active < this.max && this.count(g) < this.perGroup; }
  private take(g: string) { this.active++; this.running.set(g, this.count(g) + 1); }

  private pump() {
    while (this.active < this.max) {
      let best = -1;
      for (let i = 0; i < this.waiting.length; i++) {
        const g = this.waiting[i].group;
        if (this.count(g) >= this.perGroup) continue;
        if (best < 0 || this.count(g) < this.count(this.waiting[best].group)) best = i;
      }
      if (best < 0) return;
      const [w] = this.waiting.splice(best, 1);
      this.take(w.group);
      w.go();
    }
  }

  async use<T>(group: string, fn: () => Promise<T>): Promise<T> {
    if (this.fits(group) && !this.waiting.length) this.take(group);
    else await new Promise<void>((go, drop) => { this.waiting.push({ group, go, drop }); this.pump(); });
    try {
      return await fn();
    } finally {
      this.active--;
      const n = this.count(group) - 1;
      if (n > 0) this.running.set(group, n); else this.running.delete(group);
      this.pump();
    }
  }

  // Drops a group's waiting work (`teriac cancel`); returns how many were dropped.
  cancel(group: string): number {
    const dropped = this.waiting.filter(w => w.group === group);
    this.waiting = this.waiting.filter(w => w.group !== group);
    for (const w of dropped) w.drop(new Cancelled());
    return dropped.length;
  }

  get stats() { return { active: this.active, waiting: this.waiting.length, groups: Object.fromEntries(this.running) }; }
}

export class Cancelled extends Error { constructor() { super('cancelled'); } }

// One reply per command, right under it. In "loading" mode it appears at once
// as "⏳ Running …" and is edited into the outcome when the command finishes.
export class Reply {
  private adapter: VcsAdapter;
  private repo: Repo;
  private number: number;
  private spinner: string | null;
  private id: string | null = null;
  private lines: string[] = [];
  // `spinner` is the animated icon's URL; without one there is no "Running…" reply.
  constructor(adapter: VcsAdapter, repo: Repo, number: number, spinner: string | null) {
    this.adapter = adapter; this.repo = repo; this.number = number; this.spinner = spinner;
  }
  async start(text: string) {
    if (!this.spinner) return;
    // alt="👀": if GitHub can't load the picture, the eyes show instead.
    const icon = `<img src="${this.spinner}" width="16" height="16" align="center" alt="👀">`;
    this.id = await this.adapter.comment(this.repo, this.number, `${icon} ${text}`).catch(() => null);
  }
  say(text: string) { this.lines.push(text); }
  async send() {
    // A "Running…" reply must never be left spinning.
    if (!this.lines.length && this.id) this.lines.push('✅ Done.');
    if (!this.lines.length) return;
    const body = this.lines.join('\n\n');
    if (this.id) await this.adapter.editComment(this.repo, this.id, body);
    else await this.adapter.comment(this.repo, this.number, body);
    this.lines = [];
  }
}

const sizeText = (summary: string | null): string => {
  if (!summary) return '';
  const x = JSON.parse(summary) as { add: number; change: number; destroy: number; replace: number; noChanges: boolean };
  if (x.noChanges) return 'no changes';
  return [x.add && `+${x.add}`, x.change && `~${x.change}`, x.replace && `±${x.replace}`, x.destroy && `−${x.destroy}`].filter(Boolean).join(' ') || 'outputs only';
};

// What a plan can be asked for from a PR comment.
type PlanOpts = { destroy?: boolean; targets?: string[]; extraArgs?: string[]; refreshOnly?: boolean; replace?: string[] };

export interface AppDeps {
  config: ServerConfig;
  store: Store;
  resolver: ToolResolver;
  checkout?: typeof gitCheckout;
  checkoutBranch?: typeof gitCheckoutBranch;   // a branch's tip (teriac adopt)
  env?: NodeJS.ProcessEnv;
  live?: LiveLogs;                // live output for the dashboard
  ai?: Ai;                        // AI reviews and help (TERIAC_AI_PROVIDER)
}

// A -var-file (after `--`) must be a file inside the checkout, following symlinks: Terraform
// quotes lines of a file it can't parse, so one outside could leak (a mounted key, say).
export const varFileEscape = (root: string, project: Project, args: string[]): string | null => {
  const files: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i].replace(/^--/, '-');
    if (a === '-var-file') files.push(args[++i] ?? '');
    else if (a.startsWith('-var-file=')) files.push(a.slice('-var-file='.length));
  }
  if (!files.length) return null;
  let top: string;
  try { top = realpathSync(root); } catch { return 'the checkout is missing'; }
  const cwd = project.dir === '.' ? root : join(root, project.dir);
  for (const f of files) {
    let real: string;
    try { real = realpathSync(join(cwd, f)); } catch { return `\`-var-file\` ${f} doesn't exist in the repo`; }
    if (real !== top && !real.startsWith(`${top}/`)) return `\`-var-file\` ${f} points outside the repo`;
  }
  return null;
};

export interface AppliesPause { by: string; via: string; at: string; reason: string }
const PAUSE_KEY = 'applies_paused';
const pausedText = (p: AppliesPause) => `applies are paused from the teriac dashboard by ${p.by} since ${p.at.slice(0, 16).replace('T', ' ')} UTC (${p.reason})`;

interface PrContext {
  adapter: VcsAdapter;
  repo: Repo;
  repoKey: string;
  policy: RepoPolicy;
  pr: PullRequestState;
  root: string;
  projects: Project[];
  rulesConfig: RepoConfig;        // from the base branch
  warnings: string[];
  lookup: Lookup;
  summaryUrl?: string | null;     // the summary comment, for links from replies
  moduleAuth?: CloneAuth | null;  // read-only git credentials for module downloads
  // Per-request caches for the platform's compare view.
  fingerprints?: Map<string, Promise<string | null>>;
  baseChanges?: Promise<Comparison | null>;
  carried?: string[];             // approvals kept across a rebase (for the comment)
}

// The safety settings in force for a PR: server and repo (repos.yaml), tightened by teriac.yaml.
interface Safety {
  reapproveOnChange: boolean;
  keepOnRebase: boolean;
  staleBase: StaleBaseMode;
  verifyPlan: boolean;
  secretMode: SecretScanMode;
  secretPatterns: SecretPattern[];
  risk?: RiskConfig;
  freezes: FreezeConfig;
  protected: ProtectedConfig;
}



const slug = (s: string) => s.replace(/[^A-Za-z0-9._-]+/g, '_');
const sha256File = (file: string) => createHash('sha256').update(readFileSync(file)).digest('hex');
// The lowest limit set (server or repo), else the default; medium always stays below high.
const sizeLimits = (...sets: ({ medium?: number; high?: number } | undefined)[]) => {
  const pick = (k: 'medium' | 'high') => {
    const set = sets.map(s => s?.[k]).filter((n): n is number => n !== undefined);
    return set.length ? Math.min(...set) : DEFAULT_SIZE_LIMITS[k];
  };
  const high = pick('high');
  return { medium: Math.min(pick('medium'), high - 1), high };
};
// Who may override, in words, with links: "[marcdomain](profile)", "team [sre](team page)",
// "people with maintain access".
const overriders = (who: string[], repo: Repo) => {
  const names = who.map(p => {
    if (p.startsWith('user:')) {
      const login = p.slice(5);
      return repo.platform === 'github' ? `[${login}](https://${repo.host}/${encodeURIComponent(login)})` : login;
    }
    if (p.startsWith('team:')) {
      const t = p.slice(5);
      const [org, slug] = t.includes('/') ? t.split('/') : [repo.owner, t];
      return repo.platform === 'github' ? `team [${slug}](https://${repo.host}/orgs/${encodeURIComponent(org)}/teams/${encodeURIComponent(slug)})` : `team ${t}`;
    }
    return p === 'codeowners' ? 'the code owners' : p === 'anyone' ? 'anyone' : `people with ${p} access`;
  });
  return names.length > 1 ? `${names.slice(0, -1).join(', ')} or ${names.at(-1)}` : names[0];
};
// ---- what `ask` can see ----

// A run as text for the AI: status, counts, risk, findings, review, and the end of its output.
const runDigest = (r: Run): string => {
  const s = r.summary ? JSON.parse(r.summary) as PlanSummary : null;
  const pol = r.policy ? JSON.parse(r.policy) as PolicyResult : null;
  return [
    `## ${r.kind} of ${r.project} (${r.dir || r.project}, workspace ${r.workspace}): ${r.status}, run ${r.id} by ${r.user}, ${r.engine}`,
    s ? `Changes: ${s.changes.map(c => `${c.action} ${c.address}${c.reason ? ` (because ${c.reason})` : ''}`).join('; ') || 'none'}` : '',
    r.risk ? `Risk: ${r.risk.level}${r.risk.reasons.length ? ` (${r.risk.reasons.join('; ')})` : ''}` : '',
    pol?.findings.length ? `Policy (${pol.mode}): ${pol.findings.map(f => `${f.rule} on ${f.address}: ${f.message.split('\n')[0]}`).join('; ')}` : '',
    r.ai?.kind === 'review' ? `Earlier AI review: ${r.ai.summary}` : r.ai?.kind === 'fix' ? `Earlier AI diagnosis: ${r.ai.cause}` : '',
    `Output (end):\n${tail(r.output, 3000)}`,
  ].filter(Boolean).join('\n');
};

const readJson = (file: string): Record<string, any> | null => { try { return JSON.parse(readFileSync(file, 'utf-8')); } catch { return null; } };

// Read-only tools over runs: one resource's planned change, and a run's full output.
const runTools = (runs: Run[]) => {
  const find = (project: string) => runs.find(r => r.project === project);
  return [
    {
      name: 'plan_resource_change',
      description: 'The planned before/after values of one resource from a project\'s saved plan (sensitive values hidden).',
      schema: { type: 'object', properties: { project: { type: 'string' }, address: { type: 'string' } }, required: ['project', 'address'], additionalProperties: false },
      run: ({ project, address }: { project: string; address: string }) => {
        const r = find(project);
        const plan = r?.planPath ? readJson(`${r.planPath}.json`) : null;
        if (!plan) return `no saved plan for project ${project} (plans are dropped when a lock is released or the PR closes)`;
        const rc = (plan.resource_changes ?? []).find((x: any) => x.address === address);
        if (!rc) return `no change to ${address} in ${project}'s plan`;
        return hideValues(JSON.stringify({ address, actions: rc.change?.actions, replace_paths: rc.change?.replace_paths, before: rc.change?.before, after: rc.change?.after, after_unknown: rc.change?.after_unknown }), sensitiveValues(plan));
      },
    },
    {
      name: 'run_output',
      description: 'The full console output of a project\'s latest run (cleaned of secrets).',
      schema: { type: 'object', properties: { project: { type: 'string' } }, required: ['project'], additionalProperties: false },
      run: ({ project }: { project: string }) => tail(find(project)?.output ?? `no run for ${project}`, 30_000),
    },
  ];
};

// Read-only tools over the PR's checkout: list a folder, read a file (never outside it, never .git).
// `dirs`: the project folders it may look in (projects with AI off stay out).
const checkoutTools = (root: string, dirs: string[]) => {
  const inside = (path: string): string | null => {
    try {
      const top = realpathSync(root);
      const real = realpathSync(join(top, path));
      if (real !== top && !real.startsWith(`${top}/`)) return null;
      const rel = real.slice(top.length);
      const relDir = rel.replace(/^\//, '');
      // A project folder, something inside one, or a parent folder on the way to one (to list it).
      if (!dirs.some(d => d === '.' || relDir === d || relDir.startsWith(`${d}/`) || d.startsWith(relDir ? `${relDir}/` : ''))) return null;
      // Never: git internals, provider caches, state, env files, keys and certificates.
      if (rel.split('/').some(p => p === '.git' || p === '.terraform') || /(\.tfstate(\.backup)?|\/\.env[^/]*|\.pem|\.key|\.p12|\.pfx|id_rsa[^/]*|\.kube\/config)$/i.test(rel)) return null;
      return real;
    } catch { return null; }
  };
  return [
    {
      name: 'list_files',
      description: 'Files and folders in a folder of the pull request\'s code, relative to the repo root ("." for the root).',
      schema: { type: 'object', properties: { dir: { type: 'string' } }, required: ['dir'], additionalProperties: false },
      run: ({ dir }: { dir: string }) => {
        const real = inside(dir);
        if (!real) return `${dir}: not found`;
        const top = realpathSync(root);
        return readdirSync(real, { withFileTypes: true }).filter(d => d.name !== '.git' && d.name !== '.terraform' && inside(join(real.slice(top.length), d.name)))
          .slice(0, 300).map(d => `${d.name}${d.isDirectory() ? '/' : ''}`).join('\n') || '(nothing you can see here)';
      },
    },
    {
      name: 'read_file',
      description: 'A file of the pull request\'s code, relative to the repo root, with line numbers.',
      schema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'], additionalProperties: false },
      run: ({ path }: { path: string }) => {
        const real = inside(path);
        // Only files inside a visible project's folder, not the folders on the way.
        if (!real || !statSync(real).isFile() || !dirs.some(d => d === '.' || real.slice(realpathSync(root).length + 1).startsWith(`${d}/`))) return `${path}: not found`;
        return readFileSync(real, 'utf-8').slice(0, 60_000).split('\n').map((l, i) => `${String(i + 1).padStart(4)}| ${l}`).join('\n');
      },
    },
  ];
};

const summaryOf = (run: Run | undefined): PlanSummary | null => (run?.summary ? JSON.parse(run.summary) as PlanSummary : null);

export class App {
  private queue = new KeyedQueue();
  // Check page per PR project (where GitHub shows the Apply button).
  private checkUrls = new Map<string, string>();
  private sched: FairScheduler;
  private deps: AppDeps;
  private checkout: typeof gitCheckout;
  readonly live: LiveLogs;
  private runningPlans = new Map<string, Set<AbortController>>();

  constructor(deps: AppDeps) {
    this.deps = deps;
    this.sched = new FairScheduler(deps.config.parallelism, deps.config.prParallelism ?? Math.max(1, deps.config.parallelism - 1));
    this.checkout = deps.checkout ?? gitCheckout;
    this.live = deps.live ?? new LiveLogs();
    // Terraform refuses to use a plugin cache dir that doesn't exist.
    mkdirSync(join(deps.config.dataDir, 'plugin-cache'), { recursive: true });
  }

  idle() { return this.queue.idle(); }

  // Shares the server-wide limit on concurrent terraform processes (drift uses it too).
  limited<T>(fn: () => Promise<T>, group = 'drift'): Promise<T> { return this.sched.use(group, fn); }
  get schedulerStats() { return this.sched.stats; }

  // Entry point for every webhook. Returns once the work has finished.
  // Newest commit of each PR, recorded as push events arrive (before they queue), so
  // plans still waiting for an older commit can skip themselves and free the slot.
  private latestHead = new Map<string, string>();
  private outdated(ctx: PrContext): boolean {
    const latest = this.latestHead.get(`${ctx.repoKey}#${ctx.pr.number}`);
    return !!latest && latest !== ctx.pr.headSha;
  }

  // Runs going and waiting right now, for the Metrics page.
  get runQueue() { return this.sched.stats; }
  get commandName() { return this.deps.config.commandNames[0]; }

  // Wraps an adapter so every comment teriac writes is remembered exactly as written.
  private recording(adapter: VcsAdapter): VcsAdapter {
    const store = this.deps.store;
    const keyOf = (repo: Repo) => `${repo.host}/${repo.fullName}`;
    const prOf = new Map<string, number>();
    return Object.assign(Object.create(adapter), {
      comment: async (repo: Repo, number: number, body: string) => {
        const id = await adapter.comment(repo, number, body);
        if (id) { prOf.set(id, number); store.rememberBotComment(keyOf(repo), number, id, body); }
        return id;
      },
      editComment: async (repo: Repo, id: string, body: string) => {
        await adapter.editComment(repo, id, body);
        const pr = prOf.get(id) ?? store.botComment(keyOf(repo), id)?.pr;
        if (pr !== undefined) store.rememberBotComment(keyOf(repo), pr, id, body);
      },
      upsertComment: async (repo: Repo, number: number, marker: string, body: string, knownId?: string | null) => {
        const r = await adapter.upsertComment(repo, number, marker, body, knownId);
        if (r) { prOf.set(r.id, number); store.rememberBotComment(keyOf(repo), number, r.id, body); }
        return r;
      },
    }) as VcsAdapter;
  }

  // Someone edited or deleted teriac's comment. It's left as it is; teriac posts a warning
  // that links to it and carries the original, and audits it. (teriac never reads its
  // comments back, so an edit can't change what gets applied.)
  private async commentChanged(adapter: VcsAdapter, e: Extract<VcsEvent, { kind: 'bot_comment_changed' }>): Promise<void> {
    const repoKey = `${e.repo.host}/${e.repo.fullName}`;
    const saved = this.deps.store.botComment(repoKey, e.commentId);
    if (!saved) return; // another bot's comment
    if (e.change === 'edited' && e.body === saved.body) return;
    const url = repoLinks(repoKey, platformForHost(e.repo.host, { [e.repo.host]: e.repo.platform })).comment(e.prNumber, e.commentId);
    // The original, minus teriac's hidden markers so it is never mistaken for the live comment.
    const original = saved.body.replace(/<!--\s*teriac:[^>]*-->\n?/g, '');
    const room = adapter.commentLimit - 1200;
    const shown = original.length > room ? `${original.slice(0, room)}\n\n_…cut short; the full plan is on the check run and the dashboard._` : original;
    await adapter.comment(e.repo, e.prNumber, [
      '> [!WARNING]',
      e.change === 'edited'
        ? `> **[teriac's comment](${url}) was edited by ${e.by}.** It no longer shows what teriac wrote. This was logged.`
        : `> **A teriac comment was deleted by ${e.by}.** This was logged.`,
      `> teriac only acts on its own records (saved plans, check runs, the dashboard), never on comment text.`,
      '',
      `<details><summary>View the original</summary>`,
      '',
      shown,
      '',
      '</details>',
    ].join('\n'));
    this.deps.store.audit({ repo: repoKey, pr: e.prNumber, user: e.by, action: `comment_${e.change}`, project: '', allowed: false, reason: `${e.change} teriac comment ${e.commentId} (${url})` });
    log.warn('teriac comment changed by someone else', { repo: repoKey, pr: e.prNumber, by: e.by, change: e.change });
  }

  // Shutting down: running work finishes, new and queued events are saved for the next start.
  private draining = false;
  drain() { this.draining = true; }
  get isDraining() { return this.draining; }

  private park(adapter: VcsAdapter, event: VcsEvent) {
    this.deps.store.savePendingEvent(adapter.platform, event);
    log.info('shutting down: event saved for the next start', { kind: event.kind, repo: 'repo' in event ? `${event.repo.host}/${event.repo.fullName}` : '' });
  }

  // On start: the events saved while the last server shut down, in order.
  async replayPending(adapterFor: (platform: string) => VcsAdapter | undefined): Promise<number> {
    const pending = this.deps.store.takePendingEvents();
    for (const p of pending) {
      const adapter = adapterFor(p.platform);
      if (!adapter) continue;
      log.info('replaying an event saved at shutdown', { kind: p.event.kind });
      await this.handle(adapter, p.event as VcsEvent).catch(err => log.error('replayed event failed', { err }));
    }
    return pending.length;
  }

  // On start: runs a restart or crash cut short. They're marked failed, their checks are
  // finished, half-written plans are dropped, and each PR is told what to do next.
  async recoverInterrupted(adapterFor: (host: string) => VcsAdapter | undefined): Promise<number> {
    const { store } = this.deps;
    const runs = store.unfinishedRuns();
    const byPr = new Map<string, Run[]>();
    for (const r of runs) {
      store.finishRun(r.id, { status: 'failed', engine: r.engine, summary: r.summary, output: `${r.output ? `${r.output}\n` : ''}[teriac] the server restarted while this ran, so it stopped here.` });
      if (r.kind === 'plan') store.discardPlans(r.repo, r.pr, r.project).forEach(p => { rmSync(p, { force: true }); rmSync(`${p}.json`, { force: true }); });
      store.audit({ repo: r.repo, pr: r.pr, user: r.user, action: `${r.kind}_interrupted`, project: r.project, allowed: false, reason: 'the server restarted while this ran' });
      byPr.set(`${r.repo}#${r.pr}`, [...(byPr.get(`${r.repo}#${r.pr}`) ?? []), r]);
    }
    const cmd = this.deps.config.commandNames[0];
    for (const list of byPr.values()) {
      const [host, owner, ...rest] = list[0].repo.split('/');
      const adapter = adapterFor(host);
      if (!adapter) continue;
      const repo: Repo = { platform: adapter.platform, host, owner, name: rest.join('/'), fullName: `${owner}/${rest.join('/')}`, cloneUrl: '' };
      for (const r of list) {
        await adapter.setCheck(repo, { name: `teriac: ${r.project}`, headSha: r.headSha, externalId: r.project, status: 'completed', conclusion: 'cancelled',
          title: `${r.kind === 'apply' ? 'Apply' : 'Plan'} stopped: teriac restarted`, summary: `teriac restarted while this ${r.kind} ran. See the PR for what to do next.` }).catch(() => {});
      }
      const applies = list.filter(r => r.kind === 'apply').map(r => r.project);
      const plans = list.filter(r => r.kind !== 'apply').map(r => r.project);
      const lines = ['⚠️ **teriac restarted while this PR had work running**, so it stopped.'];
      if (plans.length) lines.push(`- Plan of ${plans.map(p => `\`${p}\``).join(', ')}: nothing was changed. Comment \`${cmd} plan\` to plan again.`);
      for (const p of applies) {
        lines.push(`- Apply of \`${p}\`: it may have stopped part-way. Comment \`${cmd} plan -p ${p}\` to see what's left, then apply that plan. If Terraform says the state is locked, release it with \`${cmd} force-unlock -p ${p} <lock-id>\`.`);
      }
      await adapter.comment(repo, list[0].pr, lines.join('\n')).catch(err => log.warn('could not tell the PR about an interrupted run', { err: (err as Error).message }));
    }
    if (runs.length) log.warn('runs cut short by a restart were marked failed', { runs: runs.length });
    return runs.length;
  }

  async handle(rawAdapter: VcsAdapter, event: VcsEvent): Promise<void> {
    if (event.kind === 'ignored') return;
    const adapter = this.recording(rawAdapter);
    const policy = repoPolicyFor(this.deps.config.repos, event.repo);
    if (!policy) {
      log.info('repo not allowed; ignoring', { repo: `${event.repo.host}/${event.repo.fullName}` });
      return;
    }
    const number = 'pr' in event ? event.pr.number : event.prNumber;
    const key = `${event.repo.host}/${event.repo.fullName}#${number}`;
    // `cancel` must not wait behind the work it cancels: it skips the PR's event queue.
    if (event.kind === 'comment') {
      const c = parseCommand(event.body, this.deps.config.commandNames);
      if (c?.ok && c.command.verb === 'cancel') {
        const reply = new Reply(adapter, event.repo, number, null);
        const ack = this.ack(policy);
        if (ack !== 'none') await adapter.react(event.repo, number, event.commentId, ack).catch(() => {});
        return this.respond(reply, () => this.cancel(adapter, event.repo, number, event.author, reply));
      }
    }
    if (event.kind === 'api_command') {
      const c = parseCommand(event.text, this.deps.config.commandNames);
      if (c?.ok && c.command.verb === 'cancel') {
        const reply = new Reply(adapter, event.repo, number, null);
        reply.say(`_From the teriac API, by ${event.user} (${event.via})._`);
        return this.respond(reply, () => this.cancel(adapter, event.repo, number, event.user, reply));
      }
    }
    if (this.draining) return this.park(rawAdapter, event);
    if (event.kind === 'pr_opened' || event.kind === 'pr_updated') this.latestHead.set(key, event.pr.headSha);
    if (event.kind === 'pr_closed') this.latestHead.delete(key);
    return this.queue.run(key, async () => {
      // Queued behind other work when shutdown began: run it after the restart instead.
      if (this.draining) return this.park(rawAdapter, event);
      try {
        switch (event.kind) {
          case 'pr_opened': case 'pr_updated':
            this.deps.store.markPrOpen(this.repoKey(event.repo), number);
            return await this.autoplan(adapter, policy, event.repo, number);
          case 'pr_closed': return await this.closed(event.repo, number, event.merged);
          case 'bot_comment_changed': return await this.commentChanged(adapter, event);
          case 'comment': return await this.onComment(adapter, policy, event.repo, number, event.author, event.body, event.commentId);
          case 'api_command': {
            const parsed = parseCommand(event.text, this.deps.config.commandNames);
            if (!parsed?.ok) return;
            const reply = new Reply(adapter, event.repo, number, this.spinner(policy));
            const cmdName = this.deps.config.commandNames[0];
            await reply.start(`Running \`${event.text.slice(0, 120)}\` for ${event.user} (from the teriac API, ${event.via})…`);
            reply.say(`_\`${event.text.slice(0, 120)}\`, run for ${event.user} from the teriac API (${event.via})._`);
            this.deps.store.audit({ repo: this.repoKey(event.repo), pr: number, user: event.user, action: 'api_command', project: parsed.command.project ?? '*', allowed: true, reason: `\`${event.text}\` from the API (${event.via}); ${cmdName} checks permissions next` });
            return await this.respond(reply, () => this.runCommand(adapter, policy, event.repo, number, event.user, parsed.command, reply));
          }
          case 'apply_button': {
            const reply = new Reply(adapter, event.repo, number, this.spinner(policy));
            await reply.start(`Applying \`${event.project}\` (Apply button pressed by ${event.user})…`);
            return await this.respond(reply, () => this.runCommand(adapter, policy, event.repo, number, event.user,
              { verb: 'apply', project: event.project, destroy: false, override: false, targets: [], extraArgs: [] }, reply));
          }
        }
      } catch (err) {
        log.error('event failed', { key, kind: event.kind, err });
        await adapter.comment(event.repo, number, `⚠️ teriac hit an error: ${(err as Error).message}`).catch(() => {});
      }
    });
  }

  // ---- context ----

  private repoKey(repo: Repo) { return `${repo.host}/${repo.fullName}`; }

  private workDir(repo: Repo, pr: number) {
    return join(this.deps.config.dataDir, 'work', repo.host, repo.owner, repo.name, String(pr));
  }

  private planDir(repo: Repo, pr: number) {
    return join(this.deps.config.dataDir, 'plans', repo.host, repo.owner, repo.name, String(pr));
  }

  private async context(adapter: VcsAdapter, policy: RepoPolicy, repo: Repo, number: number): Promise<PrContext> {
    const pr = await adapter.getPullRequest(repo, number);
    const root = this.workDir(repo, number);
    // checkout: merge plans the PR merged into its base branch (GitHub's refs/pull/N/merge).
    await this.checkout(root, await adapter.cloneAuth(repo), pr.headSha, `refs/pull/${number}/head`, policy.checkout === 'merge' ? `refs/pull/${number}/merge` : undefined);
    const moduleAuth = await this.moduleAuth(adapter, repo);

    const allowRepoConfig = policy.allow_repo_config !== false;
    const headConfig = allowRepoConfig ? loadRepoConfig(root) : emptyRepoConfig();
    // Rules come from the base branch, so a PR can't loosen its own rules.
    const rulesConfig = allowRepoConfig
      ? await loadRepoConfigFrom(f => adapter.fileAt(repo, f, pr.baseRef))
      : headConfig;
    const projects = discoverProjects(root, headConfig);
    const lookup: Lookup = {
      permission: u => adapter.userPermission(repo, u),
      inTeam: (t, u) => adapter.inTeam(repo, t, u),
      codeowners: () => adapter.codeowners(repo, pr.baseRef),
    };
    return {
      adapter, repo, repoKey: this.repoKey(repo), policy, pr, root, projects, rulesConfig,
      warnings: headConfig.warnings, lookup, moduleAuth,
    };
  }

  private rules(ctx: PrContext, project: Project): EffectiveRules {
    return rulesFor(project, ctx.policy, ctx.rulesConfig);
  }

  // Releasing another PR's lock from the dashboard: the `unlock` permission (default
  // maintain), from repos.yaml and the teriac.yaml on that PR's base branch, as a PR uses.
  async mayUnlock(adapter: VcsAdapter, lock: { repo: string; project: string; workspace: string; pr: number }, user: string): Promise<{ allowed: boolean; reason: string }> {
    const [host, owner, ...rest] = lock.repo.split('/');
    const name = rest.join('/');
    const repo: Repo = { platform: adapter.platform, host, owner, name, fullName: `${owner}/${name}`, cloneUrl: '' };
    const policy = repoPolicyFor(this.deps.config.repos, repo);
    if (!policy) return { allowed: false, reason: 'this repo is not served here' };
    const pr = await adapter.getPullRequest(repo, lock.pr).catch(() => null);
    const base = pr?.baseRef ?? repo.defaultBranch ?? 'main';
    const repoConfig = policy.allow_repo_config === false ? emptyRepoConfig()
      : await loadRepoConfigFrom(f => adapter.fileAt(repo, f, base)).catch(() => emptyRepoConfig());
    const dir = this.deps.store.latestRuns(lock.repo, lock.pr, 'plan').find(r => r.project === lock.project)?.dir || lock.project;
    const project = { name: lock.project, dir, workspace: lock.workspace } as Project;
    const lookup: Lookup = {
      permission: u => adapter.userPermission(repo, u),
      inTeam: (t, u) => adapter.inTeam(repo, t, u),
      codeowners: () => adapter.codeowners(repo, base),
    };
    return checkPermission('unlock', user, project, rulesFor(project, policy, repoConfig), lookup);
  }

  private async allowed(ctx: PrContext, action: Action, user: string, project: Project) {
    let decision = await checkPermission(action, user, project, this.rules(ctx, project), ctx.lookup);
    // Emergency access: a time-limited grant from the dashboard covers this action.
    if (!decision.allowed) {
      const grant = this.grantFor(ctx, user, project, action);
      if (grant) {
        decision = { allowed: true, reason: `emergency access #${grant.id} from ${grant.grantedBy} (until ${grant.expiresAt}): ${grant.reason}` };
        this.useGrant(grant, ctx, project, action);
      }
    }
    this.deps.store.audit({
      repo: ctx.repoKey, pr: ctx.pr.number, user, action, project: project.name,
      allowed: decision.allowed, reason: decision.reason,
    });
    return decision;
  }

  // ---- safety settings and checks ----

  private safety(ctx: PrContext): Safety {
    const { config } = this.deps;
    const p = ctx.policy;
    const rc = p.allow_repo_config === false ? null : ctx.rulesConfig;
    return {
      reapproveOnChange: (p.reapprove_on_change ?? true) || rc?.reapprove_on_change === true,
      keepOnRebase: (p.keep_approval_on_rebase ?? false) && rc?.keep_approval_on_rebase !== false,
      staleBase: stricterMode(p.stale_base ?? 'warn', rc?.stale_base, 'warn'),
      verifyPlan: p.verify_plan !== false,
      secretMode: stricterMode(config.secretScan?.mode ?? 'redact', p.secret_scan, 'redact'),
      secretPatterns: [...(config.secretScan?.patterns ?? []), ...(p.secret_patterns ?? [])],
      risk: p.risk || config.risk ? {
        production: p.risk?.production ?? config.risk?.production,
        extra_approval: { ...config.risk?.extra_approval, ...p.risk?.extra_approval },
        // A repo adds stateful types and can lower the size limits, never raise them.
        stateful_types: [...(config.risk?.stateful_types ?? []), ...(p.risk?.stateful_types ?? [])],
        size_limits: sizeLimits(config.risk?.size_limits, p.risk?.size_limits),
      } : undefined,
      // Server-wide and per-repo entries add up; each carries its own override list.
      freezes: [...(config.freezes ?? []), ...(p.freezes ?? [])],
      protected: [...(config.protected ?? []), ...(p.protected ?? [])],
    };
  }

  // The PR's own changes at `sha`, fingerprinted (see safety.ts). Cached per request.
  private fingerprint(ctx: PrContext, sha: string): Promise<string | null> {
    ctx.fingerprints ??= new Map();
    let f = ctx.fingerprints.get(sha);
    if (!f) {
      f = ctx.adapter.compare
        ? ctx.adapter.compare(ctx.repo, ctx.pr.baseRef, sha).then(changeFingerprint).catch(err => { log.warn('compare failed', { err: (err as Error).message }); return null; })
        : Promise.resolve(null);
      ctx.fingerprints.set(sha, f);
    }
    return f;
  }

  // Commits on the base branch since this branch left it (cached per request).
  private baseChanges(ctx: PrContext): Promise<Comparison | null> {
    ctx.baseChanges ??= ctx.adapter.compare
      ? ctx.adapter.compare(ctx.repo, ctx.pr.headSha, ctx.pr.baseRef).catch(err => { log.warn('compare failed', { err: (err as Error).message }); return null; })
      : Promise.resolve(null);
    return ctx.baseChanges;
  }

  // "main has 2 newer commits touching this project", or null.
  private async stale(ctx: PrContext, project: Project): Promise<string | null> {
    const mode = this.safety(ctx).staleBase;
    if (mode === 'off') return null;
    const commits = staleFor(project, ctx.projects, await this.baseChanges(ctx));
    return commits ? staleText(commits, ctx.pr.baseRef, project.name, mode === 'block') : null;
  }

  // An unexpired grant for `user` on this project (for `action`, or any action).
  private grantFor(ctx: PrContext, user: string, project: Project, action?: string): Grant | null {
    return this.deps.store.activeGrants().find(g =>
      g.user.toLowerCase() === user.toLowerCase()
      && (g.repo === '*' || matchGlob(g.repo, ctx.repoKey))
      && (!g.projects.length || g.projects.some(x => matchGlob(x, project.name) || matchGlob(x, project.dir)))
      && (!action || g.actions.includes(action))) ?? null;
  }

  private useGrant(grant: Grant, ctx: PrContext, project: Project, action: string) {
    const first = !grant.usedAt;
    this.deps.store.markGrantUsed(grant.id);
    if (!first) return;
    const notify = this.deps.config.breakGlass?.notify ?? [];
    if (!notify.length) return;
    void notifyText(notify, this.deps.config.channels, {
      title: `🚨 Emergency access #${grant.id} used by ${grant.user}`,
      lines: [`${action} on \`${project.name}\` in ${ctx.repo.fullName} PR #${ctx.pr.number}`, `Granted by ${grant.grantedBy}: ${grant.reason}`, `Expires ${grant.expiresAt}`],
      event: 'teriac.break_glass.used', data: { grant, project: project.name, pr: ctx.pr.number, action },
    }, { people: this.deps.config.people, env: this.deps.env ?? process.env });
  }

  // Hides possible secrets in tool output; "fail" mode also refuses to keep the run.
  // A PR from a fork runs an outsider's code with this server's credentials (cloud access,
  // state, the GitHub App), so it isn't planned or applied unless the repo allows forks.
  private async forkRefusal(adapter: VcsAdapter, policy: RepoPolicy, repo: Repo, number: number): Promise<string | null> {
    if (policy.allow_fork_prs) return null;
    const pr = await adapter.getPullRequest(repo, number);
    if (!pr.fromFork) return null;
    return '🚫 teriac doesn\'t plan or apply pull requests from forks: their code would run with this server\'s credentials. '
      + 'Push the branch to this repository instead, or ask an admin to allow forks for this repo (`allow_fork_prs: true` in repos.yaml).';
  }

  // Runs `fn` in this PR's turn; false when `teriac cancel` dropped it before it started.
  // How long the current run waited for a slot, for the run it starts (each run its own value).
  private waited = new AsyncLocalStorage<{ ms: number }>();

  private async inTurn(ctx: PrContext, fn: () => Promise<unknown>): Promise<boolean> {
    const asked = Date.now();
    try {
      await this.sched.use(`${ctx.repoKey}#${ctx.pr.number}`, () => this.waited.run({ ms: Date.now() - asked }, fn));
      return true;
    } catch (err) {
      if (err instanceof Cancelled) return false;
      throw err;
    }
  }

  // `teriac cancel`: drops the PR's queued work and stops its running plans. Running
  // applies finish: stopping one halfway would leave the infrastructure half changed.
  private async cancel(adapter: VcsAdapter, repo: Repo, number: number, user: string, reply: Reply) {
    const pr = await adapter.getPullRequest(repo, number);
    const perm = await adapter.userPermission(repo, user);
    if (user.toLowerCase() !== pr.author.toLowerCase() && !['write', 'maintain', 'admin'].includes(perm)) {
      return reply.say('🚫 Only the PR\'s author or people who can write to this repo can cancel its runs.');
    }
    const group = `${this.repoKey(repo)}#${number}`;
    const dropped = this.sched.cancel(group);
    const running = [...(this.runningPlans.get(group) ?? [])];
    for (const a of running) a.abort();
    this.deps.store.audit({ repo: this.repoKey(repo), pr: number, user, action: 'cancel', project: '*', allowed: true, reason: `${dropped} queued dropped, ${running.length} running plans stopped` });
    reply.say(dropped || running.length
      ? `⏹️ Cancelled: ${dropped} queued ${dropped === 1 ? 'run' : 'runs'} dropped, ${running.length} running ${running.length === 1 ? 'plan' : 'plans'} stopped. Applies already running finish on their own.`
      : 'Nothing to cancel: this PR has no queued runs or running plans.');
  }

  // A chat message per apply, for repos with `notify_applies` (best effort, never blocks).
  private notifyApply(ctx: PrContext, project: Project, user: string, run: Run) {
    const names = ctx.policy.notify_applies ?? [];
    if (!names.length) return;
    const { config } = this.deps;
    const ok = run.status === 'success';
    const a = run.applied as { added?: number; changed?: number; destroyed?: number } | null;
    const counts = a ? `${a.added ?? 0} added · ${a.changed ?? 0} changed · ${a.destroyed ?? 0} destroyed` : '';
    const prUrl = repoLinks(ctx.repoKey, platformForHost(ctx.repo.host, { [ctx.repo.host]: ctx.repo.platform })).pr(ctx.pr.number);
    notifyText(names, config.channels, {
      title: `${ok ? '✅' : '❌'} ${ok ? 'Applied' : 'Apply failed:'} ${project.name}`,
      lines: [
        `**${ctx.repo.fullName}** [#${ctx.pr.number}](${prUrl}) · by ${user} · ${run.engine}`,
        ...(counts ? [counts] : []),
      ],
      event: 'teriac.apply', url: this.commentLinks(ctx).run!(run.id),
      data: { repo: ctx.repoKey, pr: ctx.pr.number, project: project.name, workspace: project.workspace, user, ok, applied: a, run: run.id },
    }, { people: config.people, env: this.deps.env ?? process.env }).catch(err => log.warn('apply notice failed', { err: (err as Error).message }));
  }

  // Applies paused from the dashboard ("stop all applies"): like a freeze, everywhere at once.
  appliesPaused(): AppliesPause | null { return this.deps.store.getSetting<AppliesPause>(PAUSE_KEY); }
  pauseApplies(p: AppliesPause) { this.deps.store.setSetting(PAUSE_KEY, p); }
  resumeApplies() { this.deps.store.deleteSetting(PAUSE_KEY); }

  // Live output of one run, cleaned with the repo's secret scan settings.
  private liveFor(ctx: PrContext, project: Project, runId: number): LiveWriter {
    const s = this.safety(ctx);
    return this.live.start(runId, `${ctx.repoKey}#${ctx.pr.number}|${project.name}`, { mode: s.secretMode, patterns: s.secretPatterns });
  }

  // Saved plans (the plan file and its JSON) and live output are dropped when a lock is
  // released or the PR closes: they were made under that lock.
  // Only files go: runs, their output and the PR's comments stay, as history.
  private forgetPlans(repoKey: string, pr: number, project?: string, opts: { keepLive?: boolean } = {}) {
    for (const path of this.deps.store.discardPlans(repoKey, pr, project)) {
      rmSync(path, { force: true });
      rmSync(`${path}.json`, { force: true });
    }
    if (!opts.keepLive) this.live.dropPr(`${repoKey}#${pr}`, project);
  }

  private scan(ctx: PrContext, text: string): { text: string; found: string[]; fail: boolean } {
    const s = this.safety(ctx);
    if (s.secretMode === 'off') return { text, found: [], fail: false };
    const r = scanSecrets(text, s.secretPatterns);
    return { ...r, fail: s.secretMode === 'fail' && r.found.length > 0 };
  }

  private auditSecrets(ctx: PrContext, user: string, project: Project, found: string[], what: string) {
    if (!found.length) return;
    this.deps.store.audit({ repo: ctx.repoKey, pr: ctx.pr.number, user, action: 'secret_found', project: project.name, allowed: false, reason: `possible secrets hidden from ${what} output: ${found.join(', ')}` });
  }

  // ---- events ----

  private async autoplan(adapter: VcsAdapter, policy: RepoPolicy, repo: Repo, number: number) {
    if (policy.autoplan === false) return;
    // A fork's PR is not checked out or planned (unless the repo allows forks); one
    // comment, kept up to date, says why.
    const fork = await this.forkRefusal(adapter, policy, repo, number);
    if (fork) {
      await this.recording(adapter).upsertComment(repo, number, '<!-- teriac:fork -->', `<!-- teriac:fork -->\n${fork}`).catch(err => log.warn('fork notice failed', { err }));
      return;
    }
    const ctx = await this.context(adapter, policy, repo, number);
    if (ctx.pr.draft && !policy.plan_drafts) return;
    const targets = affectedProjects(ctx.projects, await adapter.changedFiles(repo, number));
    const hadRuns = this.deps.store.latestRuns(ctx.repoKey, number, 'plan').length > 0;
    if (!targets.length && !hadRuns) return;

    // Autoplan runs the PR's code, so the author needs plan rights
    // (stops strangers' fork PRs from running anything).
    const notes = new Map<string, string>();
    const allowedTargets: Project[] = [];
    for (const p of targets) {
      const d = await this.allowed(ctx, 'plan', ctx.pr.author, p);
      if (d.allowed) allowedTargets.push(p);
      else notes.set(p.name, `not planned automatically: ${d.reason}. Someone allowed can comment \`teriac plan\`.`);
    }
    if (this.commentMode(ctx) === 'update') return this.plans(ctx, allowedTargets, ctx.pr.author, {}, notes);
    if (!targets.length) return;
    const reply = new Reply(adapter, repo, number, this.spinner(policy));
    await reply.start(`Planning ${targets.length} project${targets.length === 1 ? '' : 's'} for \`${ctx.pr.headSha.slice(0, 7)}\`…`);
    await this.respond(reply, () => this.plans(ctx, allowedTargets, ctx.pr.author, {}, notes, reply));
  }

  private async closed(repo: Repo, number: number, merged = false) {
    this.deps.store.markPrClosed(this.repoKey(repo), number, merged);
    const released = this.deps.store.releasePrLocks(this.repoKey(repo), number);
    this.deps.store.forgetPrComments(this.repoKey(repo), number);
    this.deps.store.deleteSetting(`ai_suggested:${this.repoKey(repo)}#${number}`);
    this.deps.store.deleteSetting(`ai_code_posted:${this.repoKey(repo)}#${number}`);
    this.forgetPlans(this.repoKey(repo), number);
    rmSync(this.workDir(repo, number), { recursive: true, force: true });
    rmSync(this.planDir(repo, number), { recursive: true, force: true });
    log.info('PR closed; cleaned up', { repo: repo.fullName, pr: number, released });
  }

  private ack(policy: RepoPolicy) { return policy.ack_reaction ?? this.deps.config.ackReaction; }

  // The spinner for the "Running…" reply, or null when that reply is off or GitHub
  // couldn't load the image (no public https address).
  private spinner(policy: RepoPolicy) {
    return (policy.progress_reply ?? this.deps.config.progressReply) ? this.deps.config.spinnerUrl : null;
  }

  // Runs a command and always ends with its reply, even when it fails.
  private async respond(reply: Reply, work: () => Promise<unknown>) {
    try {
      await work();
    } catch (err) {
      log.error('command failed', { err });
      reply.say(`⚠️ teriac hit an error: ${(err as Error).message}`);
    }
    await reply.send();
  }

  private async onComment(adapter: VcsAdapter, policy: RepoPolicy, repo: Repo, number: number, author: string, body: string, commentId: string) {
    const parsed = parseCommand(body, this.deps.config.commandNames);
    if (!parsed) return;
    // Acknowledge at once: a reaction on the command (👀 by default) and a
    // spinning "Running…" reply under it that turns into the result.
    const ack = this.ack(policy);
    if (ack !== 'none') await adapter.react(repo, number, commentId, ack);
    const reply = new Reply(adapter, repo, number, this.spinner(policy));
    const line = body.split(/\r?\n/).map(l => l.trim()).find(Boolean) ?? '';
    if (parsed.ok && parsed.command.verb !== 'help') await reply.start(`Running \`${line.slice(0, 120)}\` for ${author}…`);
    if (!parsed.ok) {
      reply.say(`❌ ${parsed.error}`);
      await reply.send();
      return;
    }
    await this.respond(reply, () => this.runCommand(adapter, policy, repo, number, author, parsed.command, reply));
  }

  private select(ctx: PrContext, cmd: Command, fallback: Project[]): Project[] | string {
    if (!cmd.project && !cmd.dir && !cmd.workspace) return fallback;
    // -p and -d take a name or a glob: `-p 'live/prod/*'`, `-d 'stacks/**'`.
    const pick = (want: string | undefined, have: string) => {
      if (!want) return true;
      const w = want.replace(/^['"]|['"]$/g, '');
      return /[*?[]/.test(w) ? matchGlob(w, have) : w === have;
    };
    const hits = ctx.projects.filter(p =>
      pick(cmd.project, p.name)
      && pick(cmd.dir, p.dir)
      && (!cmd.workspace || p.workspace === cmd.workspace));
    if (!hits.length) {
      const what = [cmd.project && `project \`${cmd.project}\``, cmd.dir && `dir \`${cmd.dir}\``, cmd.workspace && `workspace \`${cmd.workspace}\``].filter(Boolean).join(', ');
      return `No project matches ${what}. Known projects: ${ctx.projects.map(p => `\`${p.name}\``).join(', ') || 'none'}`;
    }
    return hits;
  }

  private async runCommand(adapter: VcsAdapter, policy: RepoPolicy, repo: Repo, number: number, user: string, cmd: Command, reply: Reply) {
    const name = this.deps.config.commandNames[0];
    if (cmd.verb === 'help') {
      const oneAtATime = this.deps.config.requireApplyProject || policy.require_apply_project === true;
      return reply.say(helpText(name, oneAtATime, !!this.deps.ai?.has('ask'), !!this.deps.ai?.has('import')));
    }
    // Checked before anything is checked out: a fork's code must not run here.
    const fork = await this.forkRefusal(adapter, policy, repo, number);
    if (fork) {
      this.deps.store.audit({ repo: this.repoKey(repo), pr: number, user, action: cmd.verb, project: cmd.project ?? '*', allowed: false, reason: 'pull request from a fork' });
      return reply.say(fork);
    }
    if (cmd.targets.length && policy.allow_targets === false) {
      return reply.say('❌ Targeted plans are turned off for this repo (`allow_targets` in repos.yaml).');
    }
    if (cmd.extraArgs.length && !policy.allow_extra_args) {
      return reply.say('❌ Extra arguments are turned off for this repo (`allow_extra_args` in repos.yaml).');
    }

    const ctx = await this.context(adapter, policy, repo, number);
    if (!ctx.pr.open) return reply.say('❌ This PR is closed.');

    if (cmd.verb === 'unlock') return this.unlock(ctx, user, cmd, reply);
    if (cmd.verb === 'ask') return this.ask(ctx, user, cmd.question ?? '', reply);
    if (cmd.verb === 'review') return this.reviewCommand(ctx, user, cmd, reply);
    if (cmd.verb === 'adopt') return this.adoptCommand(ctx, user, cmd, reply);
    if (cmd.tool) return this.toolCommand(ctx, user, cmd, reply);

    if (cmd.verb === 'plan') {
      const changed = affectedProjects(ctx.projects, await adapter.changedFiles(repo, number));
      const targets = this.select(ctx, cmd, changed);
      if (typeof targets === 'string') return reply.say(`❌ ${targets}`);
      if (!targets.length) return reply.say('No projects changed in this PR. Use `-p <project>` to plan one anyway.');
      const notes = new Map<string, string>();
      const allowed: Project[] = [];
      for (const p of targets) {
        const d = await this.allowed(ctx, 'plan', user, p);
        if (d.allowed) allowed.push(p); else notes.set(p.name, `🚫 ${d.reason}`);
      }
      await this.plans(ctx, allowed, user, { destroy: cmd.destroy, targets: cmd.targets, extraArgs: cmd.extraArgs, refreshOnly: cmd.refreshOnly, replace: cmd.replace }, notes, reply);
      if (this.commentMode(ctx) === 'update' || !allowed.length) reply.say(this.planOutcome(ctx, targets, notes));
      return;
    }

    return this.applyCommand(ctx, user, cmd, reply);
  }

  // ---- Terraform commands (state list, import, state rm, ...) ----

  private async toolCommand(ctx: PrContext, user: string, cmd: Command, reply: Reply) {
    const name = this.deps.config.commandNames[0];
    const tool = cmd.tool!;
    const text = `${name} ${tool}${cmd.project ? ` -p ${cmd.project}` : cmd.dir ? ` -d ${cmd.dir}` : ''}${cmd.workspace ? ` -w ${cmd.workspace}` : ''}${cmd.args?.length ? ` ${cmd.args.join(' ')}` : ''}`;
    const picked = this.select(ctx, cmd, []);
    if (typeof picked === 'string') return reply.say(`❌ ${picked}`);
    if (picked.length !== 1) return reply.say(`❌ \`${name} ${tool}\` runs on one project; ${picked.length} match. Add \`-w <workspace>\` to pick one.`);
    const project = picked[0];
    const action = TOOL_ACTION[tool];
    const changes = EDITS_STATE.includes(tool);

    if (changes && ctx.policy.allow_state_changes === false) {
      return reply.say(`❌ Editing the state from PR comments is turned off for this repo (\`allow_state_changes\` in repos.yaml).`);
    }
    const d = await this.allowed(ctx, action, user, project);
    if (!d.allowed) return reply.say(`🚫 \`${text}\`: ${d.reason}`);
    if (changes) {
      // Changing the state outside a reviewed plan needs what an apply needs:
      // the project's approvals and PR requirements.
      if (!ctx.pr.open) return reply.say('❌ This PR is closed.');
      const blockers = await applyBlockers(project, this.rules(ctx, project), ctx.pr, await this.approvers(ctx), ctx.lookup);
      const grant = this.grantFor(ctx, user, project);
      if (!grant?.bypass.includes('freeze')) {
        const paused = this.appliesPaused();
        if (paused) blockers.push(pausedText(paused));
        for (const f of activeFreezes(this.safety(ctx).freezes, project)) blockers.push(`change freeze \`${f.name}\` is on until ${f.until}`);
      }
      if (blockers.length) {
        this.deps.store.audit({ repo: ctx.repoKey, pr: ctx.pr.number, user, action, project: project.name, allowed: false, reason: `blocked: ${blockers.join('; ')}` });
        return reply.say(`🔒 \`${text}\` needs ${blockers.join('; ')}`);
      }
    }
    // Changing the state takes the project's lock, like an apply.
    if (changes) {
      const lock = this.deps.store.acquireLock(ctx.repoKey, project.name, project.workspace, ctx.pr.number, user);
      if (!lock.ok) return reply.say(`🔒 \`${project.name}\` is locked by #${lock.heldBy.pr} (${lock.heldBy.user}); apply or unlock it there first.`);
    }

    let raw: Awaited<ReturnType<typeof runTool>> | undefined;
    const ran = await this.inTurn(ctx, async () => {
      const tools = await this.tools(ctx, project);
      raw = await runTool({
        root: ctx.root, project, tools, planPath: this.planPath(ctx, project), env: this.env(ctx, project, user), timeoutMs: this.deps.config.runTimeoutMs,
      }, toolArgs(cmd));
    });
    if (!ran || !raw) return reply.say(`⏹️ \`${text}\` was cancelled before it started.`);
    // `state show` and `output` print values: hide anything that looks like a secret.
    const scanned = this.scan(ctx, raw.output);
    this.auditSecrets(ctx, user, project, scanned.found, tool);
    const r = { ...raw, output: scanned.fail ? `Output withheld: it contains something that looks like a secret (${scanned.found.join(', ')}).` : scanned.text };
    if (scanned.found.length && !scanned.fail) reply.say(secretNote(scanned.found));
    this.deps.store.audit({
      repo: ctx.repoKey, pr: ctx.pr.number, user, action: tool, project: project.name, allowed: true,
      reason: `${r.ok ? 'ran' : 'failed'}: ${text}`,
    });

    // fmt reports unformatted files with exit code 3: that's a finding, not a failure.
    const fmtFindings = tool === 'fmt' && r.code === 3;
    const icon = r.ok ? '✅' : fmtFindings ? '📝' : '❌';
    const empty = r.output.split('\n').length <= 1;
    const out = [`${icon} \`${text}\``, ''];
    if (fmtFindings) out.push('Some files need `terraform fmt`:', '');
    if (!empty) out.push(fence(tail(r.output, ctx.adapter.commentLimit - 3000)));
    else if (r.ok) out.push(tool === 'state list' || tool === 'output' ? '_Nothing in the state._' : '_No output._');
    reply.say(out.join('\n'));

    // The old plan was made against the old state: plan again (plan only).
    if (r.ok && changes) {
      reply.say(`🔁 The state was edited directly, so \`${project.name}\` is planned again. Review it before applying.`);
      await this.plans(ctx, [project], user, {}, new Map(), reply);
    }
  }

  // ---- plan ----

  // "✅ Planned 2 projects" with each project's result and a link to the summary.
  private planOutcome(ctx: PrContext, targets: Project[], notes: Map<string, string>): string {
    const runs = new Map(this.deps.store.latestRuns(ctx.repoKey, ctx.pr.number, 'plan')
      .filter(r => r.headSha === ctx.pr.headSha).map(r => [r.project, r]));
    const lines = targets.map(p => {
      const note = notes.get(p.name);
      if (note) return `- \`${p.name}\`: ${note}`;
      const r = runs.get(p.name);
      if (!r) return `- \`${p.name}\`: not planned`;
      if (r.status === 'failed') return `- ❌ \`${p.name}\`: plan failed`;
      return `- ${r.destroys ? '⚠️' : r.hasChanges ? '📝' : '✅'} \`${p.name}\`: ${sizeText(r.summary)}${r.targets.length ? ' (targeted)' : ''}`;
    });
    const failed = targets.some(p => runs.get(p.name)?.status === 'failed' || notes.has(p.name));
    const head = `${failed ? '⚠️' : '✅'} **Planned ${targets.length} project${targets.length === 1 ? '' : 's'}**${ctx.summaryUrl ? ` · [see the summary](${ctx.summaryUrl})` : ''}`;
    return [head, ...lines].join('\n');
  }

  private async plans(ctx: PrContext, targets: Project[], user: string, opts: PlanOpts, notes: Map<string, string>, reply?: Reply) {
    const { store } = this.deps;
    await Promise.all(targets.map(project => this.inTurn(ctx, async () => {
      // A newer commit was pushed while this waited: its own plans are on the way.
      if (this.outdated(ctx)) { notes.set(project.name, '⏭️ skipped: a newer commit was pushed'); return; }
      const lock = store.acquireLock(ctx.repoKey, project.name, project.workspace, ctx.pr.number, user);
      if (!lock.ok) {
        notes.set(project.name, `🔒 locked by #${lock.heldBy.pr} (${lock.heldBy.user}); apply or unlock it there first`);
        return;
      }
      await this.planProject(ctx, project, user, opts);
    }).then(ran => { if (!ran) notes.set(project.name, '⏹️ cancelled'); })));
    // Nothing to report for a commit that's already been replaced.
    if (this.outdated(ctx)) return;
    await this.refreshComment(ctx, notes, new Set([...targets.map(t => t.name), ...notes.keys()]), reply);
  }

  private async tools(ctx: PrContext, project: Project): Promise<ToolSet> {
    return this.deps.resolver.resolve(ctx.root, project);
  }

  // Read-only credentials for Terraform's git module downloads, unless TERIAC_MODULE_AUTH=false.
  private async moduleAuth(adapter: VcsAdapter, repo: Repo): Promise<CloneAuth | null> {
    if (this.deps.config.moduleAuth === false || !adapter.moduleAuth) return null;
    return adapter.moduleAuth(repo).catch(err => {
      log.warn('no git credentials for module downloads; private modules may fail', { repo: repo.fullName, err: (err as Error).message });
      return null;
    });
  }

  private env(ctx: PrContext, project: Project, user: string) {
    const base = this.deps.env ?? process.env;
    return toolEnv(base, {
      ...gitAuthEnv(base, ctx.moduleAuth),
      TF_PLUGIN_CACHE_DIR: join(this.deps.config.dataDir, 'plugin-cache'),
      TERIAC_PR_NUMBER: String(ctx.pr.number),
      TERIAC_HEAD_SHA: ctx.pr.headSha,
      TERIAC_PROJECT: project.name,
      TERIAC_WORKSPACE: project.workspace,
      TERIAC_USER: user,
      TERIAC_REPO: ctx.repo.fullName,
    });
  }

  private planPath(ctx: PrContext, project: Project) {
    return join(this.planDir(ctx.repo, ctx.pr.number), `${slug(project.name)}-${slug(project.workspace)}.tfplan`);
  }

  private async planProject(ctx: PrContext, project: Project, user: string, opts: PlanOpts) {
    const { store, config } = this.deps;
    const checkName = `teriac: ${project.name}`;
    const started = Date.now();
    const runId = store.startRun({ repo: ctx.repoKey, pr: ctx.pr.number, project: project.name, workspace: project.workspace, kind: 'plan', headSha: ctx.pr.headSha, user, targets: opts.targets, prAuthor: ctx.pr.author, dir: project.dir, queuedMs: this.waited.getStore()?.ms });
    // Live output exists from the moment the run does, so a viewer never finds it missing.
    const live = this.liveFor(ctx, project, runId);
    // `teriac cancel` stops a running plan (never a running apply).
    const abort = new AbortController();
    const group = `${ctx.repoKey}#${ctx.pr.number}`;
    if (!this.runningPlans.has(group)) this.runningPlans.set(group, new Set());
    this.runningPlans.get(group)!.add(abort);
    // The check's "Details" link opens the live output while it runs.
    const liveUrl = this.commentLinks(ctx).run!(runId);
    await this.check(ctx, { name: checkName, headSha: ctx.pr.headSha, externalId: project.name, status: 'in_progress', title: 'Planning…', summary: `Planning \`${project.name}\`\n\n▶ [Watch the live output](${liveUrl})`, detailsUrl: liveUrl });

    let engine = '';
    try {
      const tools = await this.tools(ctx, project);
      engine = engineLabel(tools);
      const planPath = this.planPath(ctx, project);
      const escape = varFileEscape(ctx.root, project, opts.extraArgs ?? []);
      if (escape) throw new Error(escape);
      const r = await runPlan({
        root: ctx.root, project, tools, planPath, env: this.env(ctx, project, user), timeoutMs: config.runTimeoutMs,
        onOutput: live.write, onSensitive: live.sensitive, signal: abort.signal,
        hooks: { pre: ctx.policy.hooks?.pre_plan, post: ctx.policy.hooks?.post_plan },
      }, opts);
      const destroys = r.summary ? r.summary.destroy + r.summary.replace : 0;
      let policy: PolicyResult | null = null;
      const pol = this.policyFor(ctx, project);
      if (r.ok && r.plan && pol.mode !== 'off') {
        const cwd = project.dir === '.' ? ctx.root : join(ctx.root, project.dir);
        policy = {
          mode: pol.mode,
          findings: [
            ...evaluateRules(r.plan, pol.rules ?? [], project),
            ...(pol.builtin?.includes('security') ? securityFindings(r.plan, pol.disable ?? []) : []),
            ...(r.planJsonPath ? await runCommands(pol.commands ?? [], r.planJsonPath, cwd, this.env(ctx, project, user), project) : []),
          ],
        };
      }
      // Terragrunt: did this plan use a dependency's mock outputs?
      let mocks: string[] = [];
      const tgFile = join(ctx.root, project.dir, 'terragrunt.hcl');
      if (project.engine === 'terragrunt' && existsSync(tgFile)) {
        const deps = terragruntDependencies(ctx.root, project.dir, readFileSync(tgFile, 'utf-8'));
        // Planned: which dependencies were mocked. Failed: which ones it needed but couldn't read.
        mocks = (r.ok ? mockedDependencies(project.dir, deps, r.output, r.plan) : unappliedDependencies(project.dir, deps, r.output))
          .map(dir => ctx.projects.find(p => p.dir === dir)?.name ?? dir);
      }
      const lock = join(ctx.root, project.dir, '.terraform.lock.hcl');
      const providers = providersOf(existsSync(lock) ? readFileSync(lock, 'utf-8') : null, r.plan);
      // Possible secrets never leave the server. In "fail" mode the plan can't be applied.
      const scanned = this.scan(ctx, r.output);
      this.auditSecrets(ctx, user, project, scanned.found, 'plan');
      const ok = r.ok && !scanned.fail;
      const output = scanned.fail
        ? `teriac withheld this plan's output: it contains something that looks like a secret (${scanned.found.join(', ')}). `
          + 'Find where it comes from (a variable, a tag, an output), remove it, and plan again.'
        : scanned.text;
      const ruled = ok ? assessRisk(r.summary, project, policy?.findings ?? [], this.safety(ctx).risk) : null;
      // AI help: a review of a plan with changes, or the cause of a failure (not a withheld one).
      let ai: AiResult | null = null;
      if (ok && r.plan && r.hasChanges) {
        ai = await this.aiReview(ctx, project, engine, r.plan, ruled, policy?.findings ?? []);
      } else if (!r.ok && !scanned.fail && !mocks.length) {
        ai = await this.aiFailure(ctx, project, 'plan', scanned.text);
      }
      const risk = ai?.kind === 'review' ? raiseRisk(ruled, ai) : ruled;
      store.finishRun(runId, {
        status: ok ? 'success' : 'failed', engine, summary: r.summary ? JSON.stringify(r.summary) : null,
        output, planPath: ok ? planPath : null, hasChanges: r.hasChanges, destroys,
        policy: policy ? JSON.stringify(policy) : null, mocks, providers, usage: r.usage ?? null,
        // The plan file's fingerprint: apply refuses a file that changed since it was reviewed.
        planSha: ok && existsSync(planPath) ? sha256File(planPath) : null,
        risk, secrets: scanned.found, ai,
      });
      if (policy?.findings.length) store.saveFindings(store.getRun(runId)!, policy.mode, policy.findings);
      if (ai?.kind === 'fix' && await this.suggestFixes(ctx, project, ai)) store.setRunAi(runId, { ...ai, posted: true });
      await this.aiCodeReview(ctx, project, runId, false);
    } catch (err) {
      store.finishRun(runId, { status: 'failed', engine, output: `teriac could not run this project: ${(err as Error).message}` });
    } finally {
      live.end();
      this.runningPlans.get(group)?.delete(abort);
    }
    metrics.observeRun('plan', store.getRun(runId)!.status, Date.now() - started);
    await this.publishCheck(ctx, project, store.getRun(runId)!);
  }

  // ---- AI help (TERIAC_AI_PROVIDER) ----

  // AI settings for one project, or null when a feature is off for it: repos.yaml (top, repo
  // entry, first matching project rule with `ai`), then teriac.yaml, which can only narrow.
  aiSettings(policy: RepoPolicy, repoConfig: RepoConfig | null, project: { name: string; dir: string }): AiSettings | null {
    const p = project as Project;
    const server = [this.deps.config.aiPolicy, policy.ai, policy.projects?.find(r => r.ai && ruleMatches(r, p))?.ai];
    const repo = policy.allow_repo_config === false || !repoConfig ? [] : [repoConfig.ai, ...repoConfig.rules.filter(r => ruleMatches(r, p)).map(r => r.ai)];
    return resolveAi(this.deps.ai?.cfg, server, repo);
  }

  // The settings from repos.yaml's top-level `ai` alone: policy drafts, and the dashboard's default.
  aiServerSettings(): AiSettings | null { return resolveAi(this.deps.ai?.cfg, [this.deps.config.aiPolicy]); }

  private aiFor(ctx: PrContext, project: Project, feature: AiFeature): AiSettings | null {
    const s = this.deps.ai ? this.aiSettings(ctx.policy, ctx.rulesConfig, project) : null;
    return s?.features.includes(feature) ? s : null;
  }

  private async aiReview(ctx: PrContext, project: Project, engine: string, plan: Record<string, any>, risk: Risk | null, findings: { rule: string; severity: string; address: string; message: string }[]): Promise<AiResult | null> {
    const s = this.aiFor(ctx, project, 'review');
    if (!s) return null;
    // review: command reviews only on `teriac review`; first, only a PR's first plan of the project.
    if (!this.reviewDue(ctx, project, s, 'plan', false)) return null;
    const safety = this.safety(ctx);
    // AI help never fails a plan: any error just means no review.
    return this.deps.ai!.reviewPlan({ project: project.name, production: isProduction(project, safety.risk), engine, plan, risk, findings, patterns: safety.secretPatterns }, s)
      .catch(err => { log.warn('ai review skipped', { project: project.name, err: (err as Error).message }); return null; });
  }

  private async aiFailure(ctx: PrContext, project: Project, kind: 'plan' | 'apply', output: string): Promise<AiResult | null> {
    const s = this.aiFor(ctx, project, 'fix');
    if (!s) return null;
    return this.deps.ai!.explainFailure({ project: project.name, kind, output, root: ctx.root, dir: project.dir, patterns: this.safety(ctx).secretPatterns }, s)
      .catch(err => { log.warn('ai failure help skipped', { project: project.name, err: (err as Error).message }); return null; });
  }

  // `teriac review` (asked) always reviews; otherwise the project's timing decides.
  private reviewDue(ctx: PrContext, project: Project, s: AiSettings, what: 'plan' | 'code', asked: boolean): boolean {
    if (asked) return true;
    if (s.review === 'command') return false;
    return !(s.review === 'first' && this.deps.store.hadAiReview(ctx.repoKey, ctx.pr.number, project.name, what));
  }

  // The AI code review: inline comments on the project's changed Terraform files, posted once as
  // one comment-only review (medium or worse only). Never fails the run.
  private async aiCodeReview(ctx: PrContext, project: Project, runId: number, asked: boolean): Promise<number | null> {
    const s = this.aiFor(ctx, project, 'code');
    if (!s || !ctx.adapter.fileDiffs || !this.reviewDue(ctx, project, s, 'code', asked)) return null;
    try {
      const inProject = (p: string) => project.dir === '.' || p.startsWith(`${project.dir}/`);
      const diffs = (await ctx.adapter.fileDiffs(ctx.repo, ctx.pr.number)).filter(d => inProject(d.path) && /\.(tf|hcl|tfvars)$/.test(d.path));
      if (!diffs.length) return null;
      const safety = this.safety(ctx);
      const review = this.deps.store.getRun(runId)?.ai;
      const known = review?.kind === 'review' ? review.findings.map(f => ({ address: f.address, title: f.title })) : [];
      const comments = await this.deps.ai!.reviewCode({ project: project.name, production: isProduction(project, safety.risk), diffs, root: ctx.root, dir: project.dir, known, patterns: safety.secretPatterns }, s);
      if (!comments) return null;
      // Each comment once per PR: what was posted before (same file, line and title) is skipped.
      const key = `ai_code_posted:${ctx.repoKey}#${ctx.pr.number}`;
      const seen = this.deps.store.getSetting<string[]>(key) ?? [];
      const id = (c: CodeComment) => `${c.path}:${c.startLine}:${c.title.toLowerCase()}`;
      const fresh = comments.filter(c => important(c) && !seen.includes(id(c)));
      let posted = !fresh.length;
      if (fresh.length && ctx.adapter.suggestChanges) {
        const SEVS: Record<string, string> = { critical: '🔴', high: '🔴', medium: '🟠', low: '🟡' };
        posted = await ctx.adapter.suggestChanges(ctx.repo, ctx.pr.number, ctx.pr.headSha,
          `🤖 **AI code review** of \`${project.name}\` · ${fresh.length} comment${fresh.length === 1 ? '' : 's'} <sub>${label(s)} · advisory, check it yourself</sub>`,
          fresh.map(c => ({ path: c.path, startLine: c.startLine, endLine: c.endLine, note: `${SEVS[c.severity] ?? '🟡'} **${c.title}**: ${c.body}`, ...(c.suggestion ? { replacement: c.suggestion } : {}) })),
        ).catch(err => { log.warn('could not post the AI code review', { err: (err as Error).message }); return false; });
        if (posted) this.deps.store.setSetting(key, [...seen, ...fresh.map(id)].slice(-200));
      }
      this.deps.store.setRunAiCode(runId, { comments, model: label(s), posted });
      this.deps.store.audit({ repo: ctx.repoKey, pr: ctx.pr.number, user: 'teriac', action: 'ai_code_review', project: project.name, allowed: true, reason: `${comments.length} comments (${fresh.length} new, important) by ${label(s)}${posted ? '' : '; not posted inline, shown in the comment'}` });
      return comments.length;
    } catch (err) {
      log.warn('ai code review skipped', { project: project.name, err: (err as Error).message });
      return null;
    }
  }

  // Fixes as suggested changes on the PR's code, where the platform allows it. The PR comment
  // shows them too, so nothing is lost when a line is outside the PR's diff.
  // True when they are on the code (now, or already: the same fix is never posted twice on a PR).
  private async suggestFixes(ctx: PrContext, project: Project, help: Extract<AiResult, { kind: 'fix' }>): Promise<boolean> {
    if (!help.fixes.length || !ctx.adapter.suggestChanges) return false;
    const key = `ai_suggested:${ctx.repoKey}#${ctx.pr.number}`;
    const seen = this.deps.store.getSetting<string[]>(key) ?? [];
    const hash = createHash('sha256').update(JSON.stringify(help.fixes.map(f => [f.path, f.startLine, f.endLine, f.replacement]))).digest('hex').slice(0, 16);
    if (seen.includes(hash)) return true;
    const ok = await ctx.adapter.suggestChanges(ctx.repo, ctx.pr.number, ctx.pr.headSha,
      `🤖 **AI suggestion** for \`${project.name}\` (${help.model}): ${help.cause.split('\n')[0].slice(0, 300)}\n\n<sub>Check it before committing: AI can be wrong.</sub>`,
      help.fixes.map(f => ({ path: f.path, startLine: f.startLine, endLine: f.endLine, replacement: f.replacement, note: f.why })),
    ).catch(err => { log.warn('could not post AI suggestions', { err: (err as Error).message }); return false; });
    if (ok) this.deps.store.setSetting(key, [...seen, hash].slice(-50));
    this.deps.store.audit({ repo: ctx.repoKey, pr: ctx.pr.number, user: 'teriac', action: 'ai_suggestion', project: project.name, allowed: true, reason: `${help.fixes.length} suggested fix${help.fixes.length === 1 ? '' : 'es'} by ${help.model}${ok ? '' : ' (shown in the comment: outside the PR\'s diff)'}` });
    return ok;
  }

  // `teriac ask`: an AI answer from this PR's latest plans, with read-only access to the
  // checkout and the saved plans. Needs plan rights on a project of the PR.
  private async ask(ctx: PrContext, user: string, question: string, reply: Reply) {
    const ai = this.deps.ai;
    if (!ai?.has('ask')) return reply.say('AI answers are turned off on this server (`TERIAC_AI_FEATURES`).');
    // On when some project of the PR has `ask` on; that project's model and effort answer.
    const changed = affectedProjects(ctx.projects, await ctx.adapter.changedFiles(ctx.repo, ctx.pr.number).catch(() => []));
    const scope = changed.length ? changed : ctx.projects;
    const on = scope.map(p => ({ p, s: this.aiFor(ctx, p, 'ask') })).filter((x): x is { p: Project; s: AiSettings } => !!x.s);
    if (!on.length) return reply.say('AI answers are turned off for the projects in this PR (`ai` in repos.yaml or teriac.yaml).');
    let may = false;
    for (const { p } of on) if ((await this.allowed(ctx, 'plan', user, p)).allowed) { may = true; break; }
    if (!may) return reply.say('🚫 Asking needs permission to plan a project in this repo.');
    const settings = on[0].s;
    // Only projects with `ask` on are seen: their plans, and the files in their folders.
    const visible = new Set(on.map(x => x.p.name));
    const runs = this.deps.store.latestRuns(ctx.repoKey, ctx.pr.number, 'plan').filter(r => r.headSha === ctx.pr.headSha && visible.has(r.project));
    const summary = [`Pull request #${ctx.pr.number}: ${ctx.pr.title} (by ${ctx.pr.author}, ${ctx.pr.headRef} → ${ctx.pr.baseRef})`,
      `Projects you can see (AI is off for any others): ${on.map(x => `${x.p.name} (${x.p.dir})`).join(', ')}`,
      ...runs.map(r => runDigest(r))].join('\n\n');
    const answer = await ai.ask(question, { summary, tools: [...runTools(runs), ...checkoutTools(ctx.root, on.map(x => x.p.dir))] }, this.safety(ctx).secretPatterns, settings);
    this.deps.store.audit({ repo: ctx.repoKey, pr: ctx.pr.number, user, action: 'ai_ask', project: '*', allowed: true, reason: question.slice(0, 300) });
    reply.say(answer ? `🤖 **AI answer** <sub>${label(settings)} · advisory, check it yourself</sub>\n\n${answer}` : '🤖 No AI answer this time (the request failed or was declined). Try rephrasing, or ask again later.');
  }

  // ---- adopt: a PR that brings resources made by hand under Terraform ----

  // `teriac adopt -p <project> <type> <id>...`: the PR is opened against this PR's base branch.
  private async adoptCommand(ctx: PrContext, user: string, cmd: Command, reply: Reply) {
    // One reply, with the result: the 👀 reaction already says it was picked up.
    const r = await this.adoptResources({
      adapter: ctx.adapter, repo: ctx.repo, policy: ctx.policy, base: ctx.pr.baseRef,
      select: { project: cmd.project, dir: cmd.dir, workspace: cmd.workspace }, targets: cmd.adopt!, user, from: `#${ctx.pr.number}`,
    });
    reply.say(r.message);
  }

  // Dashboard requests: started in the background, polled for the result (newest first, last 30).
  private adoptJobs: { id: number; repo: string; project: string; base: string; resources: string[]; by: string; at: string; status: 'running' | 'opened' | 'failed'; message?: string; url?: string; model?: string }[] = [];
  private adoptSeq = 0;
  get adoptions() { return this.adoptJobs; }
  startAdopt(a: { adapter: VcsAdapter; repo: Repo; policy: RepoPolicy; base: string; project: string; workspace?: string; targets: AdoptTarget[]; by: string }) {
    const job: (typeof this.adoptJobs)[number] = {
      id: ++this.adoptSeq, repo: this.repoKey(a.repo), project: a.project, base: a.base, by: a.by, at: new Date().toISOString(), status: 'running',
      resources: a.targets.map(t => `${t.type}${t.name ? `.${t.name}` : ''} ${t.id}`),
    };
    this.adoptJobs = [job, ...this.adoptJobs].slice(0, 30);
    void this.adoptResources({ ...a, select: { project: a.project, workspace: a.workspace }, user: null, by: a.by, from: 'the teriac dashboard' })
      .then(r => Object.assign(job, { status: r.ok ? 'opened' : 'failed', message: r.message.replace(/<details>[\s\S]*$/, '').trim(), url: r.url, model: r.result?.model }))
      .catch(err => Object.assign(job, { status: 'failed', message: `❌ ${(err as Error).message.slice(0, 300)}` }));
    return job;
  }

  // Shared by the PR command and the dashboard. `user` null: a dashboard admin (no repo permission check).
  async adoptResources(a: {
    adapter: VcsAdapter; repo: Repo; policy: RepoPolicy; base: string;
    select: { project?: string; dir?: string; workspace?: string }; targets: AdoptTarget[]; user: string | null; from?: string; by?: string;
  }): Promise<{ ok: boolean; message: string; url?: string; result?: AdoptResult }> {
    const { config, store } = this.deps;
    const repoKey = this.repoKey(a.repo);
    const who = a.user ?? a.by ?? 'admin';
    const audit = (allowed: boolean, project: string, reason: string) => store.audit({ repo: repoKey, pr: 0, user: who, action: 'adopt', project, allowed, reason });
    if (!a.adapter.openPullRequest) return { ok: false, message: '❌ Opening PRs is not supported on this platform.' };
    return this.queue.run(`adopt:${repoKey}@${a.base}`, async () => {
      const root = join(config.dataDir, 'adopt', a.repo.host, a.repo.owner, a.repo.name, slug(a.base));
      const auth = await a.adapter.cloneAuth(a.repo);
      await (this.deps.checkoutBranch ?? gitCheckoutBranch)(root, auth, a.base);
      const repoConfig = a.policy.allow_repo_config === false ? emptyRepoConfig() : loadRepoConfig(root);
      const projects = discoverProjects(root, repoConfig).filter(p =>
        (a.select.project ? p.name === a.select.project : p.dir === a.select.dir) && (!a.select.workspace || p.workspace === a.select.workspace));
      const named = a.select.project ?? a.select.dir ?? '';
      if (projects.length !== 1) return { ok: false, message: projects.length ? `❌ \`${named}\` has ${projects.length} workspaces on \`${a.base}\`; add \`-w <workspace>\`.` : `❌ No project \`${named}\` on \`${a.base}\` (adopt writes code for a project that is already merged).` };
      const project = projects[0];
      if (a.user) {
        const lookup: Lookup = {
          permission: u => a.adapter.userPermission(a.repo, u),
          inTeam: (t, u) => a.adapter.inTeam(a.repo, t, u),
          codeowners: () => a.adapter.codeowners(a.repo, a.base),
        };
        const d = await checkPermission('adopt', a.user, project, rulesFor(project, a.policy, repoConfig), lookup);
        if (!d.allowed) { audit(false, project.name, d.reason); return { ok: false, message: `🚫 \`adopt\` on \`${project.name}\`: ${d.reason}` }; }
      }
      const moduleAuth = await this.moduleAuth(a.adapter, a.repo);
      const base = this.deps.env ?? process.env;
      const env = toolEnv(base, {
        ...gitAuthEnv(base, moduleAuth),
        TF_PLUGIN_CACHE_DIR: join(config.dataDir, 'plugin-cache'),
        TERIAC_PROJECT: project.name, TERIAC_WORKSPACE: project.workspace, TERIAC_REPO: a.repo.fullName, TERIAC_BRANCH: a.base, TERIAC_USER: who,
      });
      const s = this.deps.ai ? this.aiSettings(a.policy, repoConfig, project) : null;
      const settings = s?.features.includes('import') ? s : null;
      const patterns = [...(config.secretScan?.patterns ?? []), ...(a.policy.secret_patterns ?? [])];
      const result = await this.limited(async () => adopt({
        root, ctx: { root, project, tools: await this.deps.resolver.resolve(root, project), env, timeoutMs: config.runTimeoutMs },
        planDir: join(config.dataDir, 'adopt-plans', a.repo.host, a.repo.owner, a.repo.name), targets: a.targets,
        ai: this.deps.ai, settings, patterns,
      }), `adopt:${repoKey}`);
      if (!result.ok) {
        audit(true, project.name, `failed: ${result.error}`);
        const out = result.output ? `\n\n<details><summary>Last plan output</summary>\n\n${fence(tail(scanSecrets(result.output, patterns).text, 12_000))}\n</details>` : '';
        return { ok: false, result, message: `❌ Could not adopt into \`${project.name}\`: ${result.error!.replace(/\.$/, '')}.${out}` };
      }
      const branch = adoptBranch(project.name, result.resources);
      const n = result.resources.length;
      let url: string | null;
      try {
        url = await a.adapter.openPullRequest!(a.repo, {
          base: a.base, branch, title: `Bring ${n === 1 ? result.resources[0].address : `${n} resources`} under Terraform in ${project.name}`,
          body: adoptBody(project.name, a.base, result, { user: who, from: a.from }), files: [result.file!],
        });
      } catch (err) {
        const why = (err as Error).message.slice(0, 300);
        audit(true, project.name, `planned clean, but the PR could not be opened: ${why}`);
        return { ok: false, result, message: `❌ The code for ${result.resources.map(r => `\`${r.address}\``).join(', ')} plans cleanly, but the PR could not be opened: ${why}.` };
      }
      audit(true, project.name, url ? `opened ${url} (${result.resources.map(r => r.address).join(', ')}${result.model ? `, by ${result.model}` : ''})` : `skipped: branch ${branch} exists`);
      if (!url) return { ok: false, result, message: `ℹ️ A PR for these resources is already open (branch \`${branch}\`). Merge or close it first.` };
      const changes = result.changes.length ? ` ⚠️ Applying it also changes ${result.changes.map(c => `\`${c.address}\``).join(', ')}; see the PR.` : ' Applying it imports them and changes nothing.';
      return { ok: true, url, result, message: `✅ Opened ${url}: \`${result.file!.path}\` brings ${result.resources.map(r => `\`${r.address}\``).join(', ')} under Terraform${result.model ? ` (written by AI, ${result.model})` : result.aiFailed ? ' (Terraform\'s generated code: the AI request failed)' : ''}.${changes}` };
    });
  }

  // AI settings for a run's project, from repos.yaml and the teriac.yaml on the repo's default branch.
  async aiForRun(adapter: VcsAdapter | undefined, run: Run, feature: AiFeature): Promise<AiSettings | null> {
    if (!this.deps.ai || !adapter) return null;
    const [host, owner, ...rest] = run.repo.split('/');
    const repo: Repo = { platform: adapter.platform, host, owner, name: rest.join('/'), fullName: `${owner}/${rest.join('/')}`, cloneUrl: '' };
    const policy = repoPolicyFor(this.deps.config.repos, repo);
    if (!policy) return null;
    const pr = await adapter.getPullRequest(repo, run.pr).catch(() => null);
    const base = pr?.baseRef ?? repo.defaultBranch ?? 'main';
    const repoConfig = policy.allow_repo_config === false ? null : await loadRepoConfigFrom(f => adapter.fileAt(repo, f, base)).catch(() => null);
    const s = this.aiSettings(policy, repoConfig, { name: run.project, dir: run.dir || run.project });
    return s?.features.includes(feature) ? s : null;
  }

  // `teriac review`: an AI review of the latest plans at the PR's head, without planning again
  // (it reads the saved plan). Shown in full in the reply, as it was asked for.
  private async reviewCommand(ctx: PrContext, user: string, cmd: Command, reply: Reply) {
    if (!this.deps.ai?.has('review')) return reply.say('AI reviews are turned off on this server (`TERIAC_AI_FEATURES`).');
    const { store } = this.deps;
    const plans = store.latestRuns(ctx.repoKey, ctx.pr.number, 'plan').filter(r => r.headSha === ctx.pr.headSha && r.status === 'success' && r.hasChanges);
    const planned = ctx.projects.filter(p => plans.some(r => r.project === p.name));
    const picked = this.select(ctx, cmd, planned);
    if (typeof picked === 'string') return reply.say(`❌ ${picked}`);
    if (!picked.length) return reply.say(`Nothing to review: no plan with changes for this commit. Run \`${this.commandName} plan\` first.`);
    const out: string[] = [];
    for (const project of picked) {
      const run = plans.find(r => r.project === project.name);
      if (!run) { out.push(`- \`${project.name}\`: no plan with changes for this commit`); continue; }
      const s = this.aiFor(ctx, project, 'review');
      const code = this.aiFor(ctx, project, 'code');
      if (!s && !code) { out.push(`- \`${project.name}\`: AI reviews are off for this project`); continue; }
      if (!(await this.allowed(ctx, 'plan', user, project)).allowed) { out.push(`- \`${project.name}\`: 🚫 needs permission to plan it`); continue; }
      const codeReview = async () => {
        const n = code ? await this.aiCodeReview(ctx, project, run.id, true) : null;
        return n === null ? [] : n ? [`💬 AI code review: ${n} comment${n === 1 ? '' : 's'} on **Files changed**`] : ['💬 AI code review: nothing more to flag in the code'];
      };
      if (!s) { out.push(`**\`${project.name}\`**`, '', ...await codeReview(), ''); continue; }
      let plan: Record<string, any> | null = null;
      try { plan = run.planPath ? JSON.parse(readFileSync(`${run.planPath}.json`, 'utf-8')) : null; } catch { /* dropped */ }
      if (!plan) { out.push(`- \`${project.name}\`: its saved plan is gone; plan it again (\`${this.commandName} plan -p ${project.name}\`)`); continue; }
      const pol = this.policyOf(run);
      const safety = this.safety(ctx);
      const ruled = assessRisk(summaryOf(run), project, pol?.findings ?? [], safety.risk);
      const review = await this.deps.ai.reviewPlan({ project: project.name, production: isProduction(project, safety.risk), engine: run.engine, plan, risk: ruled, findings: pol?.findings ?? [], patterns: safety.secretPatterns }, s);
      if (!review) { out.push(`- \`${project.name}\`: no AI review this time (the request failed or was declined)`); continue; }
      store.setRunReview(run.id, review, raiseRisk(ruled, review));
      const updated = store.getRun(run.id)!;
      await this.publishCheck(ctx, project, updated);
      out.push(`**\`${project.name}\`**`, '', ...aiLines(updated), ...await codeReview(), '');
    }
    this.deps.store.audit({ repo: ctx.repoKey, pr: ctx.pr.number, user, action: 'ai_review', project: picked.map(p => p.name).join(',') || '*', allowed: true, reason: 'teriac review' });
    reply.say(out.join('\n'));
    if (this.commentMode(ctx) === 'update') await this.refreshComment(ctx, new Map());
  }

  // The dashboard's "Ask about this run": the run and its saved plan, no checkout.
  async askAboutRun(run: Run, question: string, s: AiSettings): Promise<string | null> {
    return this.deps.ai?.ask(question, { summary: runDigest(run), tools: runTools([run]) }, this.deps.config.secretScan?.patterns, s) ?? null;
  }

  // ---- rules that depend on the plan ----

  // Server policies plus the repo's; the repo can only make the mode stricter.
  private policyFor(ctx: PrContext, _project: Project): PolicyConfig & { mode: NonNullable<PolicyConfig['mode']> } {
    const server = this.deps.config.policies ?? {};
    const repo = ctx.policy.policies ?? {};
    return {
      mode: stricter(server.mode, repo.mode),
      override: repo.override ?? server.override ?? [],
      rules: [...(server.rules ?? []), ...(repo.rules ?? [])],
      commands: [...(server.commands ?? []), ...(repo.commands ?? [])],
      // A repo can add rule packs; only the server can turn single rules off.
      builtin: [...new Set([...(server.builtin ?? []), ...(repo.builtin ?? [])])],
      disable: server.disable ?? [],
    };
  }

  // Two-person rule: on for the repo, or for a matching project rule (server or repo config).
  private twoPerson(ctx: PrContext, project: Project): boolean {
    if (ctx.policy.two_person_rule) return true;
    const r = this.rules(ctx, project);
    return !!(r.server?.two_person_rule || r.repo.some(x => x.two_person_rule));
  }

  private policyOf(plan: Run | undefined): PolicyResult | null {
    return plan?.policy ? JSON.parse(plan.policy) as PolicyResult : null;
  }

  // Everything that stops a project's apply right now. With `override`,
  // the overridable ones (enforced policy findings) are skipped.
  // Dependency problems that make a plan unsafe to apply (never overridable):
  // it used mock outputs, or a dependency was applied after it was made.
  private dependencyBlockers(ctx: PrContext, project: Project, plan: Run): string[] {
    const name = this.deps.config.commandNames[0];
    const list = (xs: string[]) => xs.map(x => `\`${x}\``).join(', ');
    if (plan.mocks.length) {
      return [`planned with mock outputs from ${list(plan.mocks)}: apply ${list(plan.mocks)} first (${plan.mocks.map(m => `\`${name} apply -p ${m}\``).join(', ')}); this project is then re-planned with the real outputs`];
    }
    const applies = this.deps.store.latestRuns(ctx.repoKey, ctx.pr.number, 'apply');
    const newer = ctx.projects
      .filter(q => q !== project && project.deps.includes(q.dir))
      .filter(q => applies.some(a => a.project === q.name && a.status === 'success' && a.id > plan.id))
      .map(q => q.name);
    return newer.length ? [`${list(newer)} applied after this plan: re-plan this project first (\`${name} plan -p ${project.name}\`)`] : [];
  }

  // Everything that stops this plan's apply right now. With `override` (the applier typed
  // --override), each freeze, protected resource and policy is skipped when the applier is in
  // its own override list; `skipped` collects what was. An emergency grant may skip more.
  private async blockers(ctx: PrContext, project: Project, plan: Run, approvers: string[], opts: { override?: boolean; user?: string; skipped?: string[] } = {}): Promise<string[]> {
    const s = this.safety(ctx);
    const grant = opts.user ? this.grantFor(ctx, opts.user, project) : null;
    const skip = new Set<string>(grant?.bypass ?? []);
    const mayOverride = async (who: string[]) => {
      if (!opts.override || !opts.user) return false;
      for (const p of who) if (await matchesPrincipal(p, opts.user, project, ctx.lookup)) return true;
      return false;
    };
    const by = (who: string[]) => (who.length ? ` · ${overriders(who, ctx.repo)} can apply with \`--override\`` : '');
    const rules = this.rules(ctx, project);
    const out = [...this.dependencyBlockers(ctx, project, plan)];
    if (skip.has('approvals')) {
      // An emergency grant can skip approvals, never the PR's other requirements.
      const noApprovals: EffectiveRules = {
        server: rules.server ? { ...rules.server, approvals: [] } : null,
        repo: rules.repo.map(r => ({ ...r, approvals: [] })),
        requirements: rules.requirements.filter(r => r !== 'approved'),
      };
      out.push(...await applyBlockers(project, noApprovals, ctx.pr, approvers, ctx.lookup));
    } else {
      out.push(...await applyBlockers(project, rules, ctx.pr, approvers, ctx.lookup));
      // High-risk plans can need one more approval from a named group.
      const extra = plan.risk ? extraApprovalFor(plan.risk.level as Risk['level'], s.risk) : null;
      if (extra) {
        let have = 0;
        for (const u of approvers) if (await matchesPrincipal(extra.from, u, project, ctx.lookup)) have++;
        if (have < extra.count) {
          const n = extra.count - have;
          out.push(`${n} more approval${n > 1 ? 's' : ''} from ${extra.from === 'anyone' ? 'a reviewer' : extra.from} (${plan.risk!.level} risk)`);
        }
      }
    }
    if (s.staleBase === 'block') {
      const stale = await this.stale(ctx, project);
      if (stale) out.push(stale);
    }
    if (!skip.has('freeze')) {
      const paused = this.appliesPaused();
      if (paused) out.push(pausedText(paused));
      for (const f of activeFreezes(s.freezes, project)) {
        if (await mayOverride(f.override)) { opts.skipped?.push(`change freeze ${f.name}`); continue; }
        out.push(`change freeze \`${f.name}\` is on until ${f.until}${by(f.override)}`);
      }
    }
    if (!skip.has('protected')) {
      const blocked = new Map<string, string[]>();
      for (const h of protectedHits(s.protected, project, summaryOf(plan))) {
        if (await mayOverride(h.override)) { opts.skipped?.push(`protected ${h.address}`); continue; }
        blocked.set(h.address, [...new Set([...(blocked.get(h.address) ?? []), ...h.override])]);
      }
      const list = [...blocked.keys()];
      if (list.length) {
        const who = [...new Set([...blocked.values()].flat())];
        out.push(`protected resource${list.length === 1 ? '' : 's'} would be destroyed or replaced: ${list.slice(0, 3).map(h => `\`${h}\``).join(', ')}${list.length > 3 ? ', …' : ''}${by(who)}`);
      }
    }
    const pol = this.policyOf(plan);
    if (!skip.has('policy') && pol?.mode === 'enforce' && pol.findings.length) {
      const who = this.policyFor(ctx, project).override ?? [];
      if (await mayOverride(who)) opts.skipped?.push('policy findings');
      else {
        const names = [...new Set(pol.findings.map(f => f.rule))];
        out.push(`${pol.findings.length} policy finding${pol.findings.length === 1 ? '' : 's'} (${names.slice(0, 3).join(', ')}${names.length > 3 ? ', …' : ''})${by(who)}`);
      }
    }
    return out;
  }

  // ---- apply ----

  private async approvers(ctx: PrContext) {
    const s = this.safety(ctx);
    const a = await countApprovals(await ctx.adapter.reviews(ctx.repo, ctx.pr.number), ctx.pr.author, ctx.pr.headSha,
      { reapproveOnChange: s.reapproveOnChange, keepOnRebase: s.keepOnRebase }, sha => this.fingerprint(ctx, sha));
    ctx.carried = a.carried;
    return a.approvers;
  }

  // Groups projects into waves: each wave only depends on earlier waves.
  private waves(projects: Project[]): Project[][] {
    const level = new Map<string, number>();
    const depth = (p: Project, stack: Set<string>): number => {
      if (level.has(p.name)) return level.get(p.name)!;
      if (stack.has(p.name)) return 0; // a cycle: treat as independent
      stack.add(p.name);
      const deps = projects.filter(q => q !== p && p.deps.includes(q.dir));
      const d = deps.length ? Math.max(...deps.map(q => depth(q, stack) + 1)) : 0;
      level.set(p.name, d);
      return d;
    };
    projects.forEach(p => depth(p, new Set()));
    const out: Project[][] = [];
    for (const p of projects) (out[level.get(p.name)!] ??= []).push(p);
    return out.filter(Boolean);
  }

  // Projects in dependency order: a project runs after the projects it depends on.
  private ordered(projects: Project[]): Project[] {
    const out: Project[] = [];
    const seen = new Set<string>();
    const visit = (p: Project, stack: Set<string>) => {
      if (seen.has(p.name) || stack.has(p.name)) return;
      stack.add(p.name);
      for (const q of projects) if (p.deps.includes(q.dir)) visit(q, stack);
      seen.add(p.name);
      out.push(p);
    };
    for (const p of projects) visit(p, new Set());
    return out;
  }

  private oneAtATime(ctx: PrContext): boolean {
    return this.deps.config.requireApplyProject || ctx.policy.require_apply_project === true || ctx.rulesConfig.require_apply_project;
  }

  private async applyCommand(ctx: PrContext, user: string, cmd: Command, reply: Reply) {
    const { store } = this.deps;
    const plans = new Map(store.latestRuns(ctx.repoKey, ctx.pr.number, 'plan')
      .filter(r => r.headSha === ctx.pr.headSha)
      .map(r => [`${r.project}::${r.workspace}`, r]));
    const planned = ctx.projects.filter(p => {
      const r = plans.get(`${p.name}::${p.workspace}`);
      return r && r.status === 'success' && r.hasChanges && r.planPath;
    });
    // Servers (or repos) can insist on one project per apply.
    if (this.oneAtATime(ctx) && !cmd.project && !cmd.dir) {
      const name = this.deps.config.commandNames[0];
      return reply.say([
        `This server applies one project at a time, so \`${name} apply\` on its own is turned off.`,
        planned.length
          ? ['Apply each project with:', ...planned.flatMap(p => [...cmdBlock(`${name} apply -p ${p.name}`), ''])].join('\n').trim()
          : 'No project has a plan ready to apply yet.',
      ].join('\n\n'));
    }

    const selected = this.select(ctx, cmd, planned);
    if (typeof selected === 'string') return reply.say(`❌ ${selected}`);
    if (this.oneAtATime(ctx) && selected.length > 1) {
      return reply.say(`This server applies one project at a time, and \`${cmd.project ?? cmd.dir}\` matches ${selected.length}: ${selected.map(p => `\`${p.name}\``).join(', ')}. Apply them one by one.`);
    }
    if (!selected.length) {
      return reply.say('Nothing to apply: no project has a successful plan with changes at the current commit. Run `teriac plan` first.');
    }

    const approvers = await this.approvers(ctx);
    const notes = new Map<string, string>();
    const denied: string[] = [];
    const attempted = new Set<string>();
    const approved: { project: Project; plan: Run }[] = [];
    const staleNotes: string[] = [];
    for (const project of this.ordered(selected)) {
      const plan = plans.get(`${project.name}::${project.workspace}`);
      if (!plan || plan.status !== 'success' || !plan.planPath) {
        notes.set(project.name, 'no plan at the current commit; run `teriac plan` first');
        continue;
      }
      if (!plan.hasChanges) continue;

      const lock = store.acquireLock(ctx.repoKey, project.name, project.workspace, ctx.pr.number, user);
      if (!lock.ok) { notes.set(project.name, `🔒 locked by #${lock.heldBy.pr}`); continue; }

      const action: Action = plan.destroys > 0 ? 'apply_destroy' : 'apply';
      const perm = await this.allowed(ctx, 'apply', user, project);
      const permDestroy = action === 'apply_destroy' && perm.allowed ? await this.allowed(ctx, 'apply_destroy', user, project) : perm;
      if (!perm.allowed || !permDestroy.allowed) {
        const reason = !perm.allowed ? perm.reason : `${permDestroy.reason} (this plan destroys or replaces ${plan.destroys} resource${plan.destroys === 1 ? '' : 's'})`;
        denied.push(`- \`${project.name}\`: ${reason}`);
        continue;
      }

      if (this.twoPerson(ctx, project) && user.toLowerCase() === ctx.pr.author.toLowerCase()) {
        this.deps.store.audit({ repo: ctx.repoKey, pr: ctx.pr.number, user, action: 'apply', project: project.name, allowed: false, reason: 'two-person rule: the PR author may not apply' });
        denied.push(`- \`${project.name}\`: two-person rule: someone other than the PR author (${ctx.pr.author}) must apply`);
        continue;
      }

      // --override: each freeze, protected resource and policy checks its own override list.
      const skipped: string[] = [];
      const blockers = await this.blockers(ctx, project, plan, approvers, { override: cmd.override, user, skipped });
      if (cmd.override) {
        this.deps.store.audit({
          repo: ctx.repoKey, pr: ctx.pr.number, user, action: 'override', project: project.name, allowed: skipped.length > 0,
          reason: skipped.length ? `--override skipped: ${skipped.join('; ')}` : '--override: nothing this person may override',
        });
      }
      if (blockers.length) {
        denied.push(`- \`${project.name}\`: ${blockers.join('; ')}`);
        continue;
      }
      approved.push({ project, plan });
      // Out of date (warn mode): applied, with a heads-up in the reply.
      if (this.safety(ctx).staleBase === 'warn') {
        const stale = await this.stale(ctx, project);
        if (stale) staleNotes.push(`⚠️ ${stale}.`);
      }
    }

    // Apply in dependency waves: a project starts once everything it depends on
    // has applied; projects in the same wave run in parallel.
    const failed = new Set<string>();
    const held = new Set<string>();    // re-planned or waiting on one: applies in a later command
    const appliedNow = new Set<string>();
    const replanned: string[] = [];
    for (const wave of this.waves(approved.map(a => a.project))) {
      await Promise.all(wave.map(async project => {
        const blockedBy = approved.map(a => a.project).filter(q => project.deps.includes(q.dir) && failed.has(q.name));
        if (blockedBy.length) {
          notes.set(project.name, `skipped: ${blockedBy.map(q => `\`${q.name}\``).join(', ')} failed to apply first`);
          failed.add(project.name);
          return;
        }
        const waitingOn = approved.map(a => a.project).filter(q => project.deps.includes(q.dir) && held.has(q.name));
        if (waitingOn.length) {
          notes.set(project.name, `waits for ${waitingOn.map(q => `\`${q.name}\``).join(', ')} (re-planned); apply it after that`);
          held.add(project.name);
          return;
        }
        // Its plan used the dependency's old (or mock) outputs: plan again with the
        // real ones and let people review that, instead of applying a stale plan.
        const changedDeps = approved.map(a => a.project).filter(q => project.deps.includes(q.dir) && appliedNow.has(q.name));
        if (changedDeps.length) {
          if (!(await this.inTurn(ctx, () => this.planProject(ctx, project, user, {})))) { notes.set(project.name, '⏹️ cancelled'); held.add(project.name); return; }
          replanned.push(project.name);
          notes.set(project.name, `🔁 re-planned after ${changedDeps.map(q => `\`${q.name}\``).join(', ')} applied (its outputs feed this project). Review the new plan, then comment \`${this.deps.config.commandNames[0]} apply -p ${project.name}\``);
          held.add(project.name); // its own dependents wait too
          return;
        }
        const { plan } = approved.find(a => a.project.name === project.name)!;
        attempted.add(project.name);
        if (!(await this.inTurn(ctx, () => this.applyProject(ctx, project, user, plan)))) { attempted.delete(project.name); notes.set(project.name, '⏹️ cancelled before it started'); return; }
        if (this.deps.store.latestRuns(ctx.repoKey, ctx.pr.number, 'apply').find(r => r.project === project.name)?.status !== 'success') failed.add(project.name);
        else appliedNow.add(project.name);
      }));
    }

    // Anything in this PR that depends on what was just applied is planned again
    // (plan only, never applied), so its next apply uses the real outputs.
    const appliedDirs = ctx.projects.filter(p => appliedNow.has(p.name)).map(p => p.dir);
    const headPlans = new Set(this.deps.store.latestRuns(ctx.repoKey, ctx.pr.number, 'plan').filter(r => r.headSha === ctx.pr.headSha).map(r => r.project));
    const dependents = ctx.projects.filter(p => !appliedNow.has(p.name) && !replanned.includes(p.name)
      && headPlans.has(p.name) && p.deps.some(d => appliedDirs.includes(d)));
    await Promise.all(dependents.map(p => this.inTurn(ctx, async () => {
      await this.planProject(ctx, p, user, {});
      replanned.push(p.name);
      const from = ctx.projects.filter(q => appliedNow.has(q.name) && p.deps.includes(q.dir)).map(q => `\`${q.name}\``).join(', ');
      notes.set(p.name, `🔁 re-planned with the new outputs of ${from}. Review it, then comment \`${this.deps.config.commandNames[0]} apply -p ${p.name}\``);
    }).then(ran => { if (!ran) notes.set(p.name, '⏹️ cancelled'); })));

    const applied = this.deps.store.latestRuns(ctx.repoKey, ctx.pr.number, 'apply')
      .filter(r => r.headSha === ctx.pr.headSha && attempted.has(r.project));
    const done = applied.filter(r => r.status === 'success').map(r => `- ✅ \`${r.project}\`: applied`);
    const broke = applied.filter(r => r.status === 'failed').map(r => `- ❌ \`${r.project}\`: apply failed (see the summary for the log)`);
    const link = ctx.summaryUrl ? ` · [see the summary](${ctx.summaryUrl})` : '';
    if (this.commentMode(ctx) === 'update') {
      await this.refreshComment(ctx, notes);
      if (done.length || broke.length) reply.say([`${broke.length ? '⚠️' : '✅'} **Applied ${done.length} of ${applied.length}**${ctx.summaryUrl ? ` · [see the summary](${ctx.summaryUrl})` : link}`, ...done, ...broke].join('\n'));
    } else {
      // The apply's own report: what was created, changed and destroyed, outputs, the apply log.
      if (applied.length) {
        const planOf = new Map(this.deps.store.latestRuns(ctx.repoKey, ctx.pr.number, 'plan').filter(r => r.headSha === ctx.pr.headSha).map(r => [r.project, r]));
        reply.say(renderApplyReport({
          marker: '<!-- teriac:apply -->', headSha: ctx.pr.headSha, command: this.deps.config.commandNames[0],
          applies: applied.map(r => ({ name: r.project, apply: r, plan: plans.get(`${r.project}::${r.workspace}`) ?? planOf.get(r.project), dir: ctx.projects.find(p => p.name === r.project)?.dir })),
          links: this.commentLinks(ctx), limit: ctx.adapter.commentLimit, dashboardUrl: this.deps.config.publicUrl,
        }));
      }
      // Units re-planned with new dependency outputs: their (new) plan, to review.
      if (replanned.length) await this.refreshComment(ctx, new Map(), new Set(replanned), reply);
    }
    for (const n of staleNotes) reply.say(n);
    const failedApplies = applied.filter(r => r.status === 'failed').map(r => r.project);
    if (failedApplies.length) {
      const cmd = this.deps.config.commandNames[0];
      reply.say(`❌ The plan${failedApplies.length === 1 ? '' : 's'} for ${failedApplies.map(p => `\`${p}\``).join(', ')} ${failedApplies.length === 1 ? 'was' : 'were'} used up by the failed apply. Fix the problem, then comment ${failedApplies.map(p => `\`${cmd} plan -p ${p}\``).join(', ')} and apply the new plan.`);
    }
    const stillLocked = applied.filter(r => r.status === 'success' && this.deps.store.getLock(ctx.repoKey, r.project, r.workspace)?.pr === ctx.pr.number).map(r => r.project);
    if (stillLocked.length && !ctx.policy.automerge) {
      reply.say(`🔒 ${stillLocked.map(p => `\`${p}\``).join(', ')} ${stillLocked.length === 1 ? 'stays' : 'stay'} locked to this PR until it's merged or closed. To free ${stillLocked.length === 1 ? 'it' : 'them'} sooner, comment \`${this.deps.config.commandNames[0]} unlock${stillLocked.length === 1 ? ` -p ${stillLocked[0]}` : ''}\`.`);
    }
    if (denied.length) reply.say(`**Not applied:**\n${denied.join('\n')}`);
    for (const [project, note] of notes) reply.say(`- \`${project}\`: ${note}`);

    // The commands to type next, each in a block with a copy button.
    const name = this.deps.config.commandNames[0];
    const next: string[] = [];
    for (const project of selected) {
      const plan = plans.get(`${project.name}::${project.workspace}`);
      for (const m of plan?.mocks ?? []) next.push(`${name} apply -p ${m}`);
    }
    for (const p of replanned) next.push(`${name} apply -p ${p}`);
    const unique = [...new Set(next)].filter(c => !attempted.has(c.slice(`${name} apply -p `.length)) || replanned.includes(c.slice(`${name} apply -p `.length)));
    if (unique.length) reply.say(['**Next, comment:**', ...unique.flatMap(c => [...cmdBlock(c), ''])].join('\n').trim());
    await this.automerge(ctx, user, reply);
  }

  // automerge: once every project with planned changes at this commit is applied (and
  // none failed), merge the PR. Only that commit is merged: a newer push stops it.
  private async automerge(ctx: PrContext, user: string, reply: Reply) {
    const am = ctx.policy.automerge;
    if (!am || !ctx.adapter.mergePullRequest) return;
    const { store } = this.deps;
    const plans = store.latestRuns(ctx.repoKey, ctx.pr.number, 'plan').filter(r => r.headSha === ctx.pr.headSha);
    const applies = store.latestRuns(ctx.repoKey, ctx.pr.number, 'apply').filter(r => r.headSha === ctx.pr.headSha);
    if (!plans.length || plans.some(r => r.status === 'failed')) return;
    const toApply = plans.filter(r => r.hasChanges);
    if (!toApply.length) return;
    const appliedOk = (p: Run) => applies.some(a => a.project === p.project && a.workspace === p.workspace && a.status === 'success' && a.id > p.id);
    if (!toApply.every(appliedOk)) return;
    const method = typeof am === 'object' ? am.method ?? 'merge' : 'merge';
    const r = await ctx.adapter.mergePullRequest(ctx.repo, ctx.pr.number, method, ctx.pr.headSha)
      .catch(err => ({ ok: false, message: (err as Error).message }));
    store.audit({ repo: ctx.repoKey, pr: ctx.pr.number, user, action: 'automerge', project: '*', allowed: r.ok, reason: r.ok ? `merged (${method})` : r.message });
    if (!r.ok) return reply.say(`⚠️ Everything is applied, but teriac couldn't merge this PR: ${r.message}. Merge it yourself.`);
    let deleted = false;
    if (typeof am === 'object' && am.delete_branch && !ctx.pr.fromFork && ctx.adapter.deleteBranch) {
      deleted = await ctx.adapter.deleteBranch(ctx.repo, ctx.pr.headRef).catch(() => false);
    }
    reply.say(`🔀 Everything planned is applied, so teriac merged this PR (${method})${deleted ? ` and deleted \`${ctx.pr.headRef}\`` : ''}.`);
  }

  private async applyProject(ctx: PrContext, project: Project, user: string, plan: Run) {
    const { store, config } = this.deps;
    const started = Date.now();
    const runId = store.startRun({ repo: ctx.repoKey, pr: ctx.pr.number, project: project.name, workspace: project.workspace, kind: 'apply', headSha: ctx.pr.headSha, user, prAuthor: ctx.pr.author, dir: project.dir, queuedMs: this.waited.getStore()?.ms });
    const live = this.liveFor(ctx, project, runId);
    const liveUrl = this.commentLinks(ctx).run!(runId);
    await this.check(ctx, { name: `teriac: ${project.name}`, headSha: ctx.pr.headSha, externalId: project.name, status: 'in_progress', title: 'Applying…', summary: `Applying \`${project.name}\` for @${user}\n\n▶ [Watch the live output](${liveUrl})`, detailsUrl: liveUrl });
    let engine = plan.engine;
    try {
      // Apply exactly what was reviewed: the plan file must be the one saved at plan time.
      if (this.safety(ctx).verifyPlan && plan.planSha) {
        const now = existsSync(plan.planPath!) ? sha256File(plan.planPath!) : null;
        if (now !== plan.planSha) {
          store.audit({ repo: ctx.repoKey, pr: ctx.pr.number, user, action: 'apply', project: project.name, allowed: false, reason: `plan file ${now ? 'changed' : 'missing'} since it was reviewed (run ${plan.id})` });
          store.finishRun(runId, { status: 'failed', engine, output: `teriac refused to apply: the saved plan file ${now ? 'changed' : 'is missing'} since it was reviewed. Plan again (\`${config.commandNames[0]} plan -p ${project.name}\`), review it, then apply.` });
          live.end();
          metrics.observeRun('apply', 'failed', Date.now() - started);
          await this.publishCheck(ctx, project, store.getRun(runId)!);
          return;
        }
      }
      const tools = await this.tools(ctx, project);
      engine = engineLabel(tools);
      // The reviewed plan knows which values are sensitive: hide them from the first line.
      let sensitive: string[] = [];
      try { sensitive = sensitiveValues(JSON.parse(readFileSync(`${plan.planPath}.json`, 'utf-8'))); } catch { /* no saved plan JSON */ }
      live.sensitive(sensitive);
      const r = await runApply({ root: ctx.root, project, tools, planPath: plan.planPath!, env: this.env(ctx, project, user), timeoutMs: config.runTimeoutMs, onOutput: live.write, onSensitive: live.sensitive, sensitive, hooks: { pre: ctx.policy.hooks?.pre_apply, post: ctx.policy.hooks?.post_apply } });
      // The apply already happened, so "fail" mode can only hide the output here.
      const scanned = this.scan(ctx, r.output);
      this.auditSecrets(ctx, user, project, scanned.found, 'apply');
      // The counts are saved now, so the Metrics page never has to read logs.
      // A failed apply: what went wrong and how to fix it, from the AI (when on).
      const ai = r.ok ? null : await this.aiFailure(ctx, project, 'apply', scanned.text);
      store.finishRun(runId, { status: r.ok ? 'success' : 'failed', engine, output: scanned.text, summary: plan.summary, usage: r.usage ?? null, applied: parseApplyResult(r.output), secrets: scanned.found, ai });
      if (ai?.kind === 'fix' && await this.suggestFixes(ctx, project, ai)) store.setRunAi(runId, { ...ai, posted: true });
      this.notifyApply(ctx, project, user, store.getRun(runId)!);
      if (r.ok) {
        // unlock_after_apply: free the project for other PRs now. By default the lock stays
        // until the PR is merged or closed, so another PR can't undo an unmerged apply.
        // A failed apply always keeps it.
        const lock = store.getLock(ctx.repoKey, project.name, project.workspace);
        if (ctx.policy.unlock_after_apply && lock?.pr === ctx.pr.number) store.releaseLock(ctx.repoKey, project.name, project.workspace);
      }
    } catch (err) {
      store.finishRun(runId, { status: 'failed', engine, output: `teriac could not apply this project: ${(err as Error).message}` });
    } finally {
      live.end();
      // A plan is applied once, whatever the outcome: after a failed apply the state has
      // moved on and the plan is stale. Delete it; applying again needs a new plan. The
      // run, its output and the apply's live output stay.
      this.forgetPlans(ctx.repoKey, ctx.pr.number, project.name, { keepLive: true });
    }
    metrics.observeRun('apply', store.getRun(runId)!.status, Date.now() - started);
    await this.publishCheck(ctx, project, store.getRun(runId)!);
  }

  // ---- unlock ----

  private async unlock(ctx: PrContext, user: string, cmd: Command, reply: Reply) {
    const { store } = this.deps;
    // These locks belong to this PR: its author or anyone who may plan here can drop them.
    const locks = store.locksForPr(ctx.repoKey, ctx.pr.number)
      .filter(l => !cmd.project || l.project === cmd.project);
    const isAuthor = user.toLowerCase() === ctx.pr.author.toLowerCase();
    const released: string[] = [];
    for (const l of locks) {
      const project = ctx.projects.find(p => p.name === l.project) ?? { name: l.project, dir: l.project } as Project;
      const ok = isAuthor || (await this.allowed(ctx, 'plan', user, project)).allowed;
      if (!ok) continue;
      store.releaseLock(l.repo, l.project, l.workspace);
      this.forgetPlans(ctx.repoKey, ctx.pr.number, l.project);
      released.push(l.project);
    }
    // Unlock always ends the project here: its saved plans and live output go, lock or not.
    let discarded = false;
    if (!locks.length && (isAuthor || (cmd.project && (await this.allowed(ctx, 'plan', user, ctx.projects.find(p => p.name === cmd.project) ?? { name: cmd.project, dir: cmd.project } as Project)).allowed))) {
      discarded = this.deps.store.latestRuns(ctx.repoKey, ctx.pr.number, 'plan').some(r => (!cmd.project || r.project === cmd.project) && r.planPath);
      this.forgetPlans(ctx.repoKey, ctx.pr.number, cmd.project);
    } else if (!cmd.project && released.length) this.forgetPlans(ctx.repoKey, ctx.pr.number);
    reply.say(released.length
      ? `🔓 Unlocked ${released.map(p => `\`${p}\``).join(', ')} and discarded the plans. Run \`teriac plan\` to plan again.`
      : discarded ? `🗑️ No locks to release; discarded the saved plans${cmd.project ? ` of \`${cmd.project}\`` : ''}.`
      : 'This PR holds no locks you can release.');
  }

  // A lock released from the dashboard: drop that project's plan (it was made under the
  // lock) and tell the PR, so its people know why they must plan again.
  async dashboardUnlock(adapter: VcsAdapter | undefined, lock: { repo: string; pr: number; project: string; workspace: string; user: string }, by: { name: string; via: string }): Promise<boolean> {
    this.forgetPlans(lock.repo, lock.pr, lock.project);
    if (!adapter) return false;
    const [host, owner, ...rest] = lock.repo.split('/');
    const name = rest.join('/');
    const repo: Repo = { platform: adapter.platform, host, owner, name, fullName: `${owner}/${name}`, cloneUrl: '' };
    const cmd = this.deps.config.commandNames[0];
    const ws = lock.workspace !== 'default' ? ` (workspace \`${lock.workspace}\`)` : '';
    try {
      await this.recording(adapter).comment(repo, lock.pr, [
        `🔓 **\`${lock.project}\`${ws} was unlocked from the teriac dashboard** by ${by.name} (${by.via}).`,
        '',
        `Its plan was discarded, and another PR may now plan and apply it. To continue here, plan it again:`,
        ...cmdBlock(`${cmd} plan -p ${lock.project}`),
      ].join('\n'));
      return true;
    } catch (err) {
      log.warn('could not post the dashboard unlock to the PR', { repo: lock.repo, pr: lock.pr, err: (err as Error).message });
      return false;
    }
  }

  // ---- output ----

  private async check(ctx: PrContext, check: Parameters<VcsAdapter['setCheck']>[1]) {
    if (!ctx.adapter.supportsChecks) return;
    const url = await ctx.adapter.setCheck(ctx.repo, { ...check, detailsUrl: check.detailsUrl ?? `${this.deps.config.publicUrl}/` })
      .catch(err => { log.warn('check update failed', { err }); return null; });
    if (url && check.externalId) this.checkUrls.set(`${ctx.repoKey}#${ctx.pr.number}#${check.externalId}`, url);
  }

  private async publishCheck(ctx: PrContext, project: Project, run: Run) {
    if (!ctx.adapter.supportsChecks) return;
    let blockers: string[] | undefined;
    if (run.kind === 'plan' && run.status === 'success' && run.hasChanges) {
      blockers = await this.blockers(ctx, project, run, await this.approvers(ctx));
    }
    const out = renderCheck(project.name, run, blockers);
    const canApply = run.kind === 'plan' && run.status === 'success' && run.hasChanges;
    await this.check(ctx, {
      detailsUrl: this.commentLinks(ctx).run!(run.id),
      name: `teriac: ${project.name}`, headSha: run.headSha, externalId: project.name, status: 'completed',
      conclusion: run.status === 'success' ? (canApply ? 'neutral' : 'success') : 'failure',
      title: out.title, summary: out.summary, text: out.text,
      actions: canApply ? [{ label: 'Apply', identifier: 'apply', description: `Apply ${project.name}`.slice(0, 40) }] : undefined,
      annotations: run.kind === 'plan' && run.status === 'success' ? this.annotations(ctx, project, run) : undefined,
    });
  }

  // Notes on the code behind risky changes and policy findings, shown in the PR's
  // "Files changed": destroys and replacements, protected resources, findings.
  private annotations(ctx: PrContext, project: Project, run: Run): Annotation[] {
    const s = summaryOf(run);
    if (!s) return [];
    const protectedSet = new Set(protectedHits(this.safety(ctx).protected, project, s).map(h => h.address));
    const out = new Map<string, Annotation>();
    const add = (address: string, level: Annotation['level'], title: string, message: string) => {
      const loc = locate(ctx.root, project.dir, address);
      if (!loc) return;
      const key = `${loc.file}:${loc.start}:${title}`;
      if (!out.has(key)) out.set(key, { path: loc.file, startLine: loc.start, endLine: loc.start, level, title, message });
    };
    for (const c of s.changes) {
      if (c.action !== 'delete' && c.action !== 'replace') continue;
      const verb = c.action === 'delete' ? 'destroyed' : 'replaced';
      const prot = protectedSet.has(c.address);
      add(c.address, prot ? 'failure' : 'warning', `${c.address} will be ${verb}${prot ? ' (protected)' : ''}`,
        [c.reason ? `Replaced because ${c.reason} changed.` : '', prot ? 'This resource is protected: applying needs --override.' : '', run.risk ? `Plan risk: ${run.risk.level}.` : ''].filter(Boolean).join(' ') || `This plan ${c.action === 'delete' ? 'destroys' : 'replaces'} it.`);
    }
    for (const f of this.policyOf(run)?.findings ?? []) {
      if (f.address === '(scanner)') continue;
      add(f.address, f.severity === 'critical' || f.severity === 'high' ? 'failure' : 'warning', `Policy: ${f.rule}`, f.message);
    }
    if (run.ai?.kind === 'review') {
      const noted = new Set([...out.values()].map(a => `${a.path}:${a.startLine}`));
      for (const f of run.ai.findings.filter(important)) {
        const loc = locate(ctx.root, project.dir, f.address);
        if (loc && noted.has(`${loc.file}:${loc.start}`)) continue;
        add(f.address, 'warning', `AI review: ${f.title}`, `${f.why} (${run.ai.model}, advisory)`);
      }
    }
    return [...out.values()].slice(0, 50);
  }

  // Links and avatars for comments on this PR's platform.
  private commentLinks(ctx: PrContext): CommentLinks {
    const l = repoLinks(ctx.repoKey, platformForHost(ctx.repo.host, { [ctx.repo.host]: ctx.repo.platform }));
    return {
      commit: sha => l.commit(sha),
      tree: (sha, dir) => l.tree(sha, dir),
      user: login => l.user(login),
      // Round, from this server, when GitHub can reach it (a public https URL); else GitHub's square photo.
      avatar: login => (!avatarSource(ctx.repo.platform, ctx.repo.host, login) ? null
        : this.deps.config.spinnerUrl ? `${this.deps.config.publicUrl}${roundAvatarPath(ctx.repo.host, login)}`
        : `https://${ctx.repo.host}/${encodeURIComponent(login)}.png?size=36`),
      // The run's page, with its repo and PR in the address: #runs/<owner>/<repo>/pull/<pr>/<run>.
      run: id => `${this.deps.config.publicUrl}/#runs/${ctx.repo.owner}/${ctx.repo.name}/pull/${ctx.pr.number}/${id}`,
    };
  }

  private commentMode(ctx: PrContext) { return ctx.policy.comment_mode ?? this.deps.config.commentMode; }

  // Renders the plan report. "new" mode: only this command's projects, as the
  // command's own reply (a new comment). "update" mode: every project, in one
  // comment at the top that is edited in place.
  private async refreshComment(ctx: PrContext, notes: Map<string, string>, only?: Set<string>, reply?: Reply) {
    const { store, config } = this.deps;
    const head = ctx.pr.headSha;
    const asReply = this.commentMode(ctx) === 'new' && reply;
    const plans = store.latestRuns(ctx.repoKey, ctx.pr.number, 'plan')
      .filter(r => r.headSha === head && (!asReply || !only || only.has(r.project)));
    const applies = new Map(store.latestRuns(ctx.repoKey, ctx.pr.number, 'apply').map(r => [`${r.project}::${r.workspace}`, r]));
    const approvers = plans.some(p => p.status === 'success' && p.hasChanges) ? await this.approvers(ctx) : [];

    const views: ProjectView[] = [];
    for (const plan of plans) {
      const project = ctx.projects.find(p => p.name === plan.project) ?? { name: plan.project, dir: plan.project, deps: [] } as unknown as Project;
      const view: ProjectView = {
        name: plan.project, plan, apply: applies.get(`${plan.project}::${plan.workspace}`), note: notes.get(plan.project), dir: project.dir,
        checkUrl: this.checkUrls.get(`${ctx.repoKey}#${ctx.pr.number}#${plan.project}`) ?? null,
      };
      if (plan.status === 'success' && plan.hasChanges) {
        view.blockers = await this.blockers(ctx, project, plan, approvers);
        if (this.twoPerson(ctx, project)) view.applyBy = `someone other than ${ctx.pr.author}`;
        if (this.safety(ctx).staleBase === 'warn') {
          const stale = await this.stale(ctx, project);
          if (stale) view.warnings = [`${stale}.`];
        }
      }
      views.push(view);
    }
    for (const [name, note] of notes) if (!views.some(v => v.name === name)) views.push({ name, note });
    if (!views.length) return;
    if (asReply && plans.length === 0) {
      // Nothing ran (locked or not allowed): say why, in the reply.
      reply.say([...notes].map(([name, note]) => `- \`${name}\`: ${note}`).join('\n'));
      return;
    }
    views.sort((a, b) => a.name.localeCompare(b.name));

    // `teriac review` goes in the footer when some project here reviews only on request.
    const reviewCommand = views.some(v => {
      const p = ctx.projects.find(x => x.name === v.name);
      const s = p ? this.aiFor(ctx, p, 'review') : null;
      return !!s && s.review !== 'push';
    });
    const body = renderComment({
      reviewCommand,
      marker: asReply ? '<!-- teriac:report -->' : MARKER, headSha: head, command: config.commandNames[0], projects: views,
      dashboardUrl: config.publicUrl, limit: ctx.adapter.commentLimit, warnings: ctx.warnings,
      oneProjectPerApply: this.oneAtATime(ctx),
      approvers,
      carried: ctx.carried,
      links: this.commentLinks(ctx),
    });
    if (asReply) {
      reply.say(body);
      return;
    }
    const saved = await ctx.adapter.upsertComment(ctx.repo, ctx.pr.number, MARKER, body, store.commentId(ctx.repoKey, ctx.pr.number));
    if (saved) store.saveCommentId(ctx.repoKey, ctx.pr.number, saved.id);
    ctx.summaryUrl = saved?.url ?? null;
  }
}
