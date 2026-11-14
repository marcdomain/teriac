// Runs plan / apply for one project with the exact tool versions it pins.
import { UsageSampler, combineUsage, type Usage } from './usage.ts';
import { spawn } from 'node:child_process';
import { mkdirSync, existsSync, rmSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import type { Project } from './discovery.ts';
import type { Provider } from './teriac.ts';
import { teriac } from './teriac.ts';
import { redact } from './log.ts';
import { summarizePlan, type PlanSummary } from './render.ts';
import { sensitiveValues, hideValues } from './sensitive.ts';

export interface Tool { provider: Provider; version: string; binary: string }
export interface ToolSet { tool: Tool; terragrunt?: Tool }

export interface ToolResolver {
  resolve(root: string, project: Project): Promise<ToolSet>;
}

const parents = (root: string, dir: string): string[] => {
  const out: string[] = [];
  let d = dir === '.' ? root : join(root, dir);
  while (true) {
    out.push(d);
    if (d === root) break;
    const up = dirname(d);
    if (up === d || !up.startsWith(root)) break;
    d = up;
  }
  return out;
};

// Version pinned for `provider`: the project dir (all sources), then parent
// dirs up to the repo root (version files and terragrunt constraints only).
export const findPinnedUp = (root: string, dir: string, provider: Provider): string | null => {
  const core = teriac();
  const [own, ...ups] = parents(root, dir);
  const pinned = core.findPinnedVersion(own, provider);
  if (pinned) return pinned.version;
  for (const d of ups) {
    const p = core.findPinnedVersion(d, provider, { strict: true })
      ?? (provider !== 'terragrunt' ? core.findHclConstraint(d, 'terraform_version_constraint') : null);
    if (p) return p.version;
  }
  return null;
};

export const teriacResolver = (defaultVersion: string): ToolResolver => ({
  async resolve(root, project) {
    const core = teriac();
    const get = async (provider: Provider, configured?: string): Promise<Tool> => {
      const wanted = configured ?? findPinnedUp(root, project.dir, provider) ?? defaultVersion;
      const exact = await core.resolveExactVersion(provider, wanted === 'latest' ? '>= 0' : wanted);
      const r = await core.installVersion(provider, exact);
      return { provider, version: r.version, binary: r.binary };
    };
    const tool = await get(project.tool, project.version);
    const terragrunt = project.engine === 'terragrunt' ? await get('terragrunt', project.terragruntVersion) : undefined;
    return { tool, terragrunt };
  },
});

export const engineLabel = (t: ToolSet) =>
  t.terragrunt ? `terragrunt ${t.terragrunt.version} + ${t.tool.provider} ${t.tool.version}` : `${t.tool.provider} ${t.tool.version}`;

// ---- process execution ----------------------------------------------------

const MAX_OUTPUT = 4 * 1024 * 1024;

interface ExecResult { code: number; output: string; stdout: string; usage?: Usage | null }

export const exec = (
  binary: string, args: string[], cwd: string, env: NodeJS.ProcessEnv,
  opts: { timeoutMs: number; captureStdout?: boolean; onOutput?: (chunk: string) => void; measure?: boolean },
): Promise<ExecResult> => new Promise((resolve) => {
  const child = spawn(binary, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
  const sampler = opts.measure && child.pid ? new UsageSampler(child.pid) : null;
  let output = '';
  let stdout = '';
  const add = (chunk: Buffer, isStdout: boolean) => {
    const text = chunk.toString('utf-8');
    if (isStdout && opts.captureStdout) { stdout += text; return; }
    output += text;
    if (output.length > MAX_OUTPUT) output = output.slice(output.length - MAX_OUTPUT);
    // Raw: the live log splits output into whole lines and cleans each one.
    opts.onOutput?.(text);
  };
  child.stdout.on('data', c => add(c, true));
  child.stderr.on('data', c => add(c, false));
  const timer = setTimeout(() => {
    output += `\n[teriac] timed out after ${Math.round(opts.timeoutMs / 1000)}s; stopping\n`;
    child.kill('SIGTERM');
    setTimeout(() => child.kill('SIGKILL'), 10_000).unref();
  }, opts.timeoutMs);
  child.on('error', err => { clearTimeout(timer); sampler?.stop(); resolve({ code: 127, output: `${output}\n${err.message}`, stdout }); });
  child.on('close', code => { clearTimeout(timer); resolve({ code: code ?? 1, output: redact(output), stdout, usage: sampler?.stop() ?? null }); });
});

// Git settings, as env vars, that send `auth`'s header to its host: Terraform's
// `git::https://` module downloads then sign in, and nothing is written to disk. Left out
// when the server's env already sets GIT_CONFIG_* (your own module credentials win).
export const gitAuthEnv = (base: NodeJS.ProcessEnv, auth: { url: string; extraHeader?: string } | null | undefined): Record<string, string> => {
  if (!auth?.extraHeader || base.GIT_CONFIG_COUNT) return {};
  let origin: string;
  try { origin = new URL(auth.url).origin; } catch { return {}; }
  if (!/^https?:/.test(origin)) return {};
  return { GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: `http.${origin}/.extraheader`, GIT_CONFIG_VALUE_0: auth.extraHeader };
};

// Env for terraform/terragrunt: the server's env minus its own settings and
// secrets (anything TERIAC_*), plus automation flags and PR context.
export const toolEnv = (base: NodeJS.ProcessEnv, extra: Record<string, string>): NodeJS.ProcessEnv => {
  const env: NodeJS.ProcessEnv = {};
  // TF_LOG* (debug logs) print credentials and sensitive values: never passed on.
  for (const [k, v] of Object.entries(base)) if (!k.startsWith('TERIAC_') && !/^TF_LOG/.test(k)) env[k] = v;
  return {
    ...env,
    TF_IN_AUTOMATION: '1',
    TF_INPUT: '0',
    CHECKPOINT_DISABLE: '1',
    TG_NON_INTERACTIVE: 'true',
    TERRAGRUNT_NON_INTERACTIVE: 'true',
    TG_NO_COLOR: 'true',
    TERRAGRUNT_NO_COLOR: 'true',
    ...extra,
  };
};

export interface RunContext {
  root: string;               // checkout dir
  project: Project;
  tools: ToolSet;
  planPath: string;
  env: NodeJS.ProcessEnv;
  timeoutMs: number;
  onOutput?: (chunk: string) => void;       // live output, raw (whole lines, paths tidied)
  onSensitive?: (values: string[]) => void; // sensitive values found while running
  sensitive?: string[];                     // values to hide from the start (apply: from its plan)
}

export interface PlanResult {
  ok: boolean;
  output: string;
  summary: PlanSummary | null;
  hasChanges: boolean;
  plan?: Record<string, any>;  // full `show -json` output
  planJsonPath?: string;       // the same, written next to the plan file
  usage?: Usage | null;        // CPU and memory of the whole run
  sensitive?: string[];        // values Terraform marks sensitive (state and plan), hidden above
}

const steps = (ctx: RunContext) => {
  const { tools, project } = ctx;
  const cwd = project.dir === '.' ? ctx.root : join(ctx.root, project.dir);
  const env = tools.terragrunt
    ? { ...ctx.env, TG_TF_PATH: tools.tool.binary, TERRAGRUNT_TFPATH: tools.tool.binary }
    : ctx.env;
  const bin = tools.terragrunt?.binary ?? tools.tool.binary;
  // Server paths mean nothing to PR readers: show the plan as "tfplan", the checkout as ".".
  const tidy = (text: string) => text.split(ctx.planPath).join('tfplan').split(ctx.root).join('.');
  let usage: Usage | null = null;
  // Live output in whole lines, with server paths tidied (a path is never split across chunks).
  let partial = '';
  const live = (chunk: string) => {
    if (!ctx.onOutput) return;
    const parts = (partial + chunk).split('\n');
    partial = parts.pop() ?? '';
    if (parts.length) ctx.onOutput(parts.map(tidy).join('\n') + '\n');
  };
  const flush = () => { if (partial && ctx.onOutput) ctx.onOutput(`${tidy(partial)}\n`); partial = ''; };
  const hidden = new Set<string>(ctx.sensitive ?? []);
  const learn = (values: string[]) => {
    const fresh = values.filter(v => !hidden.has(v));
    if (!fresh.length) return;
    for (const v of fresh) hidden.add(v);
    ctx.onSensitive?.(fresh);
  };
  const run = async (args: string[], log: string[], captureStdout = false, quiet = false) => {
    const line = tidy(`$ ${tools.terragrunt ? 'terragrunt' : tools.tool.provider === 'opentofu' ? 'tofu' : 'terraform'} ${args.join(' ')}`);
    log.push(line);
    if (!quiet) live(`${line}\n`);
    const r = await exec(bin, args, cwd, env, { timeoutMs: ctx.timeoutMs, captureStdout, onOutput: quiet ? undefined : live, measure: true });
    if (!quiet) flush();
    usage = combineUsage(usage, r.usage ?? null);
    if (r.output.trim()) log.push(tidy(r.output.trimEnd()));
    return r;
  };
  // The state's sensitive values, before anything prints it. Best effort: a project with no
  // state yet, or a backend that can't be read here, just has none.
  const learnState = async () => {
    const r = await run(['show', '-json'], [], true, true);
    try { learn(sensitiveValues(JSON.parse(r.stdout.slice(r.stdout.indexOf('{'))))); } catch { /* no state */ }
  };
  const hide = (text: string) => hideValues(text, [...hidden].sort((a, b) => b.length - a.length));
  const prepare = async (log: string[]) => {
    // Terragrunt runs init itself.
    if (!tools.terragrunt) {
      const init = await run(['init', '-input=false', '-no-color'], log);
      if (init.code !== 0) return false;
    }
    if (project.workspace !== 'default') {
      const ws = await run(['workspace', 'select', '-or-create=true', project.workspace], log);
      if (ws.code !== 0) return false;
    }
    return true;
  };
  return { run, prepare, usage: () => usage, learn, learnState, hide };
};

// `terraform output` prints a sensitive output in plain text when it's asked for by name,
// so outputs are read as JSON and shown here, sensitive ones as "(sensitive value)".
export const renderOutputs = (json: string, name?: string): { ok: boolean; text: string } => {
  let all: Record<string, { sensitive?: boolean; value?: unknown; type?: unknown }>;
  try { all = JSON.parse(json.slice(json.indexOf('{'))); } catch { return { ok: false, text: 'Could not read the outputs.' }; }
  const show = (n: string, o: { sensitive?: boolean; value?: unknown }) =>
    `${n} = ${o.sensitive ? '(sensitive value)' : typeof o.value === 'string' ? JSON.stringify(o.value) : JSON.stringify(o.value, null, 2)}`;
  if (name) {
    const o = all[name];
    if (!o) return { ok: false, text: `No output named "${name}".` };
    return { ok: true, text: show(name, o) };
  }
  return { ok: true, text: Object.entries(all).sort(([a], [b]) => a.localeCompare(b)).map(([n, o]) => show(n, o)).join('\n') };
};

export const plan = async (ctx: RunContext, opts: { destroy?: boolean; targets?: string[]; extraArgs?: string[]; refreshOnly?: boolean; replace?: string[]; noLock?: boolean } = {}): Promise<PlanResult> => {
  const log: string[] = [];
  const { run, prepare, usage, learn, learnState, hide } = steps(ctx);
  mkdirSync(dirname(ctx.planPath), { recursive: true });
  if (existsSync(ctx.planPath)) rmSync(ctx.planPath);
  for (const f of [`${ctx.planPath}.json`]) if (existsSync(f)) rmSync(f);

  if (!(await prepare(log))) return { ok: false, output: hide(log.join('\n')), summary: null, hasChanges: false, usage: usage() };
  await learnState();

  const args = ['plan', '-input=false', '-no-color', '-detailed-exitcode', `-out=${ctx.planPath}`];
  if (opts.destroy) args.push('-destroy');
  for (const t of opts.targets ?? []) args.push(`-target=${t}`);
  for (const r of opts.replace ?? []) args.push(`-replace=${r}`);
  // Drift checks only read: -refresh-only finds changes made outside Terraform,
  // and -lock=false keeps them from blocking a PR's apply.
  if (opts.refreshOnly) args.push('-refresh-only');
  if (opts.noLock) args.push('-lock=false');
  args.push(...(opts.extraArgs ?? []));
  const p = await run(args, log);
  // -detailed-exitcode: 0 no changes, 2 changes, anything else failed.
  if (p.code !== 0 && p.code !== 2) return { ok: false, output: hide(log.join('\n')), summary: null, hasChanges: false, usage: usage() };

  const show = await run(['show', '-json', ctx.planPath], [], true, true);
  let summary: PlanSummary | null = null;
  let parsed: Record<string, any> | undefined;
  let planJsonPath: string | undefined;
  try {
    // Terragrunt may print log lines before the JSON.
    const json = show.stdout.slice(show.stdout.indexOf('{'));
    parsed = JSON.parse(json);
    learn(sensitiveValues(parsed));
    summary = summarizePlan(parsed!);
    planJsonPath = `${ctx.planPath}.json`;
    writeFileSync(planJsonPath, json);
  } catch {
    log.push('[teriac] could not read the plan as JSON; showing raw output only');
  }
  const hasChanges = summary ? !summary.noChanges : p.code === 2;
  return { ok: true, output: hide(log.join('\n')), summary, hasChanges, plan: parsed, planJsonPath, usage: usage(), sensitive: parsed ? sensitiveValues(parsed) : [] };
};

export const apply = async (ctx: RunContext): Promise<{ ok: boolean; output: string; usage?: Usage | null }> => {
  const log: string[] = [];
  const { run, prepare, usage, hide } = steps(ctx);
  if (!existsSync(ctx.planPath)) return { ok: false, output: 'The saved plan is gone; run plan again.' };
  if (!(await prepare(log))) return { ok: false, output: hide(log.join('\n')), usage: usage() };
  const r = await run(['apply', '-input=false', '-no-color', ctx.planPath], log);
  return { ok: r.code === 0, output: hide(log.join('\n')), usage: usage() };
};

// One Terraform command in a prepared project (init and workspace done first):
// state list/show/rm/mv, output, show, validate, providers, fmt, import, taint, force-unlock.
// Only the command's own output is returned, unless preparing failed.
export const runTool = async (ctx: RunContext, args: string[]): Promise<{ ok: boolean; code: number; output: string }> => {
  const prep: string[] = [];
  const log: string[] = [];
  const { run, prepare, learnState, hide } = steps(ctx);
  if (!(await prepare(prep))) return { ok: false, code: 1, output: hide(prep.join('\n')) };
  // `output`: read as JSON, so sensitive outputs stay hidden even when asked for by name.
  if (args[0] === 'output') {
    const name = args.slice(1).find(a => !a.startsWith('-'));
    const r = await run(['output', '-json'], log, true);
    if (r.code !== 0) return { ok: false, code: r.code, output: hide(log.join('\n')) };
    const o = renderOutputs(r.stdout, name);
    return { ok: o.ok, code: o.ok ? 0 : 1, output: hide([log[0], o.text].join('\n')) };
  }
  // Values the state marks sensitive are hidden wherever `state show` or `show` prints them.
  await learnState();
  const r = await run(args, log);
  // Commands print colour even without a terminal; PR comments can't show it.
  const output = hide(log.join('\n').replace(/\x1b\[[0-9;]*m/g, ''));
  return { ok: r.code === 0, code: r.code, output };
};

