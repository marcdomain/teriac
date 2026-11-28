// Bringing resources made by hand under Terraform: `teriac adopt -p <project> <type> <id>...`.
// Terraform reads each resource and writes its configuration (`plan -generate-config-out`, 1.5+;
// OpenTofu 1.6+). With AI on, Claude tidies that into code a person would write: no computed or
// default arguments, references instead of copied IDs, the project's naming. Then teriac plans
// it again and opens a PR only when the plan imports every resource and fixes nothing up.
//
// Nothing here applies or edits the state: the plan reads the resources, and the import happens
// when someone applies the PR, with its approvals. What the PR may contain is checked line by
// line (checkAdoptCode): import and resource blocks for exactly the resources asked for, nothing
// that can run a program or read a local file.
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { plan as runPlan, type RunContext, type ToolSet } from './runner.ts';
import { projectFiles, label, type Ai, type AiSettings } from './ai.ts';
import { scanSecrets } from './secrets.ts';
import { sensitiveValues } from './sensitive.ts';
import type { SecretPattern } from './safety-config.ts';
import { log } from './log.ts';

export interface AdoptTarget { type: string; name: string | null; id: string }
// A resource being imported: where it goes, its ID, and whether the name was asked for.
export interface AdoptResource { address: string; id: string; named: boolean }
export interface AdoptChange { address: string; actions: string[]; attributes: string[] }

export interface AdoptResult {
  ok: boolean;
  file?: { path: string; content: string };  // repo-relative
  resources: AdoptResource[];
  changes: AdoptChange[];                    // what applying would change besides the import
  others: number;                            // pending changes in the project not from this PR
  notes: string[];
  model?: string;                            // the AI that wrote it, when it did
  rounds: number;                            // plans run to check it
  error?: string;
  output?: string;                           // the last plan's output, when it failed
}

export const MAX_ADOPT = 20;
const TYPE_RE = /^[a-z][a-z0-9]*_[a-z0-9_]+$/;
const NAME_RE = /^[A-Za-z_][A-Za-z0-9_-]{0,63}$/;
const ID_RE = /^[^\s"\\$%{}]{1,512}$/;
const GENERATED = 'teriac-adopt-generated.tf';
const IMPORTS = 'teriac-adopt-imports.tf';

// `<type> <id>` or `<type>.<name> <id>`, repeated.
export const parseAdoptArgs = (args: string[]): { ok: true; targets: AdoptTarget[] } | { ok: false; error: string } => {
  if (!args.length || args.length % 2) return { ok: false, error: 'give pairs of `<type> <id>` (or `<type>.<name> <id>`), e.g. `aws_s3_bucket my-logs-bucket`' };
  if (args.length / 2 > MAX_ADOPT) return { ok: false, error: `at most ${MAX_ADOPT} resources at a time` };
  const targets: AdoptTarget[] = [];
  for (let i = 0; i < args.length; i += 2) {
    const [type, name, ...more] = args[i].split('.');
    const id = args[i + 1];
    if (!TYPE_RE.test(type) || more.length || (name !== undefined && !NAME_RE.test(name))) return { ok: false, error: `\`${args[i]}\` is not a resource type (like \`aws_s3_bucket\`) or \`type.name\`` };
    if (!ID_RE.test(id)) return { ok: false, error: `\`${id}\` is not an import ID teriac accepts (no spaces, quotes or \`\${\`)` };
    targets.push({ type, name: name ?? null, id });
  }
  const ids = targets.map(t => `${t.type} ${t.id}`);
  if (new Set(ids).size !== ids.length) return { ok: false, error: 'the same resource is listed twice' };
  return { ok: true, targets };
};

// A resource name from its ID: "arn:aws:iam::1:role/deploy-bot" → "deploy_bot".
export const nameFromId = (id: string): string => {
  const last = id.split(/[/:]/).filter(Boolean).pop() ?? id;
  let n = last.toLowerCase().replace(/[^a-z0-9_]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 48) || 'this';
  if (/^\d/.test(n)) n = `r_${n}`;
  return n;
};

export const addressesFor = (targets: AdoptTarget[], taken: Set<string> = new Set()): AdoptResource[] => {
  const used = new Set(taken);
  return targets.map(t => {
    let name = t.name ?? nameFromId(t.id);
    if (!t.name) for (let i = 2; used.has(`${t.type}.${name}`); i++) name = `${nameFromId(t.id)}_${i}`;
    used.add(`${t.type}.${name}`);
    return { address: `${t.type}.${name}`, id: t.id, named: !!t.name };
  });
};

export const importBlocks = (resources: AdoptResource[]): string =>
  resources.map(r => `import {\n  to = ${r.address}\n  id = ${JSON.stringify(r.id)}\n}\n`).join('\n');

// Config generation: Terraform 1.5+, OpenTofu 1.6+, not through Terragrunt (its cache folder).
export const generateSupport = (tools: ToolSet): string | null => {
  if (tools.terragrunt) return 'Terragrunt projects are not supported yet: run `terraform plan -generate-config-out` in the module';
  const [maj, min] = tools.tool.version.split('.').map(Number);
  const need = tools.tool.provider === 'opentofu' ? 6 : 5;
  if (maj < 1 || (maj === 1 && min < need)) return `needs ${tools.tool.provider === 'opentofu' ? 'OpenTofu 1.6' : 'Terraform 1.5'} or newer (this project uses ${tools.tool.version})`;
  return null;
};

// ---- what the PR may contain ----

// Things that can run a program, read a local file or reach the network while planning.
const FORBIDDEN: [RegExp, string][] = [
  [/\bprovisioner\b|\bconnection\s*\{/, 'a provisioner'],
  [/local-exec|remote-exec/, 'a provisioner'],
  [/\b(?:file|templatefile|filebase64|filemd5|filesha\d*|fileset|fileexists|pathexpand|abspath)\s*\(/, 'a function that reads local files'],
  [/^\s*(?:source|filename|source_hash|source_code_hash|source_dir)\s*=\s*(?!null\b)/m, 'a local file path'],
  [/\b(?:program|command|interpreter)\s*=/, 'a command'],
  [/‹redacted|\(sensitive value\)/, 'a hidden value'],
];

// Top-level blocks of HCL with their text, skipping strings, comments and heredocs.
export const topBlocks = (code: string): { head: string; body: string; line: number }[] | string => {
  const lines = code.split('\n');
  const out: { head: string; body: string; line: number }[] = [];
  let depth = 0;
  let heredoc: string | null = null;
  let cur: { head: string; body: string[]; line: number } | null = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (heredoc) {
      cur?.body.push(line);
      if (line.trim() === heredoc) heredoc = null;
      continue;
    }
    const code = line.replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/#.*|\/\/.*/, '');
    if (depth === 0) {
      if (!code.trim()) continue;
      if (/\/\*/.test(code)) return `line ${i + 1}: block comments are not allowed`;
      const m = /^\s*([a-z_]+)((?:\s+"[^"]*")*)\s*\{\s*(\}\s*)?$/.exec(line.replace(/#.*$/, ''));
      if (!m) return `line ${i + 1}: only import and resource blocks are allowed`;
      cur = { head: `${m[1]}${m[2]}`.replace(/\s+/g, ' ').trim(), body: [], line: i + 1 };
      if (m[3]) { out.push({ head: cur.head, body: '', line: cur.line }); cur = null; continue; }
      depth = 1;
      continue;
    }
    const h = /<<-?([A-Za-z_][A-Za-z0-9_]*)\s*$/.exec(code);
    for (const ch of code) { if (ch === '{') depth++; if (ch === '}') depth--; }
    if (depth < 0) return `line ${i + 1}: unbalanced braces`;
    if (depth === 0) {
      out.push({ head: cur!.head, body: cur!.body.join('\n'), line: cur!.line });
      cur = null;
      continue;
    }
    cur!.body.push(line);
    if (h) heredoc = h[1];
  }
  if (depth !== 0 || heredoc) return 'unbalanced braces or an unterminated heredoc';
  return out;
};

// Import blocks for exactly the resources asked for, one resource block for each, and
// nothing else; names asked for are kept. Returns the final addresses, or why it's refused.
export const checkAdoptCode = (code: string, targets: AdoptTarget[]): { ok: true; resources: AdoptResource[] } | { ok: false; why: string } => {
  for (const [re, what] of FORBIDDEN) if (re.test(code)) return { ok: false, why: `contains ${what}` };
  const blocks = topBlocks(code);
  if (typeof blocks === 'string') return { ok: false, why: blocks };
  const imports: { to: string; id: string }[] = [];
  const resources: string[] = [];
  for (const b of blocks) {
    if (b.head === 'import') {
      const lines = b.body.split('\n').map(l => l.replace(/#.*$/, '').trim()).filter(Boolean);
      const to = lines.map(l => /^to\s*=\s*([a-z][a-z0-9_]*\.[A-Za-z_][A-Za-z0-9_-]*)$/.exec(l)?.[1]).find(Boolean);
      const idLine = lines.map(l => /^id\s*=\s*("(?:[^"\\]|\\.)*")$/.exec(l)?.[1]).find(Boolean);
      if (!to || !idLine || lines.length !== 2) return { ok: false, why: `import block at line ${b.line} must have only \`to\` and a quoted \`id\`` };
      imports.push({ to, id: JSON.parse(idLine) as string });
      continue;
    }
    const r = /^resource "([a-z][a-z0-9_]*)" "([A-Za-z_][A-Za-z0-9_-]*)"$/.exec(b.head);
    if (!r) return { ok: false, why: `\`${b.head}\` at line ${b.line}: only import and resource blocks are allowed` };
    if (/^\s*(?:count|for_each)\s*=/m.test(b.body)) return { ok: false, why: `${r[1]}.${r[2]} uses count or for_each` };
    resources.push(`${r[1]}.${r[2]}`);
  }
  const out: AdoptResource[] = [];
  for (const t of targets) {
    const hits = imports.filter(i => i.id === t.id && i.to.split('.')[0] === t.type);
    if (hits.length !== 1) return { ok: false, why: `needs exactly one import block for ${t.type} \`${t.id}\`` };
    if (t.name && hits[0].to !== `${t.type}.${t.name}`) return { ok: false, why: `${t.type} \`${t.id}\` must be imported to ${t.type}.${t.name}` };
    out.push({ address: hits[0].to, id: t.id, named: !!t.name });
  }
  if (imports.length !== targets.length) return { ok: false, why: 'imports something that was not asked for' };
  const to = new Set(out.map(r => r.address));
  if (to.size !== out.length) return { ok: false, why: 'two resources are imported to the same address' };
  if (resources.length !== to.size || resources.some(a => !to.has(a))) return { ok: false, why: 'needs one resource block for each import, and no others' };
  return { ok: true, resources: out };
};

// What the plan does with each resource: importing (with or without changes) or not.
export const importOutcome = (plan: Record<string, any>, resources: AdoptResource[]): { missing: string[]; changes: AdoptChange[]; others: number } => {
  const wanted = new Set(resources.map(r => r.address));
  const seen = new Set<string>();
  const changes: AdoptChange[] = [];
  let others = 0;
  for (const rc of plan.resource_changes ?? []) {
    if (rc.mode === 'data') continue;
    const actions: string[] = rc.change?.actions ?? [];
    if (!wanted.has(rc.address)) { if (actions.join(',') !== 'no-op' && actions.join(',') !== 'read') others++; continue; }
    if (!rc.change?.importing) continue;
    seen.add(rc.address);
    if (actions.join(',') === 'no-op') continue;
    const before = rc.change?.before ?? {};
    const after = rc.change?.after ?? {};
    const unknown = rc.change?.after_unknown ?? {};
    const attributes = Object.keys({ ...before, ...after }).filter(k => JSON.stringify(before?.[k]) !== JSON.stringify(after?.[k]) && !unknown?.[k] && k !== 'tags_all');
    changes.push({ address: rc.address, actions, attributes });
  }
  return { missing: [...wanted].filter(a => !seen.has(a)), changes, others };
};

// A file name in the project folder that isn't taken: imported-s3-buckets.tf
const fileName = (dir: string, wanted: string | undefined, root: string): string => {
  const base = (wanted ?? '').toLowerCase().replace(/\.tf$/, '').replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48) || 'imported';
  for (let i = 1; ; i++) {
    const name = `${base}${i > 1 ? `-${i}` : ''}.tf`;
    if (!existsSync(join(root, dir, name))) return name;
  }
};

const lastLines = (text: string, n = 30) => text.trim().split('\n').slice(-n).join('\n');
const blocking = (o: ReturnType<typeof importOutcome>) => o.missing.length > 0 || o.changes.some(c => c.actions.includes('delete'));

export interface AdoptRun {
  root: string;
  ctx: Omit<RunContext, 'planPath'>;   // project, tools, env, timeout (no hooks: nothing is applied)
  planDir: string;
  targets: AdoptTarget[];
  ai?: Ai | null;
  settings?: AiSettings | null;        // AI settings with `import` on, or null for Terraform's own output
  patterns?: SecretPattern[];
  rounds?: number;                     // AI attempts after the first (default 2)
}

export const adopt = async (r: AdoptRun): Promise<AdoptResult> => {
  const { project } = r.ctx;
  const dir = project.dir === '.' ? '' : project.dir;
  const abs = (name: string) => join(r.root, dir, name);
  const rel = (name: string) => (dir ? `${dir}/${name}` : name);
  const unsupported = generateSupport(r.ctx.tools);
  const fail = (error: string, extra: Partial<AdoptResult> = {}): AdoptResult => ({ ok: false, resources: [], changes: [], others: 0, notes: [], rounds: 0, error, ...extra });
  if (unsupported) return fail(unsupported);

  const existing = new Set(projectFiles(r.root, project.dir, 2_000_000).flatMap(f => [...f.text.matchAll(/^resource\s+"([^"]+)"\s+"([^"]+)"/gm)].map(m => `${m[1]}.${m[2]}`)));
  const clash = r.targets.find(t => t.name && existing.has(`${t.type}.${t.name}`));
  if (clash) return fail(`${clash.type}.${clash.name} is already in the code; to import into it, use \`teriac import\``);
  let resources = addressesFor(r.targets, existing);
  const plan = (name: string, extraArgs: string[] = []) => runPlan({ ...r.ctx, planPath: join(r.planDir, `${name}.tfplan`) }, { noLock: true, extraArgs });
  let best: { content: string; resources: AdoptResource[]; outcome: ReturnType<typeof importOutcome> } | null = null;
  try {
    // 1. Terraform reads the resources and writes their configuration.
    rmSync(abs(GENERATED), { force: true });
    writeFileSync(abs(IMPORTS), `# Written by teriac adopt; removed after the plan\n${importBlocks(resources)}`);
    const gen = await plan('adopt-generate', [`-generate-config-out=${GENERATED}`]);
    const generated = existsSync(abs(GENERATED)) ? readFileSync(abs(GENERATED), 'utf-8') : '';
    rmSync(abs(GENERATED), { force: true });
    rmSync(abs(IMPORTS), { force: true });
    if (!generated.trim()) return fail('Terraform could not read the resources: check the IDs and the project\'s credentials', { output: lastLines(gen.output) });
    const sensitive = gen.sensitive ?? (gen.plan ? sensitiveValues(gen.plan) : []);

    const ai = r.settings && r.ai ? r.ai : null;
    let content = `${importBlocks(resources)}\n${generated.replace(/^# __generated__ by (?:Terraform|OpenTofu)\n# Please review[^\n]*\n\n?/m, '')}`;
    const types = [...new Set(r.targets.map(t => t.type))];
    let name = fileName(dir, types.length > 1 ? 'imported' : `imported-${types[0].replace(/^[a-z0-9]+_/, '').replace(/_/g, '-')}${r.targets.length > 1 ? 's' : ''}`, r.root);
    let notes: string[] = [];
    let problems = gen.ok ? '' : lastLines(gen.output, 40);
    const rounds = ai ? 1 + (r.rounds ?? 2) : 1;
    let last: { output: string; outcome?: ReturnType<typeof importOutcome> } = { output: '' };
    let ran = 0;
    for (let round = 1; round <= rounds; round++) {
      // 2. Claude turns it into code a person would write (each round sees the last plan's problems).
      if (ai) {
        const draft = await ai.adoptCode({
          project: project.name, engine: `${r.ctx.tools.tool.provider} ${r.ctx.tools.tool.version}`, resources, generated, draft: round > 1 ? content : null,
          problems, files: projectFiles(r.root, project.dir), sensitive, patterns: r.patterns,
        }, r.settings!).catch(err => { log.warn('ai adopt failed', { project: project.name, err: (err as Error).message }); return null; });
        if (!draft) { if (round === 1) return fail('the AI request failed; try again, or turn off `import` in the AI features to use Terraform\'s own output'); break; }
        content = draft.content;
        if (round === 1) name = fileName(dir, draft.file, r.root);
        notes = draft.notes;
      }
      const checked = checkAdoptCode(content, r.targets);
      if (!checked.ok) {
        problems = `teriac refused the file: ${checked.why}. Fix that and keep everything else.`;
        last = { output: problems };
        log.warn('adopt code refused', { project: project.name, why: checked.why });
        continue;
      }
      resources = checked.resources;
      // 3. The plan must import each resource and not delete or replace any.
      writeFileSync(abs(name), content);
      ran++;
      const check = await plan('adopt-check');
      rmSync(abs(name), { force: true });
      if (!check.ok || !check.plan) {
        problems = `The plan failed:\n${lastLines(check.output, 40)}`;
        last = { output: check.output };
        continue;
      }
      const outcome = importOutcome(check.plan, resources);
      last = { output: check.output, outcome };
      if (!blocking(outcome) && (!best || outcome.changes.length < best.outcome.changes.length)) best = { content, resources, outcome };
      if (!blocking(outcome) && !outcome.changes.length) break;
      problems = [
        outcome.missing.length ? `Not imported: ${outcome.missing.join(', ')}.` : '',
        ...outcome.changes.map(c => `${c.address} would be ${c.actions.join('/')} after import${c.attributes.length ? `; the code differs from the real resource in: ${c.attributes.join(', ')}` : ''}. Make the code match the real values.`),
      ].filter(Boolean).join('\n');
    }
    // Changes in place are allowed (shown in the PR); the attempt with the fewest wins.
    if (!best) {
      const o = last.outcome;
      return fail(o?.missing.length ? `the plan does not import ${o.missing.join(', ')}` : o?.changes.length ? `the plan would replace or delete ${o.changes.map(c => c.address).join(', ')}` : problems.startsWith('teriac refused') ? problems.replace(/ Fix that.*$/, '') : 'the generated code does not plan cleanly', { output: lastLines(last.output), rounds: ran, model: ai ? label(r.settings!) : undefined });
    }
    // 4. Nothing secret goes into the PR.
    const final = best.content;
    const leaked = sensitive.filter(v => v.length >= 4 && final.includes(v));
    const scanned = scanSecrets(final, r.patterns);
    if (leaked.length || scanned.found.length) return fail(`the code would contain ${scanned.found.length ? `something that looks like a secret (${scanned.found.join(', ')})` : 'a value Terraform marks sensitive'}; adopt this resource by hand`);
    return {
      ok: true, file: { path: rel(name), content: final.replace(/\n*$/, '\n') }, resources: best.resources, changes: best.outcome.changes, others: best.outcome.others,
      notes, model: ai ? label(r.settings!) : undefined, rounds: ran,
    };
  } finally {
    for (const f of [GENERATED, IMPORTS]) rmSync(abs(f), { force: true });
  }
};

export const adoptBranch = (project: string, resources: AdoptResource[]) =>
  `teriac/adopt/${project.replace(/[^A-Za-z0-9._-]+/g, '_').toLowerCase()}-${resources.map(r => r.address).join('-').replace(/[^A-Za-z0-9_-]+/g, '-').toLowerCase().slice(0, 60)}`;

export const adoptBody = (project: string, base: string, result: AdoptResult, by: { user: string; from?: string }): string => {
  const lines = [
    `Brings ${result.resources.length === 1 ? 'a resource' : `${result.resources.length} resources`} made outside Terraform under \`${project}\`, as asked by ${by.user}${by.from ? ` in ${by.from}` : ''}.`,
    '',
    '| Address | ID |',
    '|---|---|',
    ...result.resources.map(r => `| \`${r.address}\` | \`${r.id}\` |`),
    '',
    result.changes.length
      ? `⚠️ **Applying also changes ${result.changes.length === 1 ? 'one resource' : `${result.changes.length} resources`}**, because the code differs from what is running: ${result.changes.map(c => `\`${c.address}\`${c.attributes.length ? ` (${c.attributes.map(a => `\`${a}\``).join(', ')})` : ''}`).join(', ')}. Edit the code to match if that isn't wanted.`
      : '✅ teriac planned this against the real resources: **applying imports them and changes nothing.**',
  ];
  if (result.others) lines.push('', `ℹ️ \`${project}\` has ${result.others} other pending change${result.others === 1 ? '' : 's'} on \`${base}\` that are not from this PR; they show in the plan too.`);
  if (result.model) {
    lines.push('', `🤖 **Written by AI** from Terraform's generated configuration <sub>${result.model} · check it yourself</sub>`);
    for (const n of result.notes) lines.push(`- ${n}`);
  } else {
    lines.push('', 'The configuration is what Terraform generated (`plan -generate-config-out`). Tidy it before merging: drop arguments that only repeat defaults.');
  }
  lines.push('', '**Next:** review the plan teriac posts here, then apply as usual. The `import` blocks can be deleted after the apply; leaving them does nothing.',
    '', `<sub>Opened by \`teriac adopt\`. Nothing has been imported yet.</sub>`);
  return lines.join('\n');
};
