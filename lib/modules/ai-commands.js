// `teriac explain` and `teriac fix`: run a plan with the active binary, then ask Claude.
const fs = require('fs');
const os = require('os');
const path = require('path');
const readline = require('readline');
const { spawn } = require('child_process');
const { normalizeProvider, getCliName, getBinTarget } = require('../utils/paths');
const { P_END, P_OK, P_ERROR, P_WARN, P_INFO } = require('../utils/colors');
const ai = require('./ai');

const SEV = { critical: P_ERROR, high: P_ERROR, medium: P_WARN, low: P_INFO };
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

// Runs the binary, showing its output as it comes and keeping a copy.
const run = (binary, args, opts = {}) => new Promise((resolve) => {
  const child = spawn(binary, args, { cwd: process.cwd(), stdio: ['inherit', 'pipe', 'pipe'] });
  let output = '';
  const keep = (stream, to) => stream.on('data', (d) => { output += d; if (!opts.quiet) to.write(d); });
  keep(child.stdout, process.stdout);
  keep(child.stderr, process.stderr);
  child.on('error', (err) => resolve({ code: 127, output: `${output}\n${err.message}`, error: err }));
  child.on('close', (code) => resolve({ code, output }));
});

const binaryFor = (providerArg) => {
  const provider = normalizeProvider(providerArg);
  const cli = getCliName(provider);
  const target = getBinTarget(provider);
  return { cli, binary: fs.existsSync(target) ? target : cli };
};

const confirm = (question) => new Promise((resolve) => {
  if (!process.stdin.isTTY) return resolve(false);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.question(question, (a) => { rl.close(); resolve(/^y(es)?$/i.test(a.trim())); });
});

const header = (title, model) => console.log(`\n${P_OK}🤖 ${title}${P_END} ${DIM}${model} · advisory, check it yourself${P_END}\n`);

const showReview = (r, model) => {
  header('AI review', model);
  console.log(r.summary, '\n');
  if (!r.findings.length) return console.log(`${P_OK}Nothing else stood out.${P_END}`);
  for (const f of r.findings) {
    console.log(`${SEV[f.severity] || ''}● ${f.severity.toUpperCase()}${P_END} ${BOLD}${f.title}${P_END} ${DIM}${f.address}${P_END}`);
    console.log(`  ${f.why}\n`);
  }
};

const showFixes = (r, model) => {
  header('AI: why it failed', model);
  console.log(r.cause, '\n');
  for (const f of r.fixes) {
    console.log(`${BOLD}Suggested fix${P_END} ${f.path} line${f.start_line === f.end_line ? ` ${f.start_line}` : `s ${f.start_line}–${f.end_line}`}: ${f.why}`);
    console.log(f.replacement.replace(/\n+$/, '').split('\n').map(l => `${P_OK}+ ${l}${P_END}`).join('\n'), '\n');
  }
};

const failHelp = async (c, output, opts) => {
  console.log(`\n${P_INFO}Asking Claude why it failed…${P_END}`);
  const r = await ai.diagnose(c, output, process.cwd());
  showFixes(r, ai.label(c.model));
  if (!r.fixes.length) return;
  const write = opts.write || await confirm(`Write ${r.fixes.length === 1 ? 'this fix' : `these ${r.fixes.length} fixes`} into the files? [y/N] `);
  if (!write) return console.log(`${DIM}Nothing changed. Run with --write to apply the fixes.${P_END}`);
  const done = ai.applyFixes(process.cwd(), r.fixes);
  console.log(`${P_OK}Wrote ${done.length} fix${done.length === 1 ? '' : 'es'}.${P_END} Review with \`git diff\`, then plan again.`);
};

// explain: plan, then a review (or, when the plan fails, why and how to fix it).
exports.explain = async ({ provider, extraArgs = [], write = false }) => {
  let c;
  try { c = ai.client(); } catch (err) { console.log(`${P_ERROR}${err.message}${P_END}`); process.exit(1); }
  const { cli, binary } = binaryFor(provider);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'teriac-explain-'));
  const planFile = path.join(dir, 'plan.tfplan');
  try {
    console.log(`${P_OK}Running: ${cli} plan -out=<temp> ${extraArgs.join(' ')}${P_END}\n`);
    const plan = await run(binary, ['plan', '-input=false', `-out=${planFile}`, ...extraArgs]);
    if (plan.error && plan.error.code === 'ENOENT') { console.log(`${P_ERROR}${cli} not found. Run: teriac install latest${P_END}`); process.exit(1); }
    if (plan.code !== 0) { await failHelp(c, plan.output, { write }); process.exit(plan.code || 1); }
    const shown = await run(binary, ['show', '-json', planFile], { quiet: true });
    if (shown.code !== 0) { console.log(`${P_ERROR}Could not read the plan: ${shown.output.trim().slice(0, 400)}${P_END}`); process.exit(1); }
    const json = JSON.parse(shown.output);
    if (!(json.resource_changes || []).some(rc => !['no-op', 'read'].includes((rc.change.actions || []).join(',')))) {
      return console.log(`\n${P_OK}No changes to review.${P_END}`);
    }
    console.log(`\n${P_INFO}Asking Claude to review the plan…${P_END}`);
    showReview(await ai.review(c, json, path.basename(process.cwd())), ai.label(c.model));
  } catch (err) {
    console.log(`${P_ERROR}AI review failed: ${err.message}${P_END}`);
    process.exit(1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
};

// fix: run validate and plan (or read a saved log), and on failure diagnose it.
exports.fix = async ({ provider, extraArgs = [], write = false, log }) => {
  let c;
  try { c = ai.client(); } catch (err) { console.log(`${P_ERROR}${err.message}${P_END}`); process.exit(1); }
  try {
    if (log) return await failHelp(c, fs.readFileSync(log, 'utf8'), { write });
    const { cli, binary } = binaryFor(provider);
    for (const args of [['validate', '-no-color'], ['plan', '-input=false', '-lock=false', ...extraArgs]]) {
      console.log(`${P_OK}Running: ${cli} ${args.join(' ')}${P_END}\n`);
      const r = await run(binary, args);
      if (r.error && r.error.code === 'ENOENT') { console.log(`${P_ERROR}${cli} not found. Run: teriac install latest${P_END}`); process.exit(1); }
      if (r.code !== 0) return await failHelp(c, r.output, { write });
    }
    console.log(`\n${P_OK}validate and plan both passed: nothing to fix.${P_END}`);
  } catch (err) {
    console.log(`${P_ERROR}AI help failed: ${err.message}${P_END}`);
    process.exit(1);
  }
};
