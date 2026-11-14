// Live output of running plans and applies, for the dashboard. Output is split into whole
// lines, and each line is cleaned before it is kept or sent: a secret split across two chunks
// of output is still caught. Kept in memory only: a run's lines are dropped a while after it
// ends, and at once when its PR is unlocked, closed or merged.
import { redact } from './log.ts';
import { scanSecrets } from './secrets.ts';
import { hideValues } from './sensitive.ts';
import type { SecretPattern } from './safety-config.ts';

const MAX_LINES = 20_000;      // older lines are dropped (the saved log keeps the end)
const MAX_LINE = 8_000;        // a single huge line is cut
const KEEP_AFTER_END = 10 * 60_000;

export interface ScrubOptions { mode: 'off' | 'redact' | 'fail'; patterns: SecretPattern[] }

// Cleans one line at a time. Private keys span lines, so the scrubber remembers when it is
// inside one. In "fail" mode, the first line that looks like a secret stops the stream.
export class Scrubber {
  private inKey = false;
  private stopped = false;
  private sensitive: string[] = [];
  private opts: ScrubOptions;
  found = new Set<string>();
  constructor(opts: ScrubOptions) { this.opts = opts; }

  addSensitive(values: string[]) {
    this.sensitive = [...new Set([...this.sensitive, ...values])].sort((a, b) => b.length - a.length);
  }

  // The line to show, or null to drop it.
  line(raw: string): string | null {
    if (this.stopped) return null;
    let line = raw.length > MAX_LINE ? `${raw.slice(0, MAX_LINE)} …(line cut)` : raw;
    line = hideValues(redact(line), this.sensitive);
    // Private key blocks: hide from BEGIN to END, whatever is between.
    if (this.inKey) {
      if (/-----END [A-Z0-9 ]*PRIVATE KEY-----/.test(line)) this.inKey = false;
      return null;
    }
    if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(line)) {
      this.found.add('private-key');
      if (!/-----END [A-Z0-9 ]*PRIVATE KEY-----/.test(line)) this.inKey = true;
      return this.fail('private-key') ?? line.replace(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*$/, '‹redacted: private-key›');
    }
    // A bare line of a key's body (64 base64 characters), seen without its BEGIN line.
    if (/^\s*[A-Za-z0-9+/]{64}\s*$/.test(line)) return '‹redacted: private-key›';
    if (this.opts.mode === 'off') return line;
    const s = scanSecrets(line, this.opts.patterns);
    if (!s.found.length) return line;
    for (const f of s.found) this.found.add(f);
    return this.fail(s.found.join(', ')) ?? s.text;
  }

  private fail(kinds: string): string | null {
    if (this.opts.mode !== 'fail') return null;
    this.stopped = true;
    return `[teriac] the rest of this output is withheld: it contains something that looks like a secret (${kinds}).`;
  }
}

type Listener = (lines: string[], done: boolean) => void;

interface Live {
  lines: string[];
  dropped: number;
  partial: string;
  done: boolean;
  listeners: Set<Listener>;
  scrub: Scrubber;
  key: string;              // "repo#pr|project", for cleanup
  timer?: NodeJS.Timeout;
}

export interface LiveWriter {
  write(chunk: string): void;   // raw output, any chunking
  sensitive(values: string[]): void;
  end(): void;
  found(): string[];
}

export class LiveLogs {
  private runs = new Map<number, Live>();

  start(runId: number, key: string, opts: ScrubOptions): LiveWriter {
    this.drop(runId);
    const live: Live = { lines: [], dropped: 0, partial: '', done: false, listeners: new Set(), scrub: new Scrubber(opts), key };
    this.runs.set(runId, live);
    const push = (raw: string[]) => {
      const out: string[] = [];
      for (const r of raw) {
        const l = live.scrub.line(r.replace(/\r$/, '').replace(/\x1b\[[0-9;]*m/g, ''));
        if (l !== null) out.push(l);
      }
      if (!out.length) return;
      live.lines.push(...out);
      if (live.lines.length > MAX_LINES) {
        const extra = live.lines.length - MAX_LINES;
        live.lines.splice(0, extra);
        live.dropped += extra;
      }
      for (const fn of live.listeners) fn(out, false);
    };
    return {
      write: (chunk) => {
        if (live.done) return;
        const parts = (live.partial + chunk).split('\n');
        live.partial = parts.pop() ?? '';
        // A very long line without a newline is flushed in pieces, cleaned like any other.
        if (live.partial.length > MAX_LINE) { parts.push(live.partial); live.partial = ''; }
        push(parts);
      },
      sensitive: (values) => live.scrub.addSensitive(values),
      end: () => {
        if (live.done) return;
        if (live.partial) push([live.partial]);
        live.partial = '';
        live.done = true;
        for (const fn of live.listeners) fn([], true);
        live.listeners.clear();
        live.timer = setTimeout(() => this.runs.delete(runId), KEEP_AFTER_END);
        live.timer.unref?.();
      },
      found: () => [...live.scrub.found],
    };
  }

  // The lines so far, then every new batch; returns null when there is no live output.
  subscribe(runId: number, fn: Listener): { backlog: string[]; dropped: number; done: boolean; stop: () => void } | null {
    const live = this.runs.get(runId);
    if (!live) return null;
    if (!live.done) live.listeners.add(fn);
    return { backlog: [...live.lines], dropped: live.dropped, done: live.done, stop: () => live.listeners.delete(fn) };
  }

  has(runId: number) { return this.runs.has(runId); }

  drop(runId: number) {
    const live = this.runs.get(runId);
    if (!live) return;
    clearTimeout(live.timer);
    for (const fn of live.listeners) fn([], true);
    this.runs.delete(runId);
  }

  // A PR's live output (or one project's): on unlock, close or merge.
  dropPr(pr: string, project?: string) {
    for (const [id, live] of this.runs) {
      if (live.key === `${pr}|${project}` || (!project && live.key.startsWith(`${pr}|`))) this.drop(id);
    }
  }
}
