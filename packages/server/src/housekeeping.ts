// Jobs that run every few minutes:
// - log_retention_days: a PR's run logs are cleared that many days after its last apply
//   (summaries, risk, people, times, metrics and the PR's comments stay);
// - remind_unmerged: a PR that was applied but is still open after `after_hours` gets one
//   reminder, as a comment to whoever applied and/or in chat.
import type { ServerConfig, RepoPolicy } from './config.ts';
import type { Store, Run } from './store.ts';
import type { Repo, VcsAdapter } from './vcs/types.ts';
import { matchGlob } from './glob.ts';
import { notifyText } from './notify.ts';
import { repoLinks, platformForHost } from './links.ts';
import { log } from './log.ts';

const TICK_MS = 10 * 60_000;
const HOUR = 3_600_000;

export interface HousekeepingDeps {
  config: ServerConfig;
  store: Store;
  adapterFor: (host: string) => VcsAdapter | undefined;
  env?: NodeJS.ProcessEnv;
  fetchImpl?: typeof fetch;
}

const policyOf = (config: ServerConfig, repoKey: string): RepoPolicy | undefined => config.repos.find(p => matchGlob(p.id, repoKey));

const repoOf = (repoKey: string, platform: Repo['platform']): Repo => {
  const [host, owner, ...rest] = repoKey.split('/');
  const name = rest.join('/');
  return { platform, host, owner, name, fullName: `${owner}/${name}`, cloneUrl: '' };
};

export class Housekeeper {
  private timer: NodeJS.Timeout | null = null;
  private d: HousekeepingDeps;
  constructor(d: HousekeepingDeps) { this.d = d; }

  start() {
    const tick = () => { void this.tick().catch(err => log.warn('housekeeping failed', { err: (err as Error).message })); };
    tick();
    this.timer = setInterval(tick, TICK_MS);
    this.timer.unref?.();
  }
  stop() { if (this.timer) clearInterval(this.timer); }

  async tick(now = new Date()) {
    return { expired: this.expireLogs(now), reminded: await this.remind(now) };
  }

  // Days to keep a repo's logs after its last apply: the repo's own setting, else the server's.
  private retention(repoKey: string): number | undefined {
    return policyOf(this.d.config, repoKey)?.log_retention_days ?? this.d.config.logRetentionDays;
  }

  expireLogs(now: Date): number {
    const all = [this.d.config.logRetentionDays, ...this.d.config.repos.map(r => r.log_retention_days)].filter((d): d is number => typeof d === 'number');
    if (!all.length) return 0;
    let expired = 0;
    const earliest = new Date(now.getTime() - Math.min(...all) * 24 * HOUR).toISOString();
    for (const c of this.d.store.prsWithLogsAppliedBefore(earliest)) {
      const days = this.retention(c.repo);
      if (days === undefined || Date.parse(c.appliedAt) > now.getTime() - days * 24 * HOUR) continue;
      const n = this.d.store.expireOutputs(c.repo, c.pr, now.toISOString());
      if (n) log.info('logs expired', { repo: c.repo, pr: c.pr, runs: n, days });
      expired += n;
    }
    return expired;
  }

  async remind(now: Date): Promise<number> {
    const hours = this.d.config.repos.map(r => r.remind_unmerged?.after_hours).filter((h): h is number => typeof h === 'number');
    if (!hours.length) return 0;
    let sent = 0;
    for (const run of this.d.store.appliesStillOpen(new Date(now.getTime() - Math.min(...hours) * HOUR).toISOString())) {
      const r = policyOf(this.d.config, run.repo)?.remind_unmerged;
      if (!r || Date.parse(run.finishedAt!) > now.getTime() - r.after_hours * HOUR) continue;
      const key = `reminded:${run.repo}#${run.pr}:${run.id}`;
      if (this.d.store.getSetting(key)) continue;
      this.d.store.setSetting(key, now.toISOString());
      await this.send(run, r, now);
      sent++;
    }
    return sent;
  }

  // One short message: who applied what, how long ago, and what to do.
  private async send(run: Run, r: NonNullable<RepoPolicy['remind_unmerged']>, now: Date) {
    const host = run.repo.split('/')[0];
    const adapter = this.d.adapterFor(host);
    const platform = adapter?.platform ?? platformForHost(host, {});
    const repo = repoOf(run.repo, platform);
    const ago = Math.floor((now.getTime() - Date.parse(run.finishedAt!)) / HOUR);
    const prUrl = repoLinks(run.repo, platform).pr(run.pr);
    if (r.comment !== false && adapter) {
      await adapter.comment(repo, run.pr, `⏰ @${run.user} applied \`${run.project}\` ${ago} hours ago, but this pull request isn't merged yet. `
        + 'Until it is, the base branch doesn\'t match what\'s deployed. Merge it, or revert the change and apply again.')
        .catch(err => log.warn('reminder comment failed', { repo: run.repo, pr: run.pr, err: (err as Error).message }));
    }
    if (r.notify?.length) {
      await notifyText(r.notify, this.d.config.channels, {
        title: `⏰ Applied but not merged: ${repo.fullName} #${run.pr}`,
        lines: [`\`${run.project}\` applied by ${run.user} ${ago} hours ago · [open the PR](${prUrl})`],
        event: 'teriac.unmerged', url: prUrl,
        data: { repo: run.repo, pr: run.pr, project: run.project, user: run.user, appliedAt: run.finishedAt, hours: ago },
      }, { people: this.d.config.people, env: this.d.env ?? process.env, fetchImpl: this.d.fetchImpl })
        .catch(err => log.warn('reminder notice failed', { err: (err as Error).message }));
    }
  }
}
