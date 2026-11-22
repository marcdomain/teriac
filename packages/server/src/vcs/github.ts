// GitHub (github.com and GitHub Enterprise Server) via a GitHub App.
// No SDK: App JWTs are signed with node:crypto and the REST API is plain fetch.
import { createHash, createHmac, createSign, timingSafeEqual } from 'node:crypto';
import type {
  CheckRun, CloneAuth, Comparison, Permission, PullRequest, PullRequestState, Reaction, Repo, Review, VcsAdapter, VcsEvent, Suggestion,
} from './types.ts';
import type { GitHubConfig } from '../config.ts';
import { addSecret, log } from '../log.ts';

type Headers = Record<string, string | string[] | undefined>;
const header = (h: Headers, name: string) => {
  const v = h[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
};

const b64url = (data: string | Buffer) => Buffer.from(data).toString('base64url');

export const appJwt = (appId: string, privateKey: string, now = Math.floor(Date.now() / 1000)): string => {
  const head = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  // iat is backdated 60s for clock drift; GitHub allows at most 10 minutes.
  const body = b64url(JSON.stringify({ iat: now - 60, exp: now + 540, iss: appId }));
  const signer = createSign('RSA-SHA256');
  signer.update(`${head}.${body}`);
  return `${head}.${body}.${b64url(signer.sign(privateKey))}`;
};

export const verifySignature = (secret: string, rawBody: Buffer, signature: string | undefined): boolean => {
  if (!signature?.startsWith('sha256=')) return false;
  const expected = Buffer.from(`sha256=${createHmac('sha256', secret).update(rawBody).digest('hex')}`);
  const got = Buffer.from(signature);
  return expected.length === got.length && timingSafeEqual(expected, got);
};

class TtlCache<V> {
  private map = new Map<string, { value: V; until: number }>();
  private ttlMs: number;
  constructor(ttlMs: number) { this.ttlMs = ttlMs; }
  async get(key: string, load: () => Promise<V>): Promise<V> {
    const hit = this.map.get(key);
    if (hit && hit.until > Date.now()) return hit.value;
    const value = await load();
    this.map.set(key, { value, until: Date.now() + this.ttlMs });
    return value;
  }
}

export class GitHubAdapter implements VcsAdapter {
  readonly platform = 'github' as const;
  readonly commentLimit = 65000;
  readonly supportsChecks = true;

  private tokens = new Map<string, { token: string; expires: number }>();
  // RBAC lookups are cached briefly (plan: 5 minutes).
  private permCache = new TtlCache<Permission>(5 * 60_000);
  private teamCache = new TtlCache<boolean>(5 * 60_000);
  private ownersCache = new TtlCache<string | null>(60_000);

  private cfg: GitHubConfig;
  private fetchImpl: typeof fetch;

  constructor(cfg: GitHubConfig, fetchImpl: typeof fetch = fetch) {
    this.cfg = cfg;
    this.fetchImpl = fetchImpl;
    addSecret(cfg.webhookSecret);
    addSecret(cfg.clientSecret);
    this.secrets();
  }

  // ---- auth ----

  // The keys and webhook secrets in force (rotation: current first, then "next").
  private secrets(): { keys: string[]; webhookSecrets: string[] } {
    const s = this.cfg.secrets?.() ?? { keys: [this.cfg.privateKey], webhookSecrets: [this.cfg.webhookSecret] };
    for (const v of [...s.keys, ...s.webhookSecrets]) addSecret(v);
    return s.keys.length ? s : { ...s, keys: [this.cfg.privateKey] };
  }

  private goodKey: string | null = null; // fingerprint of the key GitHub last accepted

  // The key in use: the one GitHub last accepted, else the current one. Its fingerprint
  // (not the key) is what key_rotation remembers, to know how old it is.
  keyInUse(): { fingerprint: string; next: boolean } {
    const fp = (k: string) => createHash('sha256').update(k).digest('hex').slice(0, 12);
    const keys = this.secrets().keys;
    const used = keys.find(k => fp(k) === this.goodKey) ?? keys[0];
    return { fingerprint: fp(used), next: used !== keys[0] };
  }

  // After a restart: ask GitHub to send again the webhooks that failed since `since` (teriac
  // was down). A delivery counts as done once any attempt for it succeeded. Returns how many
  // were redelivered, and how many failed earlier than `since` (too old to replay safely).
  async redeliverMissed(since: Date, now = new Date()): Promise<{ redelivered: number; tooOld: number }> {
    const latest = new Map<string, { id: number; at: number; ok: boolean }>();
    let tooOld = 0;
    let url: string | null = `${this.cfg.apiUrl}/app/hook/deliveries?per_page=100`;
    for (let page = 0; url && page < 10; page++) {
      const res: Response = await this.appFetch(url);
      if (!res.ok) throw new Error(`GitHub: listing webhook deliveries failed (HTTP ${res.status})`);
      const list = await res.json() as { id: number; guid: string; delivered_at: string; status_code: number }[];
      let older = false;
      for (const d of list) {
        const at = Date.parse(d.delivered_at);
        if (at < since.getTime() - 3 * 24 * 3_600_000) { older = true; continue; }
        const ok = d.status_code >= 200 && d.status_code < 300;
        const prev = latest.get(d.guid);
        latest.set(d.guid, { id: prev && prev.at > at ? prev.id : d.id, at: Math.max(prev?.at ?? 0, at), ok: ok || !!prev?.ok });
        if (at < since.getTime()) older = true;
      }
      url = older ? null : (/<([^>]+)>;\s*rel="next"/.exec(res.headers.get('link') ?? '')?.[1] ?? null);
    }
    let redelivered = 0;
    for (const d of latest.values()) {
      if (d.ok) continue;
      if (d.at < since.getTime()) { tooOld++; continue; }
      if (d.at > now.getTime()) continue;
      const res = await this.appFetch(`${this.cfg.apiUrl}/app/hook/deliveries/${d.id}/attempts`, { method: 'POST' }).catch(() => null);
      if (res && (res.status === 202 || res.ok)) redelivered++;
    }
    return { redelivered, tooOld };
  }

  // Where the App's keys are managed (its settings page).
  async appSettingsUrl(): Promise<string | null> {
    const res = await this.appFetch(`${this.cfg.apiUrl}/app`).catch(() => null);
    if (!res?.ok) return null;
    const app = await res.json() as { slug?: string; owner?: { login?: string; type?: string } };
    if (!app.slug) return null;
    const web = this.cfg.host === 'github.com' ? 'https://github.com' : `https://${this.cfg.host}`;
    return app.owner?.type === 'Organization'
      ? `${web}/organizations/${app.owner.login}/settings/apps/${app.slug}`
      : `${web}/settings/apps/${app.slug}`;
  }

  // A request signed as the App. Tries the key that worked last, then the others: during a
  // rotation GitHub accepts both, and once the old key is deleted the next one takes over
  // with no restart. Running jobs keep their installation tokens either way.
  private async appFetch(url: string, init: RequestInit = {}): Promise<Response> {
    const fp = (k: string) => createHash('sha256').update(k).digest('hex').slice(0, 12);
    const keys = this.secrets().keys;
    const ordered = [...keys].sort((a, b) => Number(fp(b) === this.goodKey) - Number(fp(a) === this.goodKey));
    let res: Response | null = null;
    for (const [i, key] of ordered.entries()) {
      res = await this.fetchImpl(url, {
        ...init,
        headers: { ...(init.headers as Record<string, string> ?? {}), Authorization: `Bearer ${appJwt(this.cfg.clientId || this.cfg.appId, key)}`, Accept: 'application/vnd.github+json', 'User-Agent': 'teriac-server' },
      });
      if (res.status !== 401) {
        if (this.goodKey !== fp(key)) {
          if (this.goodKey !== null || key !== keys[0]) {
            log.warn(key === keys[0] ? 'GitHub accepted the current private key again' : 'GitHub refused the current private key; signed in with private-key-next. Make it the current key and remove the old one', { key: fp(key) });
          }
          this.goodKey = fp(key);
        }
        return res;
      }
      if (i < ordered.length - 1) log.warn('GitHub refused a private key; trying the next one', { key: fp(key) });
    }
    return res!;
  }

  // Which installation of the App covers a repo. Webhooks carry it; for work that
  // starts elsewhere (the dashboard, schedules) it's looked up once and remembered.
  private installationIds = new Map<string, number>();
  private async installationFor(repo: Repo): Promise<number> {
    if (repo.installationId) {
      this.installationIds.set(repo.fullName.toLowerCase(), repo.installationId);
      return repo.installationId;
    }
    const known = this.installationIds.get(repo.fullName.toLowerCase());
    if (known) return known;
    const res = await this.appFetch(`${this.cfg.apiUrl}/repos/${repo.fullName}/installation`);
    if (!res.ok) throw new Error(`no GitHub App installation for ${repo.fullName} (HTTP ${res.status}); is the App installed on it?`);
    const id = (await res.json() as { id: number }).id;
    this.installationIds.set(repo.fullName.toLowerCase(), id);
    return id;
  }

  // A token for public GitHub downloads (OpenTofu, Terragrunt): any installation of
  // the App will do. Only for github.com; a GitHub Enterprise App can't sign in there.
  async downloadToken(): Promise<string | null> {
    if (this.cfg.host !== 'github.com') return null;
    const res = await this.appFetch(`${this.cfg.apiUrl}/app/installations?per_page=1`);
    if (!res.ok) return null;
    const [first] = await res.json() as { id: number; account?: { login?: string } }[];
    if (!first) return null;
    // Public downloads need no repository access: the token can only read metadata.
    return this.installationToken({ platform: 'github', host: this.cfg.host, owner: first.account?.login ?? '', name: '', fullName: `installation-${first.id}`, cloneUrl: '', installationId: first.id }, { metadata: 'read' });
  }

  // An installation token: with every permission the App has, or only `permissions`
  // (GitHub narrows the token to those). Cached per installation and scope until 5
  // minutes before it expires; tokens last an hour.
  private async installationToken(repo: Repo, permissions?: Record<string, 'read' | 'write'>): Promise<string> {
    const id = await this.installationFor(repo);
    const key = `${id}:${permissions ? JSON.stringify(permissions) : 'all'}`;
    const cached = this.tokens.get(key);
    if (cached && cached.expires - 5 * 60_000 > Date.now()) return cached.token;
    const res = await this.appFetch(`${this.cfg.apiUrl}/app/installations/${id}/access_tokens`, {
      method: 'POST',
      headers: permissions ? { 'Content-Type': 'application/json' } : {},
      ...(permissions ? { body: JSON.stringify({ permissions }) } : {}),
    });
    if (!res.ok) throw new Error(`GitHub App token request failed: HTTP ${res.status}`);
    const data = await res.json() as { token: string; expires_at: string };
    addSecret(data.token);
    this.tokens.set(key, { token: data.token, expires: Date.parse(data.expires_at) });
    return data.token;
  }

  // Git credentials for Terraform's module downloads (git::https://<host>/...): a token
  // that can only read code, from the installation that owns the repo. Terraform runs
  // the PR's code, so it never gets the App's full token.
  async moduleAuth(repo: Repo): Promise<CloneAuth | null> {
    const token = await this.installationToken(repo, { contents: 'read', metadata: 'read' });
    const basic = Buffer.from(`x-access-token:${token}`).toString('base64');
    addSecret(basic);
    return { url: `https://${this.cfg.host}/`, extraHeader: `Authorization: Basic ${basic}` };
  }

  private async api<T = any>(repo: Repo, method: string, path: string, body?: unknown, okStatuses: number[] = [], retried = false): Promise<{ status: number; data: T; next: string | null }> {
    const token = await this.installationToken(repo);
    const url = path.startsWith('http') ? path : `${this.cfg.apiUrl}${path}`;
    const res = await this.fetchImpl(url, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'teriac-server',
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    // A token GitHub no longer accepts (revoked, or its key rotated away): get a new one
    // and try once more, so a running job carries on.
    if (res.status === 401 && !retried) {
      for (const k of this.tokens.keys()) if (this.tokens.get(k)!.token === token) this.tokens.delete(k);
      return this.api<T>(repo, method, path, body, okStatuses, true);
    }
    if (!res.ok && !okStatuses.includes(res.status)) {
      throw new Error(`GitHub ${method} ${path}: HTTP ${res.status} ${text.slice(0, 200)}`);
    }
    const next = /<([^>]+)>;\s*rel="next"/.exec(res.headers.get('link') ?? '')?.[1] ?? null;
    return { status: res.status, data: (text ? JSON.parse(text) : null) as T, next };
  }

  private async paginate<T>(repo: Repo, path: string, max = 10000): Promise<T[]> {
    const out: T[] = [];
    let next: string | null = `${path}${path.includes('?') ? '&' : '?'}per_page=100`;
    while (next && out.length < max) {
      const r: { data: T[]; next: string | null } = await this.api<T[]>(repo, 'GET', next);
      out.push(...r.data);
      next = r.next;
    }
    return out;
  }

  // ---- webhooks ----

  verify(headers: Headers, rawBody: Buffer): boolean {
    // Either webhook secret, while it's being rotated.
    const sig = header(headers, 'x-hub-signature-256');
    return this.secrets().webhookSecrets.some(s => verifySignature(s, rawBody, sig));
  }

  private repoFrom(payload: any): Repo {
    return this.toRepo(payload.repository, payload.installation?.id);
  }

  private toRepo(r: any, installationId?: number): Repo {
    return {
      platform: 'github',
      host: this.cfg.host,
      owner: r.owner.login,
      name: r.name,
      fullName: r.full_name,
      cloneUrl: r.clone_url,
      installationId,
      defaultBranch: r.default_branch,
    };
  }

  async listRepos(): Promise<Repo[]> {
    const res = await this.appFetch(`${this.cfg.apiUrl}/app/installations?per_page=100`);
    if (!res.ok) throw new Error(`GitHub: listing installations failed (HTTP ${res.status})`);
    const installations = await res.json() as { id: number }[];
    const repos: Repo[] = [];
    for (const inst of installations) {
      const probe = { installationId: inst.id } as Repo;
      let next: string | null = '/installation/repositories?per_page=100';
      while (next) {
        const page: { data: { repositories: any[] }; next: string | null } = await this.api(probe, 'GET', next);
        repos.push(...page.data.repositories.map(r => this.toRepo(r, inst.id)));
        next = page.next;
      }
    }
    return repos;
  }

  private prFrom(pr: any): PullRequest {
    return {
      number: pr.number,
      title: pr.title,
      url: pr.html_url,
      author: pr.user.login,
      headSha: pr.head.sha,
      headRef: pr.head.ref,
      baseRef: pr.base.ref,
      draft: !!pr.draft,
      fromFork: pr.head.repo?.full_name !== pr.base.repo?.full_name,
    };
  }

  parse(headers: Headers, body: any): VcsEvent {
    const event = header(headers, 'x-github-event');
    if (!body?.repository) return { kind: 'ignored', reason: `${event} without a repository` };
    const repo = this.repoFrom(body);

    if (event === 'pull_request') {
      const pr = this.prFrom(body.pull_request);
      switch (body.action) {
        case 'opened': case 'reopened': case 'ready_for_review': return { kind: 'pr_opened', repo, pr };
        case 'synchronize': return { kind: 'pr_updated', repo, pr };
        case 'closed': return { kind: 'pr_closed', repo, pr, merged: !!body.pull_request.merged };
        default: return { kind: 'ignored', reason: `pull_request.${body.action}` };
      }
    }
    if (event === 'issue_comment') {
      if (!body.issue?.pull_request) return { kind: 'ignored', reason: 'not a PR comment' };
      // A bot's comment (maybe ours) changed by someone other than that bot.
      if ((body.action === 'edited' || body.action === 'deleted') && body.comment?.user?.type === 'Bot') {
        if (body.sender?.login === body.comment.user.login) return { kind: 'ignored', reason: 'bot edited its own comment' };
        return {
          kind: 'bot_comment_changed', repo, prNumber: body.issue.number, commentId: String(body.comment.id),
          by: body.sender?.login ?? 'unknown', change: body.action, body: body.comment.body ?? '',
        };
      }
      if (body.action !== 'created') return { kind: 'ignored', reason: 'not a new PR comment' };
      if (body.comment.user?.type === 'Bot') return { kind: 'ignored', reason: 'bot comment' };
      return {
        kind: 'comment', repo, prNumber: body.issue.number, commentId: String(body.comment.id),
        author: body.comment.user.login, body: body.comment.body ?? '',
      };
    }
    if (event === 'check_run' && body.action === 'requested_action' && body.requested_action?.identifier === 'apply') {
      const prNumber = body.check_run.pull_requests?.[0]?.number;
      if (!prNumber) return { kind: 'ignored', reason: 'apply button without a PR' };
      return { kind: 'apply_button', repo, prNumber, project: body.check_run.external_id, user: body.sender.login };
    }
    return { kind: 'ignored', reason: `${event}${body.action ? `.${body.action}` : ''}` };
  }

  // ---- PR data ----

  async getPullRequest(repo: Repo, number: number): Promise<PullRequestState> {
    const { data } = await this.api(repo, 'GET', `/repos/${repo.fullName}/pulls/${number}`);
    return {
      ...this.prFrom(data),
      open: data.state === 'open',
      mergeable: data.mergeable ?? null,
      behindBase: data.mergeable_state === 'behind',
    };
  }

  async changedFiles(repo: Repo, number: number): Promise<string[]> {
    const files = await this.paginate<any>(repo, `/repos/${repo.fullName}/pulls/${number}/files`);
    // A rename touches both the old and the new location.
    return files.flatMap(f => (f.previous_filename ? [f.filename, f.previous_filename] : [f.filename]));
  }

  async cloneAuth(repo: Repo): Promise<CloneAuth> {
    const token = await this.installationToken(repo);
    const basic = Buffer.from(`x-access-token:${token}`).toString('base64');
    addSecret(basic);
    return { url: repo.cloneUrl, extraHeader: `Authorization: Basic ${basic}` };
  }

  // ---- writing to the PR ----

  async upsertComment(repo: Repo, number: number, marker: string, body: string, knownId?: string | null): Promise<{ id: string; url: string } | null> {
    // Fast path: edit the comment we made last time, without listing the PR's comments.
    if (knownId) {
      const { status, data } = await this.api(repo, 'PATCH', `/repos/${repo.fullName}/issues/comments/${encodeURIComponent(knownId)}`, { body }, [404]);
      if (status === 200) return { id: String(data.id), url: data.html_url };
    }
    const comments = await this.paginate<any>(repo, `/repos/${repo.fullName}/issues/${number}/comments`);
    const has = (c: any) => c.body?.includes(marker);
    const mine = comments.find(c => c.performed_via_github_app?.id === Number(this.cfg.appId) && has(c))
      ?? comments.find(c => c.user?.type === 'Bot' && has(c));
    const { data } = mine
      ? await this.api(repo, 'PATCH', `/repos/${repo.fullName}/issues/comments/${mine.id}`, { body })
      : await this.api(repo, 'POST', `/repos/${repo.fullName}/issues/${number}/comments`, { body });
    return data?.id != null ? { id: String(data.id), url: data.html_url } : null;
  }

  async comment(repo: Repo, number: number, body: string): Promise<string | null> {
    const { data } = await this.api(repo, 'POST', `/repos/${repo.fullName}/issues/${number}/comments`, { body });
    return data?.id != null ? String(data.id) : null;
  }

  async suggestChanges(repo: Repo, number: number, sha: string, body: string, suggestions: Suggestion[]): Promise<boolean> {
    // A suggestion block can't hold a longer fence than its own: use one longer than any inside.
    const fence = (text: string) => '`'.repeat(Math.max(3, ...[...text.matchAll(/`{3,}/g)].map(m => m[0].length + 1)));
    const comments = suggestions.map(s => ({
      path: s.path, line: s.endLine, side: 'RIGHT',
      ...(s.startLine < s.endLine ? { start_line: s.startLine, start_side: 'RIGHT' } : {}),
      body: `${s.note}\n\n${fence(s.replacement)}suggestion\n${s.replacement}\n${fence(s.replacement)}`,
    }));
    // 422: a line isn't part of the PR's diff; the caller shows the fix in its comment instead.
    const { status } = await this.api(repo, 'POST', `/repos/${repo.fullName}/pulls/${number}/reviews`, { commit_id: sha, event: 'COMMENT', body, comments }, [422]);
    return status !== 422;
  }

  async editComment(repo: Repo, commentId: string, body: string): Promise<void> {
    await this.api(repo, 'PATCH', `/repos/${repo.fullName}/issues/comments/${encodeURIComponent(commentId)}`, { body });
  }

  async react(repo: Repo, _number: number, commentId: string, reaction: Reaction): Promise<void> {
    try {
      await this.api(repo, 'POST', `/repos/${repo.fullName}/issues/comments/${commentId}/reactions`, { content: reaction });
    } catch (err) {
      log.warn('reaction failed', { err });
    }
  }

  async setCheck(repo: Repo, check: CheckRun): Promise<string | null> {
    const body: Record<string, unknown> = {
      name: check.name,
      head_sha: check.headSha,
      external_id: check.externalId,
      status: check.status,
      details_url: check.detailsUrl,
      output: { title: check.title.slice(0, 250), summary: check.summary, text: check.text },
      actions: check.actions,
    };
    // GitHub takes up to 50 annotations per request.
    if (check.annotations?.length) {
      (body.output as Record<string, unknown>).annotations = check.annotations.slice(0, 50).map(a => ({
        path: a.path, start_line: a.startLine, end_line: a.endLine, annotation_level: a.level,
        title: a.title.slice(0, 255), message: a.message.slice(0, 64000),
      }));
    }
    if (check.status === 'completed') body.conclusion = check.conclusion;
    // A plan or apply starting gets a fresh check run. GitHub adds annotations to those a
    // run already has, so reusing one would repeat the notes on every re-plan.
    if (check.status !== 'completed') {
      const { data: created } = await this.api(repo, 'POST', `/repos/${repo.fullName}/check-runs`, body);
      return created?.html_url ?? null;
    }
    const { data } = await this.api(repo, 'GET',
      `/repos/${repo.fullName}/commits/${check.headSha}/check-runs?check_name=${encodeURIComponent(check.name)}&filter=latest`);
    const existing = data.check_runs?.find((c: any) => c.app?.id === Number(this.cfg.appId)) ?? data.check_runs?.[0];
    const { data: saved } = existing
      ? await this.api(repo, 'PATCH', `/repos/${repo.fullName}/check-runs/${existing.id}`, body)
      : await this.api(repo, 'POST', `/repos/${repo.fullName}/check-runs`, body);
    return saved?.html_url ?? null;
  }

  // ---- RBAC lookups ----

  userPermission(repo: Repo, user: string): Promise<Permission> {
    return this.permCache.get(`${repo.fullName}:${user}`, async () => {
      const { status, data } = await this.api(repo, 'GET', `/repos/${repo.fullName}/collaborators/${encodeURIComponent(user)}/permission`, undefined, [404]);
      if (status === 404) return 'none';
      // role_name is precise (maintain/triage); permission is the legacy field.
      const role = String(data.role_name ?? data.permission ?? 'none');
      return (['admin', 'maintain', 'write', 'triage', 'read'].includes(role) ? role : role === 'push' ? 'write' : role === 'pull' ? 'read' : 'none') as Permission;
    });
  }

  inTeam(repo: Repo, team: string, user: string): Promise<boolean> {
    const [org, slug] = team.includes('/') ? team.split('/', 2) : [repo.owner, team];
    return this.teamCache.get(`${org}/${slug}:${user}`, async () => {
      const { status, data } = await this.api(repo, 'GET',
        `/orgs/${encodeURIComponent(org)}/teams/${encodeURIComponent(slug)}/memberships/${encodeURIComponent(user)}`, undefined, [404, 403]);
      return status === 200 && data?.state === 'active';
    });
  }

  async reviews(repo: Repo, number: number): Promise<Review[]> {
    const list = await this.paginate<any>(repo, `/repos/${repo.fullName}/pulls/${number}/reviews`);
    const states: Record<string, Review['state']> = {
      APPROVED: 'approved', CHANGES_REQUESTED: 'changes_requested', COMMENTED: 'commented', DISMISSED: 'dismissed',
    };
    return list.filter(r => states[r.state] && r.user).map(r => ({ user: r.user.login, state: states[r.state], commitSha: r.commit_id }));
  }

  async compare(repo: Repo, base: string, head: string): Promise<Comparison | null> {
    const { status, data } = await this.api(repo, 'GET',
      `/repos/${repo.fullName}/compare/${encodeURIComponent(base)}...${encodeURIComponent(head)}?per_page=100`, undefined, [404, 422]);
    if (status !== 200 || !data) return null;
    const files = (data.files ?? []) as any[];
    return {
      files: files.map(f => ({ path: f.filename, status: f.status, blob: f.sha ?? null, previous: f.previous_filename })),
      commits: ((data.commits ?? []) as any[]).map(c => {
        const message = String(c.commit?.message ?? '').split('\n')[0];
        const pr = message.match(/\(#(\d+)\)$|Merge pull request #(\d+)/);
        return { sha: c.sha, message, author: c.author?.login ?? c.commit?.author?.name ?? 'someone', pr: pr ? Number(pr[1] ?? pr[2]) : undefined };
      }),
      // GitHub lists at most 300 files.
      truncated: files.length >= 300,
    };
  }

  async openPullRequest(repo: Repo, pr: { base: string; branch: string; title: string; body: string; files: { path: string; content: string }[] }): Promise<string | null> {
    const ref = await this.api(repo, 'GET', `/repos/${repo.fullName}/git/ref/heads/${pr.branch.split('/').map(encodeURIComponent).join('/')}`, undefined, [404]);
    if (ref.status === 200) return null;
    const { data: baseRef } = await this.api(repo, 'GET', `/repos/${repo.fullName}/git/ref/heads/${encodeURIComponent(pr.base)}`);
    const baseSha = baseRef.object.sha;
    const { data: baseCommit } = await this.api(repo, 'GET', `/repos/${repo.fullName}/git/commits/${baseSha}`);
    const { data: tree } = await this.api(repo, 'POST', `/repos/${repo.fullName}/git/trees`, {
      base_tree: baseCommit.tree.sha,
      tree: pr.files.map(f => ({ path: f.path, mode: '100644', type: 'blob', content: f.content })),
    });
    const { data: commit } = await this.api(repo, 'POST', `/repos/${repo.fullName}/git/commits`, { message: pr.title, tree: tree.sha, parents: [baseSha] });
    await this.api(repo, 'POST', `/repos/${repo.fullName}/git/refs`, { ref: `refs/heads/${pr.branch}`, sha: commit.sha });
    const { data: opened } = await this.api(repo, 'POST', `/repos/${repo.fullName}/pulls`, { title: pr.title, head: pr.branch, base: pr.base, body: pr.body });
    return opened?.html_url ?? null;
  }

  // Merges only the commit that was applied (`sha`): a newer push makes GitHub refuse it.
  async mergePullRequest(repo: Repo, number: number, method: 'merge' | 'squash' | 'rebase', sha: string): Promise<{ ok: boolean; message: string }> {
    const { status, data } = await this.api(repo, 'PUT', `/repos/${repo.fullName}/pulls/${number}/merge`, { merge_method: method, sha }, [403, 405, 409, 422]);
    if (status === 403) return { ok: false, message: 'the GitHub App needs Contents: Read & write to merge pull requests (App settings → Permissions)' };
    return { ok: status === 200 && data?.merged !== false, message: data?.message ?? `HTTP ${status}` };
  }

  async deleteBranch(repo: Repo, branch: string): Promise<boolean> {
    const { status } = await this.api(repo, 'DELETE', `/repos/${repo.fullName}/git/refs/heads/${branch.split('/').map(encodeURIComponent).join('/')}`, undefined, [403, 404, 422]);
    return status === 204;
  }

  async fileAt(repo: Repo, path: string, ref: string): Promise<string | null> {
    const { status, data } = await this.api(repo, 'GET',
      `/repos/${repo.fullName}/contents/${path.split('/').map(encodeURIComponent).join('/')}?ref=${encodeURIComponent(ref)}`, undefined, [404]);
    return status === 200 && typeof data?.content === 'string' ? Buffer.from(data.content, 'base64').toString('utf-8') : null;
  }

  codeowners(repo: Repo, ref: string): Promise<string | null> {
    return this.ownersCache.get(`${repo.fullName}@${ref}`, async () => {
      for (const path of ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS']) {
        const text = await this.fileAt(repo, path, ref);
        if (text !== null) return text;
      }
      return null;
    });
  }
}
