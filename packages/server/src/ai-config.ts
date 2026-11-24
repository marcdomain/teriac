// AI settings: the server's provider and model (TERIAC_AI_*), and the `ai:` blocks of repos.yaml
// and teriac.yaml that turn it on or off per repo and project. Kept apart from ai.ts so the
// config loaders don't pull in the policy engine.
export type AiProvider = 'anthropic' | 'bedrock' | 'vertex' | 'foundry';
export const AI_PROVIDERS: AiProvider[] = ['anthropic', 'bedrock', 'vertex', 'foundry'];
export type AiFeature = 'review' | 'fix' | 'drift' | 'policy' | 'ask';
export const AI_FEATURES: AiFeature[] = ['review', 'fix', 'drift', 'policy', 'ask'];
export type AiEffort = 'low' | 'medium' | 'high' | 'xhigh' | 'max';
const EFFORTS: AiEffort[] = ['low', 'medium', 'high', 'xhigh', 'max'];

export interface AiConfig {
  provider: AiProvider;
  model: string;
  effort: AiEffort;
  features: AiFeature[];
  timeoutMs: number;
}

export const DEFAULT_MODEL = 'claude-opus-5-5';

// TERIAC_AI_PROVIDER turns it on. Credentials come from each provider's usual place:
// ANTHROPIC_API_KEY; the AWS credential chain and AWS_REGION; Google ADC with
// ANTHROPIC_VERTEX_PROJECT_ID and CLOUD_ML_REGION; ANTHROPIC_FOUNDRY_RESOURCE and ANTHROPIC_FOUNDRY_API_KEY.
export const loadAiConfig = (env: NodeJS.ProcessEnv): AiConfig | undefined => {
  const provider = (env.TERIAC_AI_PROVIDER ?? '').trim().toLowerCase();
  if (!provider || provider === 'off') return undefined;
  if (!AI_PROVIDERS.includes(provider as AiProvider)) throw new Error(`TERIAC_AI_PROVIDER must be one of ${AI_PROVIDERS.join(', ')} or off, not "${env.TERIAC_AI_PROVIDER}"`);
  const effort = (env.TERIAC_AI_EFFORT || 'medium').trim().toLowerCase();
  if (!EFFORTS.includes(effort as AiEffort)) throw new Error(`TERIAC_AI_EFFORT must be one of ${EFFORTS.join(', ')}, not "${env.TERIAC_AI_EFFORT}"`);
  const features = (env.TERIAC_AI_FEATURES || AI_FEATURES.join(',')).split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  for (const f of features) if (!AI_FEATURES.includes(f as AiFeature)) throw new Error(`TERIAC_AI_FEATURES: unknown feature "${f}" (${AI_FEATURES.join(', ')})`);
  if (provider === 'vertex' && !env.ANTHROPIC_VERTEX_PROJECT_ID) throw new Error('TERIAC_AI_PROVIDER=vertex needs ANTHROPIC_VERTEX_PROJECT_ID (and CLOUD_ML_REGION, default "global")');
  if (provider === 'bedrock' && !(env.AWS_REGION || env.AWS_DEFAULT_REGION)) throw new Error('TERIAC_AI_PROVIDER=bedrock needs AWS_REGION');
  const model = modelFor(provider as AiProvider, env.TERIAC_AI_MODEL?.trim() || DEFAULT_MODEL);
  return {
    provider: provider as AiProvider, model, effort: effort as AiEffort, features: features as AiFeature[],
    timeoutMs: Math.max(10, Number(env.TERIAC_AI_TIMEOUT_SECONDS || 180)) * 1000,
  };
};

// ---- where AI is on: repos.yaml (server, repo entry, project rule) and teriac.yaml ----

// An `ai:` block. In repos.yaml it can turn AI on or off and change the features, model and
// effort; TERIAC_AI_FEATURES stays the ceiling. In teriac.yaml it can only turn AI off or drop
// features: the server's owner pays for the requests.
// When plan reviews run: every plan (push), only a PR's first plan of each project (first),
// or only when asked with `teriac review` (command). Asking always works when review is on.
export type AiReviewMode = 'push' | 'first' | 'command';
export const AI_REVIEW_MODES: AiReviewMode[] = ['push', 'first', 'command'];
export interface AiOverride { enabled?: boolean; features?: AiFeature[]; model?: string; effort?: AiEffort; review?: AiReviewMode }
// What applies to one project; null when AI is off for it.
export interface AiSettings { features: AiFeature[]; model: string; effort: AiEffort; review: AiReviewMode }

export const validateAiOverride = (v: unknown, where: string): AiOverride | undefined => {
  if (v === undefined || v === null) return undefined;
  if (typeof v === 'boolean') return { enabled: v };   // `ai: false` is short for `ai: { enabled: false }`
  if (typeof v !== 'object' || Array.isArray(v)) throw new Error(`${where} must be true, false or { enabled, features, model, effort }`);
  const o = v as Record<string, unknown>;
  for (const k of Object.keys(o)) if (!['enabled', 'features', 'model', 'effort', 'review'].includes(k)) throw new Error(`${where}: unknown setting "${k}" (enabled, features, model, effort, review)`);
  if (o.review !== undefined && !AI_REVIEW_MODES.includes(o.review as AiReviewMode)) throw new Error(`${where}.review must be push (every plan), first (a PR's first plan, then on request) or command (only on request)`);
  if (o.enabled !== undefined && typeof o.enabled !== 'boolean') throw new Error(`${where}.enabled must be true or false`);
  if (o.features !== undefined) {
    if (!Array.isArray(o.features)) throw new Error(`${where}.features must be a list of ${AI_FEATURES.join(', ')}`);
    for (const f of o.features) if (!AI_FEATURES.includes(f as AiFeature)) throw new Error(`${where}.features: unknown feature "${f}" (${AI_FEATURES.join(', ')})`);
  }
  if (o.model !== undefined && (typeof o.model !== 'string' || !o.model.trim())) throw new Error(`${where}.model must be a model name`);
  if (o.effort !== undefined && !EFFORTS.includes(o.effort as AiEffort)) throw new Error(`${where}.effort must be one of ${EFFORTS.join(', ')}`);
  return o as AiOverride;
};

// Layers in order; later ones win. Server layers: repos.yaml's top-level `ai`, the repo entry's,
// the first matching project rule that has one. Repo layers (teriac.yaml) only narrow.
export const resolveAi = (cfg: AiConfig | undefined, server: (AiOverride | undefined)[], repo: (AiOverride | undefined)[] = []): AiSettings | null => {
  if (!cfg) return null;
  let enabled = true;
  let features = [...cfg.features];
  let model = cfg.model;
  let effort = cfg.effort;
  let review: AiReviewMode = 'push';
  for (const o of server) {
    if (!o) continue;
    if (o.enabled !== undefined) enabled = o.enabled;
    if (o.features) features = cfg.features.filter(f => o.features!.includes(f));
    if (o.model) model = modelFor(cfg.provider, o.model);
    if (o.effort) effort = o.effort;
    if (o.review) review = o.review;
  }
  for (const o of repo) {
    if (!o) continue;
    if (o.enabled === false) enabled = false;
    if (o.features) features = features.filter(f => o.features!.includes(f));
    // Less often is fine (it costs less); more often is the server's call.
    if (o.review && AI_REVIEW_MODES.indexOf(o.review) > AI_REVIEW_MODES.indexOf(review)) review = o.review;
  }
  return enabled && features.length ? { features, model, effort, review } : null;
};

// A model name as each provider wants it, so one setting (claude-sonnet-4-6) works everywhere:
// Bedrock: anthropic.claude-…, or as given when it is an inference profile (us./eu./apac./global.…)
// or an ARN. Anthropic's API and Vertex AI: the bare name. Foundry: your deployment's name, as given.
const BEDROCK_PREFIX = /^(?:(?:us|eu|apac|jp|au|ca|us-gov|global)\.)?anthropic\./;
export const modelFor = (provider: AiProvider, model: string): string => {
  const m = model.trim();
  switch (provider) {
    case 'bedrock': return m.startsWith('arn:') || BEDROCK_PREFIX.test(m) ? m : `anthropic.${m}`;
    case 'anthropic': case 'vertex': return m.replace(BEDROCK_PREFIX, '');
    case 'foundry': return m;
  }
};

// The model's name as shown on comments and the dashboard.
export const label = (s: { model: string }) => s.model.replace(/^arn:.*\//, '').replace(BEDROCK_PREFIX, '');

// What to do about a refused request, per provider: shown in the log and on the dashboard.
export const aiErrorHint = (provider: AiProvider, status: number | undefined, message: string): string => {
  const m = message.toLowerCase();
  if (provider === 'bedrock') {
    if (m.includes('inference profile') || m.includes('on-demand throughput')) return 'This model needs an inference profile on Bedrock: set the model to us.anthropic.<model> (or eu., apac., global.).';
    if (status === 403 && m.includes('not available for this account')) return 'AWS holds this model back for this account. Try another Claude model (e.g. claude-sonnet-4-6), or ask AWS for access.';
    if (status === 403 || m.includes('access denied') || m.includes("don't have access")) return "Accept Anthropic's terms for this model in Bedrock (Model catalog), and let the server's role call bedrock:InvokeModel.";
    if (status === 404 || m.includes('does not exist')) return 'Bedrock does not know this model name here. Use the id from the Bedrock console (e.g. anthropic.claude-sonnet-4-6) in AWS_REGION; with TERIAC_AI_BEDROCK_API=mantle, check the endpoint offers it.';
    if (m.includes('security token') || m.includes('credential')) return "No usable AWS credentials: give the pod a role (IRSA or EKS Pod Identity), or set AWS_* credentials.";
  }
  if (provider === 'vertex') {
    if (status === 404) return 'Enable this Claude model in Vertex AI Model Garden for ANTHROPIC_VERTEX_PROJECT_ID, in CLOUD_ML_REGION (global, or a region that offers it).';
    if (status === 403 || status === 401) return 'The server\'s Google identity needs roles/aiplatform.user on the project (Workload Identity or GOOGLE_APPLICATION_CREDENTIALS).';
  }
  if (provider === 'foundry') {
    if (status === 404) return 'Set the model (TERIAC_AI_MODEL or ai.model) to your Foundry deployment\'s name, and check ANTHROPIC_FOUNDRY_RESOURCE.';
    if (status === 401 || status === 403) return 'Check ANTHROPIC_FOUNDRY_API_KEY and that it belongs to ANTHROPIC_FOUNDRY_RESOURCE.';
  }
  if (provider === 'anthropic') {
    if (status === 401) return 'ANTHROPIC_API_KEY is missing or wrong (Claude Console → API keys).';
    if (m.includes('credit balance')) return 'The Claude Console account has no credits: add some under Billing.';
    if (status === 404) return 'Unknown model name for the Claude API (e.g. claude-opus-5-5, claude-sonnet-5-5).';
  }
  if (status === 429) return 'Rate limited by the provider: fewer projects with AI, a lower effort, or a higher quota.';
  if (status === 400 && (m.includes('output_config') || m.includes('format') || m.includes('effort'))) return 'This model or provider does not support a setting teriac uses (effort or structured output): choose a newer Claude model.';
  return '';
};

// Review findings worth a person's attention in the PR; low ones stay on the check run and dashboard.
export const important = (f: { severity: string }) => f.severity !== 'low';
