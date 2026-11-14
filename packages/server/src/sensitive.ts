// Values Terraform marks as sensitive, read from `show -json` (of a state or a plan), so they
// can be hidden wherever they turn up in text. Terraform hides them in its own diffs, but not
// everywhere: `terraform output NAME` prints them, and a resource that copies a sensitive
// input into an unmarked attribute (terraform_data's `output`, for one) shows it in `state
// show`, `show` and in plan diffs of later changes.

type Json = unknown;
const MIN = 6; // shorter values are too likely to appear by accident ("true", "admin")

const add = (out: Set<string>, v: Json) => {
  if (typeof v === 'string') {
    if (v.length >= MIN) out.add(v);
    // A multi-line value (a key, a certificate) can show up one line at a time.
    for (const line of v.split('\n')) if (line.trim().length >= 16) out.add(line.trim());
  } else if (Array.isArray(v)) {
    for (const x of v) add(out, x);
  } else if (v && typeof v === 'object') {
    for (const x of Object.values(v)) add(out, x);
  }
};

// Every leaf of `values` that `mask` marks true (Terraform's sensitive_values shape: true,
// or an object/array of the same shape as the values).
const masked = (out: Set<string>, values: Json, mask: Json) => {
  if (mask === true) return add(out, values);
  if (!mask || typeof mask !== 'object' || !values || typeof values !== 'object') return;
  for (const [k, m] of Object.entries(mask as Record<string, Json>)) masked(out, (values as Record<string, Json>)[k], m);
};

const moduleValues = (out: Set<string>, mod: Json) => {
  const m = mod as { resources?: { values?: Json; sensitive_values?: Json }[]; child_modules?: Json[] } | undefined;
  for (const r of m?.resources ?? []) masked(out, r.values, r.sensitive_values);
  for (const c of m?.child_modules ?? []) moduleValues(out, c);
};

const stateValues = (out: Set<string>, values: Json) => {
  const v = values as { root_module?: Json; outputs?: Record<string, { sensitive?: boolean; value?: Json }> } | undefined;
  moduleValues(out, v?.root_module);
  for (const o of Object.values(v?.outputs ?? {})) if (o?.sensitive) add(out, o.value);
};

export const sensitiveValues = (doc: Json): string[] => {
  const out = new Set<string>();
  const d = doc as Record<string, any> | null;
  if (!d || typeof d !== 'object') return [];
  // A state (`show -json`) or a plan's prior state and planned values.
  stateValues(out, d.values);
  stateValues(out, d.prior_state?.values);
  stateValues(out, d.planned_values);
  for (const rc of d.resource_changes ?? []) {
    masked(out, rc.change?.before, rc.change?.before_sensitive);
    masked(out, rc.change?.after, rc.change?.after_sensitive);
  }
  for (const oc of Object.values<Record<string, any>>(d.output_changes ?? {})) {
    if (oc?.before_sensitive === true) add(out, oc.before);
    if (oc?.after_sensitive === true) add(out, oc.after);
  }
  // Variables declared `sensitive = true`, with the values the plan used.
  const declared = d.configuration?.root_module?.variables ?? {};
  for (const [name, v] of Object.entries<Record<string, any>>(d.variables ?? {})) {
    if (declared[name]?.sensitive) add(out, v?.value);
  }
  // Longest first, so a value containing another is replaced whole.
  return [...out].sort((a, b) => b.length - a.length);
};

// Hides each value. Values are matched as plain text; quotes around them stay.
export const hideValues = (text: string, values: Iterable<string>): string => {
  let out = text;
  for (const v of values) if (out.includes(v)) out = out.split(v).join('(sensitive value)');
  return out;
};
