# teriac server

Pull request automation for **Terraform, OpenTofu and Terragrunt**, self-hosted with Docker or
the [Helm chart](../../charts/teriac-server/README.md).

On every push it does three things:
1. Finds the affected projects with no config needed.
2. Plans each one with the exact tool version it pins.
3. Posts the plan as a new comment, showing the exact command to apply each project, plus a check run per project with an **Apply** button.

Every action goes through per-project permissions and required approvers taken from your Git
platform's users and teams. Scheduled drift checks post to Slack, Teams, Discord, Google Chat or
any webhook, and tag who last changed each resource.

## Quick start

```sh
docker run -p 8080:8080 -v teriac-data:/data --stop-timeout 3600 \
  -e TERIAC_GITHUB_APP_ID=123456 \
  -e TERIAC_GITHUB_PRIVATE_KEY_FILE=/run/secrets/app.pem \
  -e TERIAC_GITHUB_WEBHOOK_SECRET_FILE=/run/secrets/webhook \
  -e TERIAC_REPO_ALLOWLIST='github.com/acme/*' \
  ghcr.io/marcdomain/teriac-server
```

`--stop-timeout` lets `docker stop` wait for running plans and applies (Docker's default is 10
seconds); see [Restarts and upgrades](#restarts-and-upgrades).

Set up the GitHub App like this:
- **Webhook URL:** `https://<host>/events/github`
- **Events:** pull request, issue comment, check run
- **Permissions** (Settings → Developer settings → GitHub Apps → your App → Permissions and events):

  | Permission | Access | What teriac uses it for |
  |---|---|---|
  | Repository → **Checks** | Read & write | A check run per plan, the **Apply** button, and code annotations on risky lines |
  | Repository → **Contents** | Read | Cloning the PR, reading `teriac.yaml` and `CODEOWNERS`, comparing the branch with its base (out-of-date warnings, keeping approvals after a rebase) |
  | | Read & write | Only for drift fix PRs (`fix_pr: true`: pushing the fix branch) and `automerge` (merging the PR, deleting its branch) |
  | Repository → **Issues** | Read & write | Posting and editing comments, and the 👀 reaction on commands (PR comments use the Issues API) |
  | Repository → **Pull requests** | Read & write | Changed files, reviews and approvals, mergeable state, and opening drift fix PRs |
  | Repository → **Metadata** | Read | Required by GitHub for every App |
  | Organization → **Members** | Read | `team:` rules: approvers, permissions, `override` lists and emergency-access grantors |

  Nothing else is needed: no Administration, Workflows, Secrets or Actions access. After changing
  permissions, an org owner must accept them under the org's *Installed GitHub Apps*, or the App
  keeps the old ones.
- **Logo:** upload [`brand/teriac-avatar.png`](../../brand/teriac-avatar.png) under *Display information*.
  Without a logo, GitHub shows the App owner's picture on teriac's comments.

## PR commands

| Comment | Does |
|---|---|
| `teriac plan` | Plan every project this PR changes |
| `teriac plan -p <project>` | Plan one project. `-d <dir>` and `-w <workspace>` also work |
| `teriac plan -p <project> -t <address>` | Plan only some resources; repeat `-t` for more |
| `teriac plan --destroy` | Plan a destroy |
| `teriac plan -p <project> --replace <address>` | Plan replacing a resource |
| `teriac plan -p <project> --refresh-only` | Plan updating the state to match what's deployed |
| `teriac plan -p <project> -- -var=env=prod` | Pass plan flags (off unless the repo sets `allow_extra_args: true`). Allowed: `-var`, `-var-file`, `-target`, `-replace`, `-refresh`, `-refresh-only`, `-destroy`, `-parallelism`, `-lock-timeout`, `-compact-warnings`. A `-var-file` must be a file inside the repo (checked on disk, symlinks included) |
| `teriac apply` | Apply every ready project (can be turned off, see below) |
| `teriac apply -p <project>` | Apply one project. The Apply button does the same |
| `teriac unlock` | Release this PR's locks and delete its saved plans and live output (`-p <project>` for one). Closing or merging the PR does the same |
| `teriac cancel` | Stop this PR's running plans and drop its queued work. The PR author, or anyone with write access or more |
| `teriac ask <question>` | An AI answer about this PR's plans and code, when [AI help](#ai-help) is on. Needs `plan` on a project |

`-p` and `-d` take a name or a glob: `teriac plan -p 'live/prod/*'`. A repo that applies one
project at a time refuses an apply whose glob matches more than one.

Apply always uses the saved plan, so what runs is exactly what was reviewed. A plan is applied
once: after an apply, successful or not, its plan file is deleted, and applying again needs a
new `teriac plan`.

**Terraform commands** run on one project (`-p <project>`):

| Comment | Needs |
|---|---|
| `teriac validate`, `providers`, `fmt`, `state list [address]` | `plan` |
| `teriac state show <address>`, `show`, `output [name]` | `state_read` |
| `teriac import <address> <id>`, `taint <address>`, `untaint <address>` | `state_write` and approvals |
| `teriac state rm <address>...`, `state mv <from> <to>`, `force-unlock <lock-id>` | `state_remove` and approvals |

Commands that edit the state directly take the project's lock, are audited, and plan the
project again. Only these commands run, and arguments are checked, so nothing else (such as `console` or
`-chdir`) can be passed through. Turn direct state edits off for a repo with
`allow_state_changes: false`.

Values Terraform marks as sensitive stay hidden in every command. `teriac output <name>` shows
`(sensitive value)` for sensitive outputs (plain `terraform output <name>` would print them), and
`state show` and `show` hide sensitive values wherever they appear, including where a resource
copied one into an attribute Terraform doesn't mark.

## Settings

| Env var | Default | |
|---|---|---|
| `TERIAC_REQUIRE_APPLY_PROJECT` | `false` | `true` turns off a bare `teriac apply`; people must apply one project at a time with `-p` |
| `TERIAC_REPO_ALLOWLIST` | | Allowed repos, e.g. `github.com/acme/*` (or list them in `repos.yaml`) |
| `TERIAC_REPOS_CONFIG` | `/data/repos.yaml` | Rules, approvers, channels, drift schedules |
| `TERIAC_ACK_REACTION` | `eyes` | Reaction on a command teriac picked up: `eyes`, `rocket`, `+1`, `heart`, `hooray`, `laugh`, `confused`, `-1` or `none`. Per repo: `ack_reaction` |
| `TERIAC_PROGRESS_REPLY` | `false` | Off: each result is posted once, as a new comment, and never edited (👀 shows it was picked up). On: a spinning "Running…" reply that is edited into the result. Needs a public https `TERIAC_PUBLIC_URL`; skipped otherwise. Per repo: `progress_reply` |
| `TERIAC_COMMENT_MODE` | `new` | `new`: each plan and apply gets its own comment under the command. `update`: one comment at the top, edited in place. Per repo: `comment_mode` |
| `TERIAC_PARALLELISM` | `4` | Plans and applies running at once, across all PRs |
| `TERIAC_PR_PARALLELISM` | parallelism − 1 | One PR's share, so other PRs always get a slot. Freed slots go to the PR with the fewest runs going |
| `TERIAC_DEFAULT_VERSION` | `latest` | Tool version when a project pins none |
| `TERIAC_PREINSTALL` | | Warm the cache, e.g. `terraform@1.9.8,tofu@1.8.5` |
| `GITHUB_TOKEN` | | Optional: teriac uses its GitHub App automatically. Set it on servers without a github.com App (GitLab, Bitbucket, GitHub Enterprise) to download OpenTofu and Terragrunt as a signed-in user. Needs no permissions |
| `TERIAC_GITHUB_MIRROR` / `TERIAC_HASHICORP_MIRROR` | | Download OpenTofu/Terragrunt and Terraform from your own mirror (Artifactory, Nexus) instead of GitHub and HashiCorp |
| `TERIAC_DRIFT` | `true` | Run drift schedules |
| `TERIAC_SESSION_SECRET` | random | Signs dashboard sessions (32+ characters). Set it, or sessions end on restart |
| `TERIAC_API_TOKEN` | | Admin token for automation and `/api` |
| `TERIAC_DATA_DIR` | `/data` | Database, plans, checkouts and downloaded tools |
| `TERIAC_PORT` | `8080` | HTTP port |
| `TERIAC_PUBLIC_URL` | `http://localhost:<port>` | The address people and GitHub use, for links and the dashboard. With a public `https` address, PR comments show round profile pictures, served by teriac at `/avatars/round/…` (public, and only for your GitHub host); otherwise GitHub's square ones |
| `TERIAC_GITHUB_API_URL` | `https://api.github.com` | GitHub Enterprise Server: `https://<host>/api/v3` |
| `TERIAC_RUN_TIMEOUT_SECONDS` | `3600` | Longest one Terraform command may run |
| `TERIAC_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `TERIAC_SESSION_HOURS` | `12` | How long a dashboard sign-in lasts |
| `TERIAC_MODULE_AUTH` | `true` | A read-only App token for Terraform's `git::https://` module downloads; see [Module sources](#settings) |
| `TERIAC_VERIFY_SIGNATURES` | `true` | Check the vendor's signature on downloaded Terraform, OpenTofu and Terragrunt. `false` for mirrors that don't copy `.sig` files |
| `TERIAC_BACKUP_ENABLED` | `false` | Scheduled database backups; see [Backups](#backups) for the `TERIAC_BACKUP_*` settings |
| `TERIAC_REDELIVER_MISSED` | `true` | After a restart, ask GitHub to resend webhooks that failed while teriac was down; see [Restarts and upgrades](#restarts-and-upgrades) |
| `TERIAC_REDELIVER_WINDOW_MINUTES` | `60` | Only resend webhooks this recent |
| `TERIAC_LOG_RETENTION_DAYS` | | Clear run logs this many days after a PR's last apply. Summaries, metrics and PR comments stay. Per repo: `log_retention_days` |
| `TERIAC_GITHUB_CLIENT_ID` | | The App's client ID: names the App when teriac signs in to GitHub, and enables "Sign in with GitHub" with the secret below |
| `TERIAC_GITHUB_CLIENT_SECRET` | | Turns on "Sign in with GitHub" for the dashboard; see [Dashboard](#dashboard) |
| `TERIAC_GITHUB_PRIVATE_KEY_NEXT`, `TERIAC_GITHUB_WEBHOOK_SECRET_NEXT` | | A new App key or webhook secret during a rotation; see [Rotating the GitHub App key](#rotating-the-github-app-key) |

`TERIAC_*` values are never passed to Terraform. Each secret can also be read from a file:
`<NAME>_FILE` (for example `TERIAC_SESSION_SECRET_FILE`).

**Module sources.** Use `git::https://` module sources (the image has no SSH client). Private
modules work with no setup: for each plan, apply and drift check, teriac asks the GitHub App for
a token that can **only read code** (`contents: read`) and gives it to git as a header for your
GitHub host. It never touches disk and lasts an hour. Terraform runs the PR's code, so it never
gets the App's full token. The token reaches every repo the App is installed on, so anyone who can
open a PR could read those repos during a plan; install the App only where that's fine, or set
`TERIAC_MODULE_AUTH=false` (Helm: `config.moduleAuth: false`). To use your own credentials
instead, set `GIT_CONFIG_*` with `extraEnv` (for example `GIT_CONFIG_COUNT=1`,
`GIT_CONFIG_KEY_0=url.https://x-access-token:<token>@github.com/.insteadOf`,
`GIT_CONFIG_VALUE_0=https://github.com/`); teriac then leaves git's settings alone.

Terraform, scanners and scripts get the PR's details instead: `TERIAC_REPO`, `TERIAC_PR_NUMBER`,
`TERIAC_HEAD_SHA`, `TERIAC_PROJECT`, `TERIAC_WORKSPACE` and `TERIAC_USER` (who ran the command).
Drift checks set `TERIAC_REPO`, `TERIAC_BRANCH`, `TERIAC_PROJECT` and `TERIAC_WORKSPACE`.

## Rules: `repos.yaml`

```yaml
repos:
  - id: github.com/acme/*
    require_apply_project: true          # same as the env var, per repo
    apply_requirements: [mergeable]
    projects:
      - match: prod/**
        permissions:
          apply: [team:platform-admins]  # read|write|maintain|admin, team:x, user:x, codeowners, anyone
          apply_destroy: [admin]         # plans that delete or replace
          state_read: [team:platform]    # state show, show, output (optional)
        approvals:
          - { from: team:platform-admins, count: 2 }
          - { from: team:security, count: 1 }
      - match: "**"
        approvals: [{ from: write, count: 1 }]
```

Defaults when no rule applies:

| Permission | Covers | Default | Not set for a project? Uses |
|---|---|---|---|
| `plan` | plans, `validate`, `providers`, `fmt`, `state list` | write | |
| `apply` | applies | write | |
| `apply_destroy` | applies that delete or replace | maintain | |
| `unlock` | releasing another PR's lock from the dashboard (`teriac unlock` in a PR only releases that PR's own locks: its author or anyone who may plan) | maintain | |
| `state_read` | `state show`, `show`, `output` | write | `plan` |
| `state_write` | `import`, `taint`, `untaint` | write | `apply` |
| `state_remove` | `state rm`, `state mv`, `force-unlock` | maintain | `apply_destroy` |

The last three cover the Terraform commands. When a project doesn't set them, they use the
rule they extend, so they're never looser: limit `apply_destroy` to admins and `state rm` is
admin-only too. Commands that edit the state directly (outside a plan and apply) also need the
project's approvals, like an apply.

Each command also has its own key, for exceptions: `state_list`, `state_show`, `show`, `output`,
`validate`, `providers`, `fmt`, `import`, `taint`, `untaint`, `state_rm`, `state_mv`,
`force_unlock`. A command that isn't set uses its group; `[]` means nobody.

```yaml
permissions:
  state_remove: [admin]   # state rm, state mv, force-unlock: admins
  state_mv: [maintain]    # except state mv: maintainers too
  force_unlock: []        # and nobody may force-unlock
```

Each entry's `id` is one repo (`github.com/acme/infra`) or a glob (`github.com/acme/*`). A repo uses
only the first entry that matches; entries don't combine, so list exact repos before globs and give
each everything it needs. Drift schedules need an exact repo.

Only approvals of the current commit count, and the author's own approval never counts. Each
project needs only its own approvals.

A repo's `teriac.yaml` can name projects, pin versions, and add stricter rules, but never looser
ones. It's read from the base branch, so a PR can't change its own rules.

### More repo settings

```yaml
repos:
  - id: github.com/acme/infra
    allow_fork_prs: false        # default: PRs from forks are refused (they'd run outside code with your credentials)
    checkout: merge              # plan the PR merged into its base branch; default "branch" (the PR's own commit)
    automerge: { method: squash, delete_branch: true }   # or true (merge commit)
    unlock_after_apply: false    # default: an applied project stays locked to its PR until it merges or closes
    notify_applies: [infra-alerts]                       # every apply here, done or failed
    log_retention_days: 30       # clear this repo's run logs 30 days after a PR's last apply
    remind_unmerged: { after_hours: 24, notify: [infra-alerts], comment: true }
    hooks:                       # server config only; a repo can't add hooks
      pre_plan:   [{ name: lint, run: "tflint" }]
      post_plan:  [{ name: scan, run: "checkov -f \"$PLAN_JSON\"" }]
      pre_apply:  [{ name: gate, run: "./scripts/change-window.sh" }]
      post_apply: [{ name: notify, run: "./scripts/announce.sh" }]
```

- **Fork PRs** are refused unless `allow_fork_prs: true`; teriac says so on the PR.
- **`checkout: merge`** plans GitHub's test merge of this exact commit into the base branch, so
  the plan includes what's on the base branch now. A PR with conflicts fails with a clear message.
- **`automerge`** (the App needs Contents: Read & write) merges the whole PR (all its files, not just applied projects) once every
  project with planned changes at the current commit is applied and nothing failed. Only that
  commit is merged: a newer push makes GitHub refuse it. Branch protection still applies; a
  refused merge is reported with GitHub's reason.
- **`unlock_after_apply`.** Unlock, merge and close always free a project and delete its saved
  plan and live output. Apply is different: by default the project stays locked to its PR until
  it merges or closes, so another PR can't undo an apply that was never merged. `true` frees each
  project once it's applied. A failed apply always keeps the lock.
- **`remind_unmerged`**: one reminder, mentioning whoever applied, when a PR is applied but still
  open after `after_hours`. `comment: false` sends it to chat only.
- **`hooks`** run with `sh` in the project folder, and their output goes to the log and live view.
  `post_plan` hooks get `PLAN_FILE` and `PLAN_JSON`. A failing `pre_plan`, `post_plan` or
  `pre_apply` hook fails the run (the plan can't be applied); a failing `post_apply` hook is
  reported, and the apply stands.

**Pause all applies** (an emergency stop, for incidents; planned windows belong in
[change freezes](#change-freezes-and-protected-resources)): admins pause and resume from the
dashboard's Guardrails page, or with `POST /api/applies/pause` (`{"reason": "…"}`) and
`POST /api/applies/resume`. While paused, every apply and state change in every repo is refused
with the reason; running applies finish and plans still run.

## What gets planned

teriac finds Terraform, OpenTofu and Terragrunt projects on its own and plans the ones a PR
affects. That includes changes to:
- the project's own files;
- modules it uses, and the modules those use;
- Terragrunt includes (such as `_envcommon`), `dependency` units, `read_terragrunt_config(...)`,
  `file(...)`, and hook scripts;
- parent `root.hcl`, `env.hcl` and version pins.

Paths built with Terragrunt functions (`get_repo_root()`, `get_terragrunt_dir()`,
`find_in_parent_folders()`) and with locals are resolved too.

**Watch extra files.** For a file no config mentions, such as source code that a build step
packages, add a watch. Globs work, a folder means everything inside it, and watches add to
automatic detection; they never replace it.

```hcl
# teriac:watch /lambda/orders/**/*.py scripts/build.sh      ← in any .tf, .tofu or .hcl file

locals {                                                ← Terragrunt, with its functions
  teriac_watch = ["${get_repo_root()}/schemas/*.json"]
}
```

```yaml
# teriac.yaml
projects:
  - dir: stacks/orders
    watch: ["/lambda/orders/**"]
```

Paths are relative to the project folder; a leading `/` means the repo root.

## Terragrunt dependencies

teriac never applies a dependency for you, and never applies a plan built on wrong outputs:
- **Mock outputs.** A unit planned with a dependency's `mock_outputs` (because the dependency
  isn't applied yet) is flagged in the PR and can't be applied, not even with `--override`.
  teriac tells you to apply the dependency first: `teriac apply -p live/prod/vpc`.
- **Re-plans.** When you apply a dependency, teriac re-plans the units that depend on it with the
  real outputs. That's a plan only, for you to review and apply.
- **Outdated plans.** A plan made before one of its dependencies was applied is refused with
  "re-plan first".
- **Order.** Several units applied in one command go in dependency order, and independent ones
  run in parallel.

**Plain Terraform and OpenTofu** have no dependency blocks, so declare the order in `teriac.yaml`:

```yaml
projects:
  - dir: network
  - dir: app
    depends_on: [network]     # names or dirs
```

Then `app` is planned whenever `network` changes, applied after it in the same command, skipped if
`network` fails to apply, and re-planned after `network` is applied (for you to review). teriac
doesn't pass outputs between them: `app` reads `network`'s values itself, for example with a
`terraform_remote_state` data source. This is not Terraform's own `depends_on`, which orders
resources inside one project.

## Policy checks

Rules run on every plan. In `audit` mode they report; in `enforce` mode they also block apply.
Only people in `override` can apply anyway, with `teriac apply -p <project> --override`. That is
audited.

```yaml
policies:                     # in repos.yaml (server side, so a PR can't change them)
  mode: enforce               # off | audit | enforce (a repo entry can make it stricter, not looser)
  override: [team:security]
  rules:
    - name: no-public-s3
      resource: aws_s3_bucket_acl
      deny_if: { attribute: acl, in: [public-read, public-read-write] }
    - name: rds-encrypted
      resource: aws_db_instance
      require: { attribute: storage_encrypted, equals: true }
    - name: no-prod-destroy
      projects: ["prod/**"]
      actions: [delete, replace]
      message: Destroying in prod needs a security override
  builtin: [security]         # ready-made AWS security rules (below)
  disable: [aws-kms-rotation-off]   # turn single built-in rules off
  commands:                   # any scanner; non-zero exit = finding
    - name: checkov
      run: [checkov, -f, "{plan_json}", --framework, terraform_plan, --compact, --quiet]
```

**Rule fields:**
- `resource`: a glob on the resource type.
- `actions`: `create`, `update`, `replace` or `delete`.
- `projects`: globs on the project.
- `deny_if`: a finding when the condition is true.
- `require`: a finding when the condition is false.
- Neither: the change itself is a finding.

**Conditions** check an `attribute` path with `equals`, `in`, `matches` (a regex) or `exists`.
Values only known after apply are skipped.

Findings appear in the PR comment, the check run and the dashboard's **Audit → Policy findings**
tab.

**Built-in security rules** (`builtin: [security]`): they report like any other rule, so `mode`,
`--override` and the findings tab all apply.

| Rule | Flags |
|---|---|
| `aws-s3-public-acl` | bucket ACLs `public-read`, `public-read-write`, `authenticated-read` |
| `aws-s3-public-access-block-off` | a public access block with any setting turned off |
| `aws-s3-public-policy` | a bucket policy allowing `"Principal": "*"` without a condition |
| `aws-security-group-open-ingress` | ingress from `0.0.0.0/0` or `::/0` on anything but ports 80 and 443 |
| `aws-storage-unencrypted` | RDS, Aurora, DocumentDB, Neptune, EBS, EFS, ElastiCache or Redshift without encryption |
| `aws-iam-wildcard` | an IAM policy allowing `"Action": "*"` on `"Resource": "*"` |
| `aws-database-public` | a publicly accessible database |
| `aws-deletion-protection-off` | deletion protection turned off on a database, table or load balancer |
| `aws-kms-key-deleted` | a KMS key destroyed or replaced |
| `aws-kms-rotation-off` | a symmetric KMS key without rotation |
| `aws-audit-or-backup-removed` | CloudTrail, AWS Config, GuardDuty or a backup vault or plan deleted, or CloudTrail logging off |
| `aws-eks-public-endpoint` | an EKS API endpoint open to the whole internet |

## Two-person rule

`two_person_rule: true` on a repo, or on a project rule in `repos.yaml`, means the PR's author
can't apply it; someone else with apply rights must.

## Approvals, rebases and out-of-date branches

```yaml
repos:
  - id: github.com/acme/*
    reapprove_on_change: true      # default true: a code change needs a fresh approval
    keep_approval_on_rebase: true  # default false: a rebase or "Update branch" keeps approvals
    stale_base: warn               # off | warn (default) | block
    verify_plan: true              # default true: apply only the exact plan file reviewed
```

- **Rebases.** teriac fingerprints the PR's own changes: the files it changes and their exact
  contents, compared with where the branch left the base. When an approval was given on an earlier
  commit and the fingerprint is the same now, only the base moved, so the approval still counts.
  The comment says whose approval was kept. A rebase where conflicts were resolved changes the
  fingerprint and needs a new approval. When teriac can't compare (for example, more than 300
  files changed), it asks for a new approval.
- **Out-of-date branches.** At plan and apply, teriac checks whether the base branch changed any
  file a project uses (its folder, local modules, Terragrunt dependencies, watched files) since the
  PR branched. Applying such a branch could undo those changes. `warn` shows the commits on the PR
  and in the apply reply; `block` refuses the apply until the branch is updated.
- **Reviewed plan only.** The plan file's SHA-256 is saved when it's made and checked again before
  apply. A changed or missing file is refused, audited, and must be planned again.

A repo's `teriac.yaml` can make these stricter (`reapprove_on_change: true`,
`keep_approval_on_rebase: false`, a stricter `stale_base`), never looser.

## Risk score

Every plan with changes gets a risk level, from fixed rules, so the same plan always gets the
same score. With [AI help](#ai-help) on, the AI review's findings can raise it further (never lower it);
those reasons start with "AI review:". The PR comment's Risk column shows the level, or **None** when nothing risky was found;
the reasons are in each project's dropdown and on its check run.

| Raises the level to | When the plan |
|---|---|
| Critical | destroys or replaces a stateful resource (database, bucket, KMS key, DNS zone, cluster, volume…) in production |
| High | does that outside production; destroys anything in production; changes access (IAM, roles, policies) in production; changes more than 100 resources (`size_limits.high`); has high or critical policy findings |
| Medium | destroys anything elsewhere; changes access or network resources; changes more than 25 resources (`size_limits.medium`); has medium findings; changes production at all |
| None | anything else |

```yaml
risk:                                   # in repos.yaml (server-wide or per repo)
  production: ["prod/**", "live/prod/**"]   # default: folders named prod, production or prd
  stateful_types: ["mongodbatlas_cluster", "snowflake_database", "confluent_kafka_*"]  # added to the built-in list
  size_limits: { medium: 25, high: 100 }    # changed resources that make a plan medium / high
  extra_approval:
    high: { from: team:sre, count: 1 }      # high and critical need one SRE approval
    critical: { from: team:sre, count: 2 }
```

What counts as stateful (built in): databases and clusters (RDS, Aurora, DynamoDB, Cloud SQL, Cosmos DB,
Redis, OpenSearch, Kafka…), storage (S3, GCS, Azure storage, EBS, EFS, disks), keys and secrets (KMS,
Key Vault, Secrets Manager), DNS zones, Kubernetes clusters, namespaces and volumes, backup vaults and
CloudTrail. `stateful_types` adds your own. Policy findings feed the score too, so a rule with
`severity: critical` makes a plan at least High.

**Server-wide and per repo.** `risk`, `freezes`, `protected`, `secret_scan` and `policies` can be set
at the top of `repos.yaml` (every repo) and in a repo's entry (that repo only):

- **Lists add up:** `freezes`, `protected`, `policies.rules`, `risk.stateful_types`.
- **Only stricter:** `secret_scan`, `policies.mode`, `risk.size_limits` (the server sets a minimum).
- **Anything else** set on the repo wins for that repo (`risk.production`, `risk.extra_approval`,
  `policies.override`).

A repo's own `teriac.yaml` is different: repo owners control it, so it can only tighten
(`reapprove_on_change`, `keep_approval_on_rebase`, `stale_base`, and its rules).

The check run also puts notes on the code: each resource block that will be destroyed or replaced,
and each policy finding, shows up on its line in the PR's **Files changed**.

## AI help

Optional help from Claude, off until you choose a provider. It only advises: it can raise a plan's
risk, never lower it, and nothing it says approves or applies anything. Everything it writes is
labelled with the model's name.

| Feature | What it does |
|---|---|
| `review` | A two-to-four sentence summary in each plan's comment and check run, plus findings the rules can miss: forced replacements and why, data that could be lost, access that gets wider, things that become public, protections turned off. Findings also show on the code in **Files changed** |
| `fix` | When a plan or apply fails: the likely cause, and the smallest code fix, posted as GitHub **suggested changes** (one click to commit) and shown in the comment |
| `drift` | On drift-fix PRs (`fix_pr: true`), for what the mechanical fixer can't edit: **adopt** (the code is updated to match), **revert** (left alone, so applying puts it back) or **unsure** (left to a person) |
| `ask` | `teriac ask <question>` on a PR, and **Ask about this run** on the dashboard. The AI can read the PR's code and saved plans, nothing else |
| `policy` | **Draft a policy with AI** on the dashboard's Guardrails page (admins): plain English in, `policies.rules` YAML out, checked against test cases it writes. You paste it into `repos.yaml` yourself |

```yaml
# Helm values (or the TERIAC_AI_* variables)
ai:
  provider: anthropic           # anthropic, bedrock, vertex or foundry
  existingSecret: claude-api    # Secret with key api-key (provider anthropic)
  effort: medium                # low … max: deeper reviews take longer and cost more
  features: [review, fix, drift, ask, policy]   # default: all
```

| Variable | |
|---|---|
| `TERIAC_AI_PROVIDER` | `anthropic`, `bedrock`, `vertex` or `foundry`. Empty or `off`: no AI |
| `TERIAC_AI_MODEL` | Default `claude-opus-5-5` (`anthropic.claude-opus-5-5` on Bedrock) |
| `TERIAC_AI_EFFORT` | `low`, `medium` (default), `high`, `xhigh`, `max` |
| `TERIAC_AI_FEATURES` | Comma list; default `review,fix,drift,policy,ask` |
| `TERIAC_AI_TIMEOUT_SECONDS` | Per request, default 180 |

**Per repo and per project.** `ai:` in `repos.yaml` turns AI on or off and changes the features,
model and effort, at the top (every repo), on a repo entry, and on a project rule. The first matching
project rule with `ai` wins over its repo entry, which wins over the top. `TERIAC_AI_FEATURES` stays
the ceiling. The Guardrails page shows what each level ends up with.

```yaml
ai: { enabled: false }                  # off by default…
repos:
  - id: github.com/acme/infra
    projects:
      - match: "live/prod/**"
        ai: { enabled: true, features: [review, fix], effort: high }   # …on for production
      - match: "live/dev/**"
        ai: { enabled: true, model: claude-sonnet-5-5 }               # a cheaper model for dev
```

A repo's `teriac.yaml` can turn AI off or drop features for itself (`ai: false`, or
`ai: { features: [review] }`, at the top or on a project), never turn it on or change the model:
the server's owner pays for the requests.

**Kept short in PRs.** The comment shows the AI review only when it found something medium or worse,
with at most five findings, and never repeats them in the risk line; the full review is on the check
run and the dashboard. A fix posted as a suggested change is a one-line pointer in the comment, and the
same fix is never posted twice on a PR.

Credentials come from each provider's usual place: `ANTHROPIC_API_KEY` (or `ANTHROPIC_API_KEY_FILE`); the pod's AWS role and
`AWS_REGION` for Bedrock (the standard Bedrock API; `TERIAC_AI_BEDROCK_API=mantle` for its Messages endpoint, and model names as in the Bedrock console, e.g. `anthropic.claude-sonnet-4-6`); Workload Identity with `ANTHROPIC_VERTEX_PROJECT_ID` and `CLOUD_ML_REGION`
for Vertex AI; `ANTHROPIC_FOUNDRY_RESOURCE` and `ANTHROPIC_FOUNDRY_API_KEY` for Microsoft Foundry.
With Bedrock, Vertex AI or Foundry, plans stay in your own cloud account.

**What is sent.** For a review, the changed attributes of each resource; for a fix, the end of the
error output and the project's `.tf`, `.hcl` and `.tfvars` files. Values Terraform marks sensitive are
replaced with `(sensitive value)` and the [secret scan](#leaked-secret-scan) always runs on what is
sent, whatever `secret_scan` is set to. Anything from the repo is marked as data, not instructions.

**What the AI can't do.** It only reads and writes text; nothing it says is ever run.
- It can't plan, apply, approve, unlock or change any setting. Its suggested fixes are comment-only
  reviews (never approvals) that a person must choose to commit, and teriac ignores comments written
  by bots, so an AI answer containing a teriac command does nothing.
- It can only raise a plan's risk, never lower it.
- Code it suggests (fixes, drift-fix edits) is refused if it could run programs or reach outside when
  planned: provisioners, `external` and `http` data sources, any new `data`, `module`, `provider` or
  `backend` block, `source` or `version` changes, and file functions. Drift edits must stay inside
  the drifted resource's own block.
- `teriac ask` can read the PR's code and saved plans, never `.git`, `.terraform`, state files,
  `.env` files, keys or certificates. Everything it reads is cleaned before it is sent.
- Its text has links, images, HTML and @mentions removed before it is posted.

**When it can't help.** A failed, timed-out or declined request just means no AI section: plans and
applies carry on as usual. On Anthropic's API a declined request is retried on a fallback model in
the same call. Dashboard requests are limited to 20 per person per 15 minutes. Every question,
suggestion and draft is in the audit log (`ai_ask`, `ai_suggestion`, `ai_policy_draft`).

Cost is per request, at your provider's prices: a typical review sends 5–30k tokens.

## Change freezes and protected resources

```yaml
freezes:                                # in repos.yaml (server-wide or per repo)
  - { name: weekend, projects: ["prod/**"], schedule: "0 15 * * 5", hours: 63, timezone: Europe/Madrid, override: [team:sre] }  # Fri 15:00 → Mon 06:00
  - { name: holidays, from: "2026-12-23", to: "2027-01-02" }   # whole days, both included; no override
protected:
  - { projects: ["prod/**"], resources: ["aws_db_instance.*", "aws_kms_key.*"], override: [team:sre] }
```

During a freeze, plans still run but applies and state edits (`import`, `state rm`, …) are
refused, with when the freeze ends. A protected resource is never destroyed or replaced:
the apply is refused and the block is marked on the code. Resource globs match inside modules too
(`aws_db_instance.*` covers `module.db.aws_db_instance.main[0]`).

Each entry has its own `override`: the people who may apply anyway with
`teriac apply -p <project> --override`. Without one, nobody can skip that entry. `--override` skips
only the entries (and policy findings, via `policies.override`) whose list includes the person; the
reply says who can override what is still blocking, and every use is audited.

## Leaked-secret scan

Before any output reaches a PR comment, a check run or the dashboard (live or saved), teriac
hides secrets in layers:

1. **Values Terraform marks sensitive**, read from the state and the plan, wherever they appear.
   Terraform hides them in its own diffs but not everywhere: a resource that copies a sensitive
   input into an unmarked attribute shows it in later plans, `state show` and `show`.
2. **The server's own secrets** (the GitHub App key, webhook secret, tokens) and any environment
   variable whose name looks secret, each line of multi-line values included.
3. **Known secret formats**: AWS, GitHub, GitLab, Slack, npm, PyPI, Google, GCP service-account,
   Stripe, Twilio, SendGrid, DigitalOcean, Datadog, Vault and Terraform Cloud tokens and keys;
   OpenAI and Anthropic API keys; JWTs; Azure storage keys and SAS signatures; private keys (whole
   or cut off); passwords in URLs (`postgres://user:pass@host`) and connection strings
   (`Password=…;`); and `password`, `token`, `secret`, `api_key`, `client_secret`… in plan lines.
4. **Your own patterns**, server-wide and per repo.

Terraform's own placeholders (`(sensitive value)`, `(known after apply)`) are left alone.
Terraform never gets `TF_LOG*` from the server: its debug logs print credentials.

```yaml
secret_scan:                            # in repos.yaml (Helm: under `repos:`)
  mode: redact                          # redact (default) | fail | off; a repo entry can make it stricter, not looser
  patterns:                             # your own, optional; a match shows as ‹redacted: acme-token›
    - { name: acme-token, regex: "acme_[0-9a-f]{32}" }
repos:
  - id: github.com/acme/payments
    secret_scan:                        # a repo can add patterns too (they add to the server's)
      mode: fail
      patterns: [{ name: payments-key, regex: "pay_live_[A-Za-z0-9]{24}" }]
```

- `redact` replaces each match with `‹redacted: aws-access-key›` and adds a warning.
- `fail` also refuses the plan, so it can't be applied until the secret is gone. Live output
  stops at the first match.
- `off` turns the pattern scan off; layers 1 and 2 always apply.

No scan can recognise every possible secret (a secret is just a string), so these layers cover
what can be known: what Terraform marks, what the server holds, and well-known formats. Mark
secrets `sensitive = true` in Terraform, and add patterns for your own token formats.

Every find is audited.

## Emergency access

```yaml
break_glass:                            # in repos.yaml
  grantors: [admin, "user:sre-lead@acme.com", "group:oncall"]  # dashboard admins, people, SSO groups
  max_hours: 4
  notify: [infra-alerts]
```

On the dashboard's **Access** page, a grantor gives someone a permission for a few hours, with a
reason: for example `apply` on `prod/**`. A grant can also skip approvals, freezes, protected
resources or enforced policies, for when the people who'd approve can't be reached. It ends on its
own, and can be revoked. The grant, its first use, a revoke and the expiry all go to the audit log
and the `notify` channels.

## Weekly summary

```yaml
summary:                                # in repos.yaml
  schedule: "0 9 * * 1"                 # Mondays at 09:00
  timezone: Europe/Madrid
  notify: [infra-alerts]
  days: 7
```

It sends:
- runs, failures, and how fast changes ship (PR to applied, failed applies, time to fix);
- open drift, and locks held for more than 3 days;
- the slowest projects and the most active people;
- policy findings, refused actions, and emergency access given.

## Rotating the GitHub App key

The key stays with you: teriac never creates or deletes GitHub keys (GitHub has no API for
that). It only reminds you when it's time, and switches to the new key without a restart.

```yaml
key_rotation:                           # in repos.yaml; off unless set
  every_days: 90
  remind_every_days: 7                  # default 7
  notify: [infra-alerts]
```

When the key teriac uses is `every_days` old (counted from when teriac first saw it), it sends
a message with the steps, and again every `remind_every_days` until the key changes. Check the
dashboard (the message links to running jobs) before deleting the old key:

1. On the App's settings page (linked in the message), **Generate a private key**.
2. Add it to teriac's GitHub Secret as `private-key-next` (Helm: `github.privateKeyNext`). The
   Secret is mounted as files, so teriac sees it without a restart.
3. After an hour (older tokens have expired by then), delete the old key in GitHub. GitHub
   refuses it, and teriac signs in with the new one by itself.
4. Move the new key to `private-key` and remove `private-key-next`.

The webhook secret rotates the same way, with `webhook-secret-next`: while both are set, webhooks
signed with either are accepted.

## Drift checks

```yaml
channels:                                # in repos.yaml; secrets stay in env vars
  infra-alerts: { type: slack, channel: "#infra-drift", token_env: TERIAC_SLACK_TOKEN }
  ops-teams:    { type: teams, webhook_url_env: TERIAC_TEAMS_WEBHOOK }
people:                                  # optional: git/GitHub → chat identity
  - { name: Bob Martins, github: bob-m, slack: U04BOBM, teams: bob@acme.onmicrosoft.com }

repos:
  - id: github.com/acme/infra
    drift:                               # or under `drift:` in the repo's teriac.yaml
      - name: prod-nightly
        projects: ["envs/prod", "live/prod/**"]
        branch: main
        schedule: "0 6 * * 1-5"
        timezone: Europe/Madrid
        notify: [infra-alerts, ops-teams]
```

Each run checks the branch with read-only plans (`-refresh-only -lock=false`) and reports:
- changes made outside Terraform;
- changes that were merged but never applied.

Each drifted resource tags the last person who changed its code, found from the git history of
its block, plus the last person who applied that project. Matching to chat users uses `people`
or Slack's lookup by email.

A message goes out only when the findings change (`notify_when: always` sends one every run).
Failed checks always notify.

**Fix PRs.** With `fix_pr: true` on a schedule, teriac opens a PR that updates the code to match
what is running, and links it in the message. It only edits values written plainly in the
resource block (a string, number or `true`/`false`) that still match the last applied value.
Values from variables, expressions, modules and nested blocks are listed in the PR for a person,
with who last changed them. Merge the PR to accept the change; close it and apply the base branch
to put things back. One PR per project at a time (branch `teriac/drift-fix/<project>`). The
GitHub App needs **Contents: read & write** for this.

## Backups

Runs, locks, the audit log, drift history and metrics live in a SQLite database on the server's
volume. With backups on, the server copies the database **only at the scheduled times**,
gzips the copy, uploads it to S3, GCS or Azure, and deletes the local copy. Nothing builds
up on the volume, whether the upload works or not.

| Setting | Helm value | Default | Does |
|---|---|---|---|
| `TERIAC_BACKUP_ENABLED` | `backup.enabled` | `false` | Turn backups on |
| `TERIAC_BACKUP_SCHEDULE` | `backup.schedule` | `0 3 * * *` in the chart | When to back up (cron: minute hour day month weekday). Required |
| `TERIAC_BACKUP_TIMEZONE` | `backup.timezone` | `UTC` | Time zone of the schedule |
| `TERIAC_BACKUP_BACKEND` | the section you fill in: `backup.backend.s3`, `.gcs` or `.azure` | | `s3`, `gcs` or `azure`. `s3` also covers MinIO, Cloudflare R2, Backblaze B2, … |
| `TERIAC_BACKUP_BUCKET` | `backup.backend.s3.bucket`, `.gcs.bucket` or `.azure.container` | | Bucket (Azure: container) name only |
| `TERIAC_BACKUP_PATH` | `backup.backend.<s3, gcs or azure>.path` | `teriac` (chart: `teriac/<namespace>/<release>`) | Folder in the bucket |
| `TERIAC_BACKUP_S3_REGION` / `_S3_ENDPOINT` / `_S3_STORAGE_CLASS` | `backup.backend.s3.region`, `.endpoint`, `.storageClass` | | Region; endpoint for S3-compatible services only; storage class |
| `TERIAC_BACKUP_AZURE_ACCOUNT` | `backup.backend.azure.accountName` | | Storage account (required for Azure) |
| `TERIAC_BACKUP_NOTIFY` | `backup.notify` | | Channels told when a backup fails, and when backups work again |

**Credentials.** By default the server signs in as itself: IRSA or EKS Pod Identity, GKE
Workload Identity, or Azure Workload Identity. Otherwise use `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY` (S3), `GOOGLE_APPLICATION_CREDENTIALS` (GCS), or
`TERIAC_BACKUP_AZURE_KEY` (Azure). In Helm, `backup.backend.existingSecret` names a Secret
with `access-key-id` and `secret-access-key`, `credentials.json`, or `account-key`.

**Bucket permissions.** S3: `s3:ListBucket` on the bucket, `s3:GetObject` and
`s3:PutObject` on the path (plus `kms:GenerateDataKey` and `kms:Decrypt` with SSE-KMS). GCS:
`roles/storage.objectUser`. Azure: *Storage Blob Data Contributor*. Nothing needs delete
or create-bucket rights.

**Old backups.** teriac never deletes backups. Add a lifecycle rule (expiration) to the
bucket for the backup path. Each backup (`teriac-20261111T030000000Z.db.gz`) is a whole
database on its own, so expiring old ones never breaks newer ones. Keep the expiry well
above the time between backups (daily backups: 7 days or more), so a recent one always
exists.

**Restoring.** When the server starts and its volume has no database (a new PVC, a lost
disk, or `persistence.enabled: false`), it restores the newest backup that passes SQLite's
integrity check. A broken backup, or one the lifecycle rule removed after it was listed, is
skipped for the one before. A volume that already has a database is kept as is. If the
bucket can't be read (wrong name or credentials), the server doesn't start, rather than
start empty and hide the problem. Set `TERIAC_BACKUP_ENABLED=false` to start without
restoring. Changes since the last backup are lost with the volume, so back up as often as
that matters to you.

**Watching it.** The dashboard's **Guardrails** page shows the destination, the next
backup, the latest results and a **Back up now** button for admins (audited).
`/metrics` has `teriac_backup_last_ok` and `teriac_backup_last_success_timestamp_seconds`,
for an alert such as "no good backup in 26 hours". A bucket that can't be reached fails the backup in about a minute (rclone's
`RCLONE_CONTIMEOUT`, `RCLONE_TIMEOUT`, `RCLONE_RETRIES` and `RCLONE_LOW_LEVEL_RETRIES` can be set on the
server to change that). A backup needs free space on the
volume about the size of the database while it runs.

Docker:

```sh
docker run -d -p 8080:8080 -v teriac-data:/data \
  -e TERIAC_BACKUP_ENABLED=true -e TERIAC_BACKUP_SCHEDULE='0 3 * * *' \
  -e TERIAC_BACKUP_BACKEND=s3 -e TERIAC_BACKUP_BUCKET=acme-backups -e TERIAC_BACKUP_S3_REGION=eu-west-1 \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
  … ghcr.io/marcdomain/teriac-server
```

## Restarts and upgrades

A restart, upgrade or node drain doesn't lose work. On `SIGTERM` teriac:
- finishes the plans and applies already running. It keeps answering health checks, so it isn't
  killed half-way, and `/readyz` says not ready so no new traffic comes;
- saves webhooks that arrive, and commands queued behind running work, and runs them after the
  restart;
- exits once the running work is done.

On start it:
- marks runs that a crash cut short (grace period exceeded, node lost) as failed, finishes their
  GitHub checks, drops half-written plans, and tells each PR what to do. For an apply that stopped
  part-way, that's: plan again to see what's left, and `teriac force-unlock` if Terraform's state
  lock is still held;
- asks GitHub to send again the webhooks that failed while it was down (`TERIAC_REDELIVER_MISSED`,
  on by default; needs no extra App permission). Only ones from the last
  `TERIAC_REDELIVER_WINDOW_MINUTES` (default 60) are resent, so an old `teriac apply` comment is
  never run hours later. Older failures are logged, for someone to comment again.

Give it time to finish: the chart's `terminationGracePeriodSeconds` is 4200, above the default
`TERIAC_RUN_TIMEOUT_SECONDS` of 3600. With Docker, use `--stop-timeout 3600` on `docker run`, or
`docker stop -t 3600`.

## Tamper-proof output

GitHub lets anyone with write access edit any comment, including teriac's. teriac never reads its
comments back: what gets applied comes from the plan saved on the server, and check runs (which
users can't edit) and the dashboard are the trusted record. If someone edits or deletes a teriac
comment, teriac posts a warning naming who did it, with a link to the comment and a "View the
original" section, and logs it in the audit log.

## Dashboard

From 1 December to 6 January the logo and tab icon wear a Christmas hat; `TERIAC_SEASONAL_LOGO=false` turns that off.

Open the server's URL in a browser. It shows:
- an overview of runs, failures, locks and drift, with a banner while a change freeze is on;
- every plan and apply, with its risk, change list and redacted log, and **live output while it
  runs** (cleaned of secrets line by line; kept in memory, dropped when the PR's lock is released or
  the PR closes);
- locks, with an Unlock button;
- drift schedules, findings, and who last changed each resource;
- the audit log;
- an **All applies paused** banner, with Resume for admins, and an Emergency stop on Guardrails;
- **Guardrails**: change freezes (and whether one is on now), protected resources, risk,
  policy and secret-scan settings, each repo entry's approval settings, and database
  backups with a **Back up now** button (see [Backups](#backups));
- **Access**: emergency access grants (see [Emergency access](#emergency-access));
- **Metrics**: runs, timings, resource use, and delivery: PR to applied, failed applies, time to
  fix, applies per week.

Logs are coloured like the PR comments. It has light and dark themes. Viewers can see everything;
admins can also unlock, pause applies, start drift checks and start a backup.

| Sign-in | Settings |
|---|---|
| Okta or any OIDC provider | `TERIAC_OIDC_ISSUER`, `TERIAC_OIDC_CLIENT_ID`, `TERIAC_OIDC_CLIENT_SECRET`, `TERIAC_OIDC_ADMIN_GROUPS`, `TERIAC_OIDC_ALLOWED_GROUPS`; optional `TERIAC_OIDC_NAME` (button label), `TERIAC_OIDC_SCOPES` (default `openid,profile,email,groups`), `TERIAC_OIDC_GROUPS_CLAIM` (default `groups`). Redirect URI: `<public url>/auth/oidc/callback` |
| GitHub | `TERIAC_GITHUB_CLIENT_ID`, `TERIAC_GITHUB_CLIENT_SECRET` (the App's, from its settings page), `TERIAC_GITHUB_ADMIN_USERS`, `TERIAC_GITHUB_ADMIN_TEAMS` (`org/slug`), optional `TERIAC_GITHUB_ALLOWED_TEAMS`. Callback URL on the App: `<public url>/auth/github/callback` |
| Username and password | `dashboard.users` in `repos.yaml`, or `TERIAC_DASHBOARD_USERS_FILE`. Hash passwords with `node packages/server/src/hash-password.ts`. `TERIAC_DASHBOARD_PASSWORD_LOGIN=false` turns it off (and ends password sessions) |
| API token | `TERIAC_API_TOKEN` (admin) |

**Signed in with GitHub**, people see only the repos that both they and the App can see on
GitHub (runs, live output, locks, audit, metrics, drift). They can release their own locks, and others
where the project's `unlock` permission allows them (default maintain); other actions are for admins. teriac checks with
GitHub again every 10 minutes, so lost access or leaving an admin team takes effect within that time;
these sessions last at most 8 hours.

Sessions are signed, HttpOnly cookies. Login attempts are rate limited, and the page loads nothing
from third parties.

## API

These need a dashboard session or `Authorization: Bearer $TERIAC_API_TOKEN`:
- `GET /api/runs`
- `GET /api/locks`
- `GET /api/audit`
- `GET /api/drift`
- `GET /api/drift/schedules`
- `POST /api/drift/run?key=…` (admin)
- `POST /api/locks/unlock` (admin)
- `GET /api/safety` (the Guardrails page)
- `GET /api/backups`
- `POST /api/backups/run` (admin)
- `GET /api/applies`, `POST /api/applies/pause` and `/resume` (admin)
- `POST /api/commands`: run a PR command from outside GitHub (below)

```bash
curl -X POST https://teriac.acme.com/api/commands \
  -H "Authorization: Bearer $TERIAC_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"repo": "github.com/acme/infra", "pr": 42, "command": "apply -p envs/dev", "as": "alice"}'
```

It runs `plan`, `apply`, `unlock` or `cancel` as a GitHub login: the one in `as` with the API
token, or yourself when signed in with GitHub (password and SSO users can't). That person's
permissions and the PR's approvals, locks and freezes apply, as for a comment. The answer is
`202 Accepted`; teriac posts the result on the PR, saying it came from the API and for whom.

`/healthz`, `/readyz` and `/metrics` (Prometheus) are open.
