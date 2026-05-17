# RFC: Least-Privilege Access for MongoDB Atlas & RDS

**Status:** Draft — pending review  
**Story:** [#70385](https://app.shortcut.com/sentra/story/70385)  
**Epic:** [#70383](https://app.shortcut.com/sentra/epic/70383) — Least-Privilege Access for MongoDB & RDS  
**Author:** Platform Engineering  
**Reviewers:** DevOps Lead, Security  
**Created:** 2026-05-17  

---

## TL;DR

Every service and human in prod currently shares one of two credentials: an `atlasAdmin` MongoDB user or the RDS master password. This RFC defines the role model, credential delivery path, and migration strategy to eliminate shared admin access across both databases, replacing it with per-service scoped roles managed as code.

---

## 1. Problem Statement

### Current state

#### MongoDB Atlas

A single database user `admin` with the built-in `atlasAdmin` role exists on the `general` cluster across all environments (prod, staging, demo). Its credentials are stored in AWS Secrets Manager as `sentra-prod-mongodb-admin-secret` and distributed to every service that touches MongoDB.

**All five MongoDB consumers share this one credential:**

| Service | Actual need | Current role |
|---|---|---|
| `connectors-service` | readWrite on owned org databases | `atlasAdmin` ⚠️ |
| `luxus-service` / `classifications` / `galio` | readWrite on org databases | `atlasAdmin` ⚠️ |
| `debezium-mongodb-source-connector` | read + changeStream (CDC only) | `atlasAdmin` ⚠️ |

#### RDS / PostgreSQL

The RDS provisioning stack (`postgresql_provision/provision.py`) retrieves the **master RDS credentials** from the base stack and writes them verbatim into every service secret in Secrets Manager. There are no application-level roles today. The only scoped users are `datadog` and `pganalyze` (both with `pg_monitor`).

**~25 service secrets all contain the same master username/password:**

| RDS Instance | Databases | Services using master creds |
|---|---|---|
| `application` | api_service_prod, scan_flow_service_prod, integrations_api_prod, backoffice_service_prod, automations_service, deployment_ca_service_prod, monitoring_service_prod, organization_management_prod, remediation_service_prod, temporal, temporal_visibility, adr_mcp_server_prod | api-service, data-assets-backend, data-feed, e2e-manager, scan-flow, integrations-api, backoffice, automations, deployment-ca, monitoring, org-management, remediation, temporal, adr-mcp-server |
| `access-service` | access_service_prod, ai_security_service_prod | access-service, monitoring-access, data-lake, platform-tool, ai-security-service |
| `dagster-v2` | dagster, dagster_scanning, data_pipelines | dagster, dagster-scanning, data-pipelines |
| `labelstudio` | labelstudio | labelstudio |
| `metabase` | metabase | metabase |

### Risk

- Any compromised service pod has full admin access to **all** customer data across all organisations.
- Credential rotation requires coordinating every service simultaneously.
- No audit trail distinguishes which service performed a given database operation.
- `debezium-mongodb-source-connector` reads all org databases for CDC but holds the same credential that can drop collections, create users, or modify cluster config.

---

## 2. Scope

### In scope (v1)

- Production MongoDB Atlas cluster `general` — all environments (prod, staging, demo)
- Production RDS instances: `application`, `access-service`, `dagster-v2`
- All Sentra-internal services (microservices, Debezium connectors, Dagster pipelines)
- Human engineer access: read-only and break-glass

### Out of scope (v1)

- RDS instances `labelstudio` and `metabase` (third-party tools, separate track)
- Customer-facing connectors that scan external databases (different credential model)
- Dev/local environments

---

## 3. Role Taxonomy

### 3.1 MongoDB Atlas

Naming convention: `<service-slug>_<env>_<access-level>`

| Role name | Atlas privileges | Assigned to |
|---|---|---|
| `connectors_prod_rw` | `readWrite` on `organization_*` databases | connectors-service |
| `luxus_prod_rw` | `readWrite` on `organization_*` databases | luxus-service, classifications, galio |
| `debezium_prod_cdc` | `read` + `changeStream` on `organization_*` | debezium-mongodb-source-connector |
| `human_analytics_ro` | `read` on `organization_*` | engineers (SSO-federated, read-only) |
| `break_glass_admin` | `atlasAdmin` | on-call (JIT via Atlas federation, time-bound) |

> **Design note:** `connectors-service` and `luxus-service` access the same org databases, but they get separate roles for independent revocation. A single compromised service should not implicate the other.

### 3.2 RDS / PostgreSQL

Naming convention: `<service-slug>_app` / `<service-slug>_ro` / `<service-slug>_mig`

| Role suffix | PostgreSQL privileges | Purpose |
|---|---|---|
| `<service>_app` | `CONNECT`, `USAGE ON SCHEMA public`, `SELECT/INSERT/UPDATE/DELETE` on owned tables | Normal application read-write |
| `<service>_ro` | `CONNECT`, `USAGE ON SCHEMA public`, `SELECT` only | Monitoring, analytics, read-only consumers |
| `<service>_mig` | `CREATE`, `ALTER`, `DROP` on owned schema | Alembic/migration jobs only; `NOLOGIN` by default, enabled only during deploy |
| `debezium_replication` | `REPLICATION` role + `SELECT` on published tables | CDC connectors (one per RDS instance) |
| `datadog` | `pg_monitor` | Already exists ✓ |
| `pganalyze` | `pg_monitor`, connection limit 5 | Already exists ✓ |

**Examples for the `application` RDS instance:**

```
api_service_app        → readWrite on api_service_prod
data_feed_app          → readWrite on api_service_prod
scan_flow_app          → readWrite on scan_flow_service_prod
integrations_api_app   → readWrite on integrations_api_prod
temporal_app           → readWrite on temporal, temporal_visibility
debezium_app_replication → REPLICATION on application instance
metabase_ro            → SELECT on relevant databases (future)
```

---

## 4. Credential Storage & Delivery

### 4.1 MongoDB — Atlas Kubernetes Operator (new)

The **MongoDB Atlas Kubernetes Operator** (`mongodb-kubernetes` v1.5) is already deployed in staging via ArgoCD. We will move it to the **platform-tools cluster** to centrally manage Atlas users across all environments.

**Flow:**

```
Git PR (AtlasDatabaseUser CRD)
  → ArgoCD (platform-tools)
    → Atlas Operator
      → Atlas API (creates user)
        → K8s Secret written to platform-tools/core namespace
          → Reflector mirrors secret to workload clusters (prod/staging)
            → Service pod reads MongoDB credentials as env vars
```

**CRD location:** `argocd/infra/manifests/atlas/users/<env>/<service>.yaml`

**Example CRD:**
```yaml
apiVersion: atlas.mongodb.com/v1
kind: AtlasDatabaseUser
metadata:
  name: connectors-prod-rw
  namespace: core
spec:
  projectRef:
    name: sentra-prod          # AtlasProject CRD
  username: connectors_prod_rw
  databaseName: admin
  roles:
    - roleName: readWrite
      databaseName: organization_*  # scoped via Atlas custom role
  passwordSecretRef:
    name: atlas-connectors-prod-password
```

**Required changes:**
1. Change `mongodb-operator_applicationset.yaml` cluster selector from `environment: "staging"` → `environment: "platform-tools"`
2. Create `AtlasProject` CRDs for prod, staging, demo (referencing Atlas org-level API key already in Secrets Manager)
3. Add Reflector annotations to operator-generated secrets for cross-cluster mirroring

### 4.2 RDS — Pulumi + ESO (existing path, extended)

RDS roles continue to be provisioned by Pulumi in `postgresql_provision/provision.py`. The change is that `provision_instance()` creates **per-service `Role` + `Grant` resources** instead of distributing master credentials.

Master credentials stay in the base stack and are used only as the Pulumi PostgreSQL provider — they are **never written to service secrets**.

**Flow (unchanged for RDS):**
```
Pulumi (postgresql_provision)
  → creates Role + Grant per service
    → stores scoped secret in AWS Secrets Manager (prod/rds-<service>-v2)
      → ESO syncs to K8s Secret in workload cluster
        → Service pod reads as env vars
```

### 4.3 Rotation policy

| Credential type | Rotation cadence | Method |
|---|---|---|
| MongoDB app users | 90 days | Atlas Operator re-generates password on CRD update |
| RDS app users | 90 days | AWS Secrets Manager automatic rotation (Lambda rotator) |
| RDS master | 180 days | Manual, break-glass only |
| Break-glass admin (Atlas) | Per-use | JIT via Atlas federation, auto-expired |

---

## 5. Human Access

> **Key for this section:**
> - ✅ **Confirmed** — verified in code or config
> - ⚠️ **Assumption** — technically possible, not yet built; alternate path provided
> - ❌ **Blocked** — depends on a prerequisite that must be resolved first

---

### 5.1 RDS / PostgreSQL access

#### IAM database authentication

✅ **Confirmed possible.** `iam_database_authentication_enabled: true` is already set on all target prod RDS instances (`application-v2`, `dagster-v2`, `access-service`) in `Pulumi.prod.yaml`. The feature is live — no Pulumi change needed to enable it.

✅ **Confirmed possible.** `aws sso login --profile prod/staging` is an existing daily developer workflow (`~/.aws/config` uses `d-9067e67cee.awsapps.com/start`). The SSO session provides the IAM identity needed to call `aws rds generate-db-auth-token`.

**What still needs to be built:**
- PostgreSQL IAM-auth roles (`CREATE ROLE break_glass_admin LOGIN; GRANT rds_iam TO break_glass_admin;`) — Pulumi change in `postgresql_provision/provision.py`
- IAM policy allowing `rds-db:connect` for the relevant SSO permission sets — Pulumi or AWS console

**Developer workflow (RDS):**
```bash
aws sso login --profile prod                         # existing daily habit
aws rds generate-db-auth-token \
  --profile prod \
  --hostname <rds-endpoint> \
  --port 5432 \
  --username break_glass_admin
# Token valid 15 min. Every call logged via IAM CloudTrail.
```

---

### 5.2 MongoDB / Compass access

#### Option A — Atlas Identity Federation with Okta (SAML SSO) ⚠️ Assumption

⚠️ **Assumption (technically possible, not yet configured).** MongoDB Atlas supports Okta as a SAML IdP via Atlas Org Federation Management. The feature exists in Atlas. Sentra has Okta at `sentrasec.okta.com` and already uses it as a SAML IdP for ArgoCD (`argocd.py` line ~210). The integration pattern is proven in the org.

**What would need to be done:**
1. Atlas org-admin creates a federation config in Atlas → Organization → Federation Management
2. Adds Okta as IdP (metadata URL from `sentrasec.okta.com`)
3. Maps Okta groups → Atlas roles (`sentra-db-admins` → `atlasAdmin`, `sentra-db-readonly` → `human_analytics_ro`)
4. Engineers log in to Compass via `Log in with SSO` → Okta MFA → role granted from group membership

**This requires:** Atlas org-admin access + Okta admin access to create the SAML app. No code changes.

**Developer workflow if Option A is built:**
```bash
# Compass: File → Connect → Advanced → Authentication: SSO
# mongosh:
mongosh "mongodb+srv://general-pl-0.0bjrm.mongodb.net/" \
  --username oren@sentra.io \
  --authenticationMechanism MONGODB-OIDC
# Okta MFA popup → Atlas reads group membership → role granted
```

#### Option B — Scoped Atlas user credentials via Secrets Manager (alternate, buildable now)

✅ **Confirmed possible immediately.** If Atlas Identity Federation is not prioritised, the same security improvement is achievable with scoped Atlas users whose passwords are stored in Secrets Manager (never on laptops) and fetched via `task dev:pull-secrets`.

```
Atlas user: human_analytics_ro  (readOnly on org_* databases)
Password:   stored in Secrets Manager dev/mongo-human-ro
Access:     granted to engineers via SSO IAM session (existing aws sso login)
Rotation:   Atlas Operator rotates every 90 days
Audit:      Atlas audit log → Datadog (same as SSO path)
```

**Tradeoff:** Password is fetched and written to `.env.local.*.generated` (gitignored, 90-day TTL vs. SSO session expiry). Less elegant than SSO but fully auditable and revocable. Can be upgraded to Option A later without changing the service code.

**Recommendation:** Build Option B first (unblocked, no Atlas/Okta admin coordination needed). Plan Option A as a follow-up story once Atlas federation setup is scoped.

---

### 5.3 On-call / break-glass admin access

#### PagerDuty → Okta group sync

✅ **Confirmed possible.** The hourly GHA cron in `.github/workflows/on_callers.yaml` already polls PagerDuty and updates Slack usergroups. The Okta Python SDK (`okta ^3.0.0`) is already a dependency and the client is initialised in `okta_user_sync.py` against `sentrasec.okta.com`.

**What still needs to be validated before building:**
- Does `OKTA_SENTRASEC_ADMIN_TOKEN` (existing GHA secret) have `groups:manage` scope, or does a new token need to be issued? — **Needs Okta admin to check**
- Does `sentra-db-admins` Okta group exist? — **Needs Okta admin to check; trivial to create if not**

**What needs to be built (once above confirmed):**

Add one step to `.github/workflows/on_callers.yaml`:
```yaml
- name: Set Okta db-admins group
  run: task remote:set-okta-db-admins
  env:
    OKTA_API_TOKEN: ${{ secrets.OKTA_API_TOKEN }}
```

New script `scripts/okta_assign_db_admins.py` — direct port of `slack_assign_on_call_groups.py`, replacing `client.usergroups_users_update()` with:
```python
await okta_client.add_user_to_group(DB_ADMINS_GROUP_ID, user_id)
```

Filtered strictly to `prod-db-admin` PagerDuty schedule. Access updates within 60 minutes of shift change.

#### If Okta group management scope is unavailable — alternate path ⚠️

⚠️ **Assumption (fallback).** If the Okta token cannot be granted `groups:manage`, the same outcome is achievable via an IAM-only path for RDS, and a dedicated Atlas database user for MongoDB (both without touching Okta groups):

- **RDS:** IAM permission set `prod-db-break-glass` granted to on-call engineer's SSO session directly, without an Okta group — managed via AWS IAM Identity Center permission assignments (existing infrastructure).
- **MongoDB:** Dedicated `break_glass_admin` Atlas user with password in Secrets Manager, accessible only to the `prod-db-admin` PagerDuty on-call person via a manual `task db:break-glass` command that requires PagerDuty API confirmation of active on-call status before printing the credential.

#### Who owns the `prod-db-admin` schedule

| Role | Responsibility |
|---|---|
| **Security team / DevOps lead** | Owns `prod-db-admin` schedule; only people who can add/remove members |
| **Engineering manager** | Nominates engineers for rotation; cannot self-assign |
| **Engineers** | Cannot add themselves; cannot self-escalate |
| **Quarterly access review** | Audits schedule membership vs. active employees |

#### Security gates

| Gate | Status | Enforced by |
|---|---|---|
| Access window tied to PagerDuty schedule | ✅ GHA cron already runs hourly | On-call schedule owners |
| Okta/IAM token not on developer laptops | ✅ GHA secret / AWS SSO session | Platform team / AWS |
| MFA required for prod SSO session | ✅ `aws sso login --profile prod` | AWS IAM Identity Center |
| Network restricted to Twingate IPs (MongoDB) | ⚠️ Needs Atlas IP list update | Infra/Pulumi |
| Access auto-revoked at shift end | ✅ (hourly cron removes from group) | Automatic |
| Full audit trail | ✅ GHA log + Atlas audit + CloudTrail → Datadog | Passive |

#### Planned maintenance (outside on-call schedule)

A PR to temporarily add the engineer to the `prod-db-admin` PagerDuty schedule, approved by Security/DevOps lead. The hourly cron picks it up automatically. No bespoke tooling needed.

### Quarterly access review

A runbook (Story #70395) will enumerate:
- All Atlas users via `db.getUsers()` across all projects
- All RDS roles via `SELECT usename, usecreatedb, usesuper, last_auth FROM pg_user JOIN pg_stat_activity USING (usename)`
- All current `sentra-db-*` Okta group members vs. active employees
- Any user not tied to an active service secret or SSO group → immediate revocation

---

## 6. Auditing & Alerting

### MongoDB Atlas

- Enable **Atlas Audit Logging** on the `general` cluster for all projects (prod + staging)
- Audit filter: `{ atype: { $in: ["authenticate", "createUser", "dropUser", "grantRolesToUser", "dropCollection", "dropDatabase"] } }`
- Stream to **Datadog** via the existing `ThirdPartyIntegration` resource in `mongodb.py`

### RDS / PostgreSQL

- Enable `pgaudit` extension on all prod RDS instances (log DDL + privilege changes)
- Ship logs: CloudWatch Logs → Datadog log forwarder (already deployed)

### Alerts (both)

| Trigger | Severity | Channel |
|---|---|---|
| `atlasAdmin` role authenticated | P1 | PagerDuty |
| `GRANT`/`REVOKE` on prod database | P2 | `#db-security-alerts` Slack |
| `DROP TABLE` / `DROP DATABASE` | P1 | PagerDuty |
| `permission denied` errors > 10/min from a single service | P2 | `#db-security-alerts` |
| Break-glass secret accessed | P1 | PagerDuty + `#oncall` |
| Service authenticating with master creds (post-migration) | P1 | PagerDuty |

---

## 7. Migration Strategy

### Guiding principle: parallel-role approach

1. Create new scoped role alongside the existing admin credential (no service downtime)
2. Update service deployment to reference new secret
3. Deploy to staging → verify no `permission denied` errors for 48h
4. Deploy to prod → verify
5. Revoke old credential / remove from secret

### Rollout order (lowest blast radius first)

| Phase | Services | Rationale |
|---|---|---|
| 1 | `data-feed-service`, `adr-mcp-server`, `monitoring-service` | Low write volume, simple schema |
| 2 | `scan-flow-service`, `integrations-api`, `backoffice-service` | Medium complexity |
| 3 | `api-service`, `access-service`, `organization-management-service` | Core services, highest traffic |
| 4 | `debezium-kafka-connector` (RDS CDC) | Needs `REPLICATION` role, replication slot recreation |
| 5 | `connectors-service`, `luxus-service`, `debezium-mongodb-source-connector` | MongoDB consumers |
| 6 | `temporal`, `dagster` | Stateful workloads, most complex rollback |

### Rollback

Each service keeps the old admin secret available for 2 weeks post-cutover. Rollback = revert the `values.prod.yaml` change in the service repo.

---

## 8. Success Metrics

| Metric | Baseline (today) | Target |
|---|---|---|
| Services using admin-equivalent DB role | 100% | 0% (except break-glass) |
| Distinct DB users in prod | 2 (admin + master) | ≥ 20 (one per service) |
| Services with automated credential rotation | 0% | 100% |
| Human access requiring stored password | 100% | 0% (SSO/IAM auth only) |
| Mean time to revoke a single service's DB access | hours (manual) | < 5 min (CRD delete or Pulumi run) |

---

## 9. Open Questions

- [ ] Does `luxus-service` write to the same org databases as `connectors-service`, or only read? (affects whether they can share a role or need separate ones)
- [ ] Which migration framework does each RDS service use? (Alembic confirmed for connectors-service — others need inventory from Story #70387)
- [x] ~~RDS IAM auth: confirm all prod RDS instances have `iam_database_authentication_enabled = true`~~ — **Confirmed.** Already set on `application-v2`, `dagster-v2`, `access-service` in `Pulumi.prod.yaml`.
- [x] ~~Atlas `federation.py` — Identity Federation or Data Federation?~~ — **Confirmed Data Federation** (S3/query routing). Atlas Identity Federation (Compass SSO) is a separate unbuilt feature.
- [ ] **Decision required:** Pursue Atlas Identity Federation (Compass SSO via Okta SAML — Section 5.2 Option A) or Secrets Manager scoped credentials (Option B, unblocked)? Option B can ship now; Option A needs Atlas org-admin + Okta admin coordination.
- [ ] **Action required (Okta admin):** Does `OKTA_SENTRASEC_ADMIN_TOKEN` have `groups:manage` scope? If not, a new token must be issued before `okta_assign_db_admins.py` can be built. If Okta groups are not available, fall back to IAM Identity Center permission sets for RDS and dedicated Atlas user for MongoDB (Section 5.3 alternate path).
- [ ] **Action required (Okta admin):** Does `sentra-db-admins` Okta group exist? Trivial to create; needs Okta admin console access.
- [ ] **Governance decision required:** Who owns the `prod-db-admin` PagerDuty schedule — Security team or DevOps lead?
- [ ] **Governance decision required:** Which engineers are eligible for the `prod-db-admin` rotation?
- [ ] Confirm `prod-db-admin` PagerDuty schedule ID before building `okta_assign_db_admins.py`.

---

## 10. Acceptance Criteria

- [ ] This RFC reviewed and approved by DevOps lead
- [ ] This RFC reviewed and approved by Security
- [ ] Stories [#70386](https://app.shortcut.com/sentra/story/70386) (MongoDB discovery) and [#70387](https://app.shortcut.com/sentra/story/70387) (RDS discovery) outputs incorporated into Section 2 before IaC work begins
- [ ] Each downstream story (#70388–#70395) has acceptance criteria derived from this document
- [ ] RFC merged to `docs/` repo on `main`

---

## 11. Local Developer Access

### 11.1 Current state (the problem)

Local dev runs in two modes today:

| Mode | Env file | DB target | Credentials |
|---|---|---|---|
| Fully local | `.env.local` | Docker Compose on `127.0.0.1` | `sentra/sentra` (dummy, safe ✓) |
| Staging connect | `.env.local.staging` | Real Atlas staging cluster | `MONGO_USER=admin` hardcoded ⚠️ |
| Prod debug | `.env.local.prod` | Real Atlas **prod** cluster | `MONGO_USER=admin` hardcoded 🚨 |

No secrets manager is involved in staging/prod modes. Credentials live in `.env.*` files on developer laptops with no expiry, no audit trail, and no revocation path. A stolen laptop or leaked dotfile gives permanent admin access to all customer data.

### 11.2 Target model

#### RDS — ✅ Confirmed possible, unblocked

`aws sso login --profile staging` is already a daily developer habit, and `iam_database_authentication_enabled: true` is already set on all target prod RDS instances (`Pulumi.prod.yaml`). Developers get a 15-min IAM DB auth token — no stored password, no credential on the laptop.

```
aws sso login --profile staging    ← already done daily
      │
      ▼
aws rds generate-db-auth-token     ← 15-min token, tied to SSO session
      │
      ▼
psql / service connects as dev_rds_staging_ro
```

#### MongoDB — ⚠️ SSO path is an assumption; alternate path is confirmed possible

**Target (assumption):** Atlas Identity Federation with Okta — developer logs into Compass via SSO, no password stored. Technically possible (Atlas supports it, Okta is the org IdP for ArgoCD already) but not yet configured. Requires Atlas org-admin + Okta admin coordination.

**Alternate (confirmed possible now):** Scoped Atlas user `dev_staging_rw` with password stored in Secrets Manager. Developer fetches it via `task dev:pull-secrets` using their existing SSO session — IAM policy limits access to `dev/mongo-*` secrets only, never `prod/*`. Password rotates every 90 days via Atlas Operator; developer never stores it permanently.

```
aws sso login --profile staging    ← existing habit
      │
      ▼  (IAM session proves identity — no password distributed)
aws secretsmanager get-secret-value --secret-id dev/mongo-staging-dev-rw
      │
      ▼
MONGO_USER=dev_staging_rw  MONGO_PASSWORD=<rotated 90d>
written to .env.local.staging.generated  (gitignored)
```

### 11.3 Developer workflow — what you actually type

#### Mode 1 — Full local stack (most common, zero changes)

```bash
# Spin up local infra (MongoDB :27017, Postgres :5432, Kafka, Redis)
docker compose up -d

# Run your service — identical to today
task run                    # loads .env.local
                            # MONGO_HOSTNAME=127.0.0.1 / sentra:sentra
                            # POSTGRES_HOSTNAME=localhost / sentra:sentra
```

**Nothing changes here.** `.env.local` with dummy creds stays as-is.

#### Mode 2 — Connect to staging DB (debugging real data)

```bash
# Step 1 — already part of your morning routine
aws sso login --profile staging         # Okta browser popup, once per day

# Step 2 — new, replaces manually editing .env.local.staging
task dev:pull-secrets ENV=staging
# ✓ MongoDB:  fetched dev_staging_rw password → your Okta group proves SM access
# ✓ Postgres: generated 15-min RDS IAM token → no password ever stored
# ✓ Written to .env.local.staging.generated  (gitignored, never committed)

# Step 3 — run service against staging
task run:staging                        # loads .env.local.staging.generated
```

`task dev:pull-secrets` under the hood:

```
aws sso login session (staging)
  ├── secretsmanager:GetSecretValue  dev/mongo-staging-dev-rw
  │     → MONGO_USER=dev_staging_rw
  │       MONGO_PASSWORD=<rotated every 90d, developer never sees or stores it permanently>
  │
  └── rds:generate-db-auth-token
        → POSTGRES_PASSWORD=<15-min token, useless after expiry>

writes → .env.local.staging.generated  (gitignored)
```

The IAM policy on the developer's staging SSO role allows `secretsmanager:GetSecretValue` on `dev/mongo-*` and `dev/rds-*` only — not on `prod/*` secrets.

#### Mode 3 — Read prod data (incident debugging, read-only)

`.env.local.prod` **does not exist** in the target state.

```bash
aws sso login --profile prod            # requires MFA

# MongoDB — Compass or mongosh, browser SSO
mongosh "mongodb+srv://general-pl-0.0bjrm.mongodb.net/" \
  --username oren@sentra.io \
  --authenticationMechanism MONGODB-OIDC
# Access: human_analytics_ro — read-only on org_* databases
# Every login triggers Atlas audit log → Datadog event

# Postgres prod — 15-min token, read-only
task dev:pull-secrets ENV=prod-ro       # generates .env.local.prod-ro.generated
task run:prod-ro
```

#### Mode 4 — Break-glass admin (on-call only)

```bash
# Requires sentra-db-admins Okta group + MFA
aws sso login --profile prod

# MongoDB: atlasAdmin via SSO — auto-triggers P1 Datadog alert
# RDS: assume prod-db-break-glass IAM role (manager approval required)
#      generates 15-min token, all queries logged via pgaudit
```

### 11.4 Taskfile tasks to add to every service

```yaml
tasks:
  dev:pull-secrets:
    desc: "Pull scoped DB credentials for ENV (staging|prod-ro). Requires: aws sso login --profile {{.ENV}}"
    requires:
      vars: [ENV]
    cmds:
      - |
        # MongoDB — fetch scoped password via SSO session
        aws secretsmanager get-secret-value \
          --profile {{.ENV}} \
          --secret-id dev/mongo-{{.ENV}}-dev-rw \
          --query SecretString --output text \
        | python3 -c "
        import sys, json; s = json.load(sys.stdin)
        print(f'MONGO_HOSTNAME={s[\"mongoHostname\"]}')
        print(f'MONGO_USER={s[\"mongoUser\"]}')
        print(f'MONGO_PASSWORD={s[\"mongoPassword\"]}')
        print('MONGO_SRV=TRUE')
        print('MONGO_SSL=TRUE')
        " > .env.local.{{.ENV}}.generated
      - |
        # Postgres — IAM DB auth token (15 min expiry)
        RDS_HOST=$(aws ssm get-parameter --profile {{.ENV}} \
          --name /sentra/{{.ENV}}/rds/application/hostname \
          --query Parameter.Value --output text)
        TOKEN=$(aws rds generate-db-auth-token \
          --profile {{.ENV}} \
          --hostname $RDS_HOST --port 5432 \
          --username dev_rds_staging_ro)
        echo "POSTGRES_HOSTNAME=$RDS_HOST" >> .env.local.{{.ENV}}.generated
        echo "POSTGRES_USER=dev_rds_staging_ro" >> .env.local.{{.ENV}}.generated
        echo "POSTGRES_PASSWORD=$TOKEN" >> .env.local.{{.ENV}}.generated
        echo "POSTGRES_PORT=5432" >> .env.local.{{.ENV}}.generated
      - echo "✓ .env.local.{{.ENV}}.generated ready (RDS token valid ~15min)"

  run:staging:
    desc: Run service connected to staging DBs
    deps: [install]
    dotenv: ['.env.local.staging.generated']
    cmds:
      - uv run uvicorn app.main:app --host 0.0.0.0 --port 8086 --reload
```

### 11.5 `.gitignore` additions (all service repos)

```
.env.local.*.generated
.env.local.prod
```

`.env.local.prod` must also be **purged from git history** in `sentra-connectors-service` — immediate action, independent of the rest of the epic.

### 11.6 Comparison: today vs. target

| | Today | After RFC |
|---|---|---|
| Staging credential on laptop | `admin` password, never rotates, never expires | 90-day rotated password fetched on demand; 15-min RDS token |
| Laptop stolen | Attacker has permanent prod admin access 🚨 | SSO session gone — credentials useless |
| Dev offboarded | Ops must rotate shared password + notify all teams | Remove from Okta group → all access revoked instantly |
| Prod access | `.env.local.prod` with admin — always available | Explicit SSO + MFA, read-only by default, every access logged |
| Audit trail | None | Every staging/prod DB connection logged to Datadog |

### 11.7 Okta groups required

| Group | Atlas access | RDS access |
|---|---|---|
| `sentra-db-developers` | `dev_staging_rw` on staging | `rds-db:connect` as `dev_rds_staging_ro` on staging |
| `sentra-db-readonly` | `human_analytics_ro` on prod | `rds-db:connect` as `human_rds_ro` on prod |
| `sentra-db-oncall` | `human_oncall_ro` on prod | `rds-db:connect` as `human_rds_ro` on prod |
| `sentra-db-admins` | `break_glass_admin` on all projects | `prod-db-break-glass` IAM role (MFA required) |

### 11.8 Revocation

| Event | Effect |
|---|---|
| Developer removed from Okta group | Atlas access revoked at next SAML session expiry |
| Developer offboarded from Okta | All DB access revoked immediately across both databases |
| RDS token stolen | Expires in 15 min, cannot be renewed without a valid SSO session |
| Break-glass used | P1 Datadog alert fires; IAM role can be revoked in seconds |

### 11.9 What needs to be built

| Task | Where | Immediate? |
|---|---|---|
| Delete `.env.local.prod`, purge git history | `sentra-connectors-service` | **Yes — do now** |
| Add `.env.local.*.generated` to `.gitignore` | All service repos | **Yes — do now** |
| Configure Okta as Atlas SAML IdP | Atlas Org Federation Management | Story #70393 |
| Create Okta groups and assign engineers | Okta admin console | Story #70393 |
| Atlas role mappings via `mongodbatlas.OrgFederationSettings` | Pulumi | Story #70393 |
| `AtlasDatabaseUser` CRDs for human roles | Atlas Operator CRDs | Story #70393 |
| ~~Enable RDS IAM auth on prod instances~~ | ~~Pulumi~~ | Already enabled ✅ (`Pulumi.prod.yaml`) |
| Enable RDS IAM auth on **staging** instances | `Pulumi.staging.yaml` | Story #70390 |
| `dev_rds_staging_ro` PostgreSQL role + SM secret | Pulumi | Story #70390 |
| IAM Identity Center Permission Sets for Okta groups | Pulumi or AWS console | Story #70393 |
| `task dev:pull-secrets` + `task run:staging` | Each service's `Taskfile.yml` | Story #70393 |
---

## Appendix: Infrastructure References

| Component | Location |
|---|---|
| Atlas Pulumi provisioning | `sentra-infrastructure/mongodb_provision/mongodb.py` |
| RDS Pulumi provisioning | `sentra-infrastructure/postgresql_provision/provision.py` |
| Prod MongoDB stack config | `sentra-infrastructure/Pulumi.prod-mongodb-provision.yaml` |
| Prod RDS stack config | `sentra-infrastructure/Pulumi.prod-postgresql-provision.yaml` |
| Atlas Operator ArgoCD ApplicationSet | `argocd/infra/mongodb-operator_applicationset.yaml` |
| Atlas Operator Helm values | `argocd/infra/values/mongodb-operator_values.yaml` |
| Connectors-service prod K8s values | `sentra-connectors-service/kubernetes/connectors-service/values.prod.yaml` |
| Data-feed prod K8s values | `sentra-data-feed/kubernetes/data-feed/values.prod.yaml` |
| PagerDuty on-call fetcher (existing) | `sentra-infrastructure/scripts/pager_duty_get_on_callers.py` |
| PagerDuty → Slack group updater (existing, pattern for Okta) | `sentra-infrastructure/scripts/slack_assign_on_call_groups.py` |
| Okta API client (existing) | `sentra-infrastructure/scripts/okta_user_sync.py` |
