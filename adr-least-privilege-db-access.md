# ADR-001: Least-Privilege Access for MongoDB Atlas & RDS

**Status:** Accepted  
**Date:** 2026-05-17  
**Story:** [#70385](https://app.shortcut.com/sentra/story/70385)  
**Epic:** [#70383](https://app.shortcut.com/sentra/epic/70383)  
**RFC:** [rfc-least-privilege-db-access.md](./rfc-least-privilege-db-access.md)

---

## Stakeholders

| Stakeholder | Role | Viewpoint |
|---|---|---|
| Platform Engineering / DevOps lead | **Decision owner** — designs and implements | Architecture, Operations |
| Security team | **Approver** — threat model, break-glass governance | Security, Compliance |
| Engineering Manager (R&D) | **Consulted** — developer workflow, on-call rotation eligibility | Developer Experience |
| Service owners (Application, Access, Dagster) | **Consulted** — migration validation, no-regression sign-off | Operations |
| Data Engineering lead | **Consulted** — Dagster / data pipelines (highest rollback risk) | Operations |
| Compliance / SOC2 owner | **Consulted** — audit evidence, CC6.x controls | Compliance |
| On-call engineers | **Informed** — break-glass flow changes incident response | Developer Experience |

---

## Context

Every Sentra service and human in production currently shares one of two credentials:

- **MongoDB Atlas:** single `admin` user with `atlasAdmin` role, shared by all services and all engineers
- **RDS / PostgreSQL:** master RDS credentials distributed verbatim to every service secret (~25 services)

A single compromised service pod has full admin access to all customer data across all organisations. There is no per-service audit trail, no automated rotation, and no revocation path shorter than a full credential rotation coordinated across all teams simultaneously.

---

## Decision Drivers

| Driver | Weight |
|---|---|
| Blast radius reduction — compromised pod must not reach all customer data | Critical |
| Audit trail — each DB operation must be attributable to a specific service or person | Critical |
| Automated revocation — offboarding or service removal must take effect in < 5 min | High |
| Zero-downtime migration — no service interruption during cutover | High |
| Developer experience — local dev and incident response workflows must not degrade | High |
| SOC2 CC6.1/CC6.2/CC6.3 — access control evidence for auditors | High |
| IaC consistency — credentials managed as code, not manual console operations | Medium |

---

## Options Considered

### Option 1 — Per-service scoped credentials via Atlas Operator + Pulumi (chosen)

Create dedicated database roles per service with minimum required privileges. Deliver credentials via Atlas Kubernetes Operator (MongoDB) and Pulumi + ESO (RDS). Human access via AWS SSO IAM tokens (RDS) and Okta-gated Secrets Manager (MongoDB).

### Option 2 — Shared credentials with IP restriction only

Keep shared credentials but restrict access to known Twingate IPs. Simpler, no migration risk.

**Rejected:** Doesn't address blast radius — a compromised pod inside the network still has full admin access. Fails SOC2 CC6.2 (least privilege).

### Option 3 — External secrets vault (HashiCorp Vault or AWS Secrets Manager dynamic secrets)

Replace all static credentials with dynamic secrets generated on connection.

**Rejected for v1:** Requires Vault operator installation and agent injection across all services. High operational complexity for teams unfamiliar with Vault. ESO + Pulumi-managed Secrets Manager achieves 80% of the benefit with existing tooling. Can be adopted as v2 on top of this foundation.

### Option 4 — Full SSO federation for all DB access (Okta → Atlas SAML + RDS IAM)

No stored credentials anywhere — all access via SAML federation to Atlas and IAM DB auth tokens for RDS.

**Partially adopted:** RDS IAM auth is confirmed available and will be used for human access. Atlas Identity Federation (Compass SSO) is technically possible but not yet configured — deferred to a follow-up story. Service-to-service connections still use scoped passwords (Atlas OIDC workload identity for services is not yet supported at the required scale).

### Option 5 — MongoDB Workload Identity Federation via OIDC/IRSA (deferred to v2)

Eliminate username/password entirely for service-to-MongoDB connections. Services authenticate to Atlas using their AWS IAM identity (IRSA) — the same mechanism used for RDS in v1. No K8s Secret, no stored password, no rotation events.

**How it works:**

```mermaid
flowchart LR
    subgraph cluster["prod cluster"]
        POD["service pod\nIRSA role annotated on SA\nauthMechanism=MONGODB-OIDC"]
    end

    subgraph aws["AWS"]
        OIDC["EKS OIDC Provider\n(already exists per cluster)"]
        IAM["IAM Role\nconnectors-prod-role\ntrusted by pod SA"]
    end

    subgraph atlas["MongoDB Atlas"]
        IDP["Atlas OIDC Identity Provider\nAWS IAM trusted issuer"]
        USER["AtlasDatabaseUser\noidcAuthType: IDP_GROUP\nexternalId: arn:aws:iam::<account>:role/connectors-prod-role"]
    end

    POD -->|sts:AssumeRoleWithWebIdentity| IAM
    IAM -->|JWT token| OIDC
    OIDC -->|OIDC assertion| IDP
    IDP -->|validates IAM role ARN| USER
    POD -->|connects with MONGODB-OIDC, no password| atlas
```

**What's needed vs v1:**

| | v1 (ESO + password) | v2 (OIDC) |
|---|---|---|
| K8s Secret with password | Required | Not needed |
| Atlas Operator CRD | `passwordSecretRef` | `oidcAuthType: IDP_GROUP` + IAM role ARN |
| Rotation events | Yes (90d, Reloader restart) | No — IAM token refresh is implicit |
| App code change | None | **Yes** — connection string must use `authMechanism=MONGODB-OIDC` |
| MongoDB driver version | Any | Must support OIDC (PyMongo ≥ 4.7, Node.js driver ≥ 6.3) |
| Atlas project config | Standard | Must configure AWS IAM as OIDC IdP in Atlas Org Federation |
| IRSA role | Not needed for MongoDB | Reuses same IRSA role already created for RDS |

**Why deferred:**
- Requires driver version audit and upgrade across all services (NestJS, FastAPI, Python workers)
- Requires code change in every service's MongoDB connection initialisation — not a config-only change
- Atlas OIDC IdP configuration requires Atlas org-admin coordination (same blocker as human SSO)
- v1 already achieves scoped, rotated, auditable credentials — OIDC is a security improvement, not a security requirement for v1

**Upgrade path from v1 to v2 is non-destructive:**
1. Upgrade MongoDB driver in service
2. Change connection string `authMechanism` to `MONGODB-OIDC`
3. Replace `AtlasDatabaseUser` CRD `passwordSecretRef` with `oidcAuthType` + IAM role
4. Remove ESO `ExternalSecret` for that service's MongoDB password
5. Deploy — Atlas Operator updates the user type; service authenticates via OIDC

Services can migrate one at a time. No cluster-wide cutover required.

---

## Decision

**Adopt Option 1** — per-service scoped credentials with a unified ESO-based secret delivery plane for both MongoDB and RDS. Management plane differs per database (Atlas Operator for MongoDB, Pulumi for RDS) but delivery to pods is identical: K8s Secret → env vars. Break-glass orchestrated by extending the existing PagerDuty → GHA cron workflow.

### Key architectural decisions within Option 1

| Decision | Choice | Rationale |
|---|---|---|
| MongoDB user creation | Centralized in infra/argocd repo | Security gate: DB privilege PRs reviewed separately from service code; CODEOWNERS enforced |
| MongoDB password source | ESO pulls from Secrets Manager → K8s Secret; Atlas Operator reads same secret | Single secret, two consumers — no duplication, no chicken-and-egg |
| MongoDB username | Fixed deterministic prefix `<service>_<env>_<role>` | Never rotates; service config is static; only password changes |
| Password rotation propagation | Reloader (deployed cluster-wide) watches K8s Secret → rolling restart | Already deployed to all clusters; zero new tooling |
| Per-service Helm user creation | **Rejected** | Creates circular dependency: Helm needs password to exist before install, but password provisioning requires a centralized step anyway. Privilege changes bundled into service deploys evade security review. |
| MongoDB service auth | Username + password (K8s Secret) | Atlas has no OIDC/IRSA equivalent for service connections. Asymmetry with RDS is acceptable — password is scoped, rotated, never on laptops. |
| RDS service auth | IRSA + RDS Proxy | Proxy handles 15-min token refresh transparently; no app code changes; no stored password |

---

## Deployment Patterns

### Pattern A — MongoDB Atlas credential delivery (approved)

```mermaid
flowchart TD
    subgraph infra["infra repo (gated PR — CODEOWNERS on atlas/users/)"]
        PULUMI["Pulumi: generates password\nstores → prod/mongo-connectors-password"]
        CRD["AtlasDatabaseUser CRD\nargocd/infra/manifests/atlas/users/prod/connectors.yaml\nusername: connectors_prod_rw (fixed)\npasswordSecretRef: atlas-connectors-password"]
    end

    subgraph aws["AWS Secrets Manager"]
        SM["prod/mongo-connectors-password\n{password: ...}"]
    end

    subgraph cluster["prod / staging cluster"]
        ESO["External Secrets Operator\nsyncs SM → K8s Secret"]
        SECRET["K8s Secret\natlas-connectors-password\n{password: ...}"]
        OP["Atlas Operator\nreads passwordSecretRef"]
        POD["connectors-service pod\nMONGO_USER=connectors_prod_rw (values.yaml)\nMONGO_PASSWORD=<from secret>"]
        RELOAD["Reloader\nwatches secret → rolling restart on change"]
    end

    subgraph atlas["MongoDB Atlas"]
        USER["AtlasDatabaseUser\nconnectors_prod_rw\nreadWrite on organization_*"]
    end

    PULUMI -->|creates| SM
    SM -->|ESO syncs| ESO
    ESO --> SECRET
    CRD -->|ArgoCD sync| OP
    OP -->|reads password| SECRET
    OP -->|creates/updates user| USER
    SECRET -->|mounted as env var| POD
    SECRET -->|secret changed| RELOAD
    RELOAD -->|rolling restart| POD
    POD -->|authenticates as connectors_prod_rw| USER
```

**Rotation flow (90-day cycle):**
```
SM rotates password
  └─▶ ESO syncs new value → K8s Secret updated
        ├─▶ Atlas Operator reconciles → updates Atlas user password
        └─▶ Reloader detects secret change → rolling restart
              └─▶ pod starts with new password ✅ zero manual steps
```

### Pattern B — RDS credential delivery (approved)

Services connect via **IRSA + RDS Proxy**. No stored password in the pod — the proxy handles IAM token refresh transparently.

```mermaid
flowchart TD
    subgraph infra["infra repo (Pulumi)"]
        PROV["postgresql_provision/provision.py\ncreates: Role + Grant per service\nenables: iam_database_authentication"]
        SA["KubernetesServiceAccount\nIRSA role with rds-db:connect policy\ntrusted to service k8s SA"]
    end

    subgraph aws["AWS"]
        PROXY["RDS Proxy\nIAM auth enabled\nhandles token refresh (15-min tokens)"]
        RDS["RDS PostgreSQL\nconnectors_app role\niam_database_authentication_enabled: true ✅"]
        IAM["IAM Identity\nservice SA → IRSA role → rds-db:connect"]
    end

    subgraph cluster["prod cluster"]
        POD["connectors-service pod\nPOSTGRES_HOST=rds-proxy-endpoint\nPOSTGRES_USER=connectors_app\nno password — IAM auth"]
    end

    PROV -->|creates role + grant| RDS
    PROV -->|creates proxy| PROXY
    SA -->|annotates k8s SA with role ARN| POD
    POD -->|assumes IRSA role via OIDC| IAM
    IAM -->|rds-db:connect| PROXY
    PROXY -->|manages token rotation| RDS
    POD -->|connects via proxy| PROXY
```

**Key properties:**
- `iam_database_authentication_enabled: true` already set on all prod RDS instances ✅
- `KubernetesServiceAccount` component (`eks_provision/service_account.py`) already builds IRSA roles ✅
- RDS Proxy removes token refresh complexity from application code
- No password in any K8s Secret, Secrets Manager, or env var for service connections

### Pattern C — Break-glass access delivery (PagerDuty → Okta → Atlas/RDS)

```mermaid
flowchart TD
    subgraph pd["PagerDuty"]
        SCHED["prod-db-admin schedule\nmanaged via UI by Security/DevOps"]
    end

    subgraph gha["GitHub Actions (sentra-infrastructure)"]
        CRON["on_callers.yaml\ncron: every hour"]
        STEP1["step 1: get-pagerduty-on-callers\non_callers.json"]
        STEP2["step 2: set-slack-on-callers ✅"]
        STEP3["step 3: set-okta-db-admins ⚠️ to build"]
    end

    subgraph okta["Okta (sentrasec.okta.com)"]
        GROUP["sentra-db-admins group"]
    end

    subgraph access["On-call engineer access"]
        ATLAS["Atlas: atlasAdmin via SAML\n(sentra-db-admins → break_glass_admin role)"]
        RDS_OP["RDS: 15-min IAM token\naws rds generate-db-auth-token"]
    end

    SCHED -->|polled hourly| CRON
    CRON --> STEP1
    STEP1 --> STEP2
    STEP1 --> STEP3
    STEP3 -->|add/remove user| GROUP
    GROUP -->|SAML federation| ATLAS
    GROUP -->|IAM Identity Center permission set| RDS_OP
```

### Pattern D — Local developer access

```mermaid
flowchart LR
    subgraph dev["Developer laptop"]
        SSO["aws sso login --profile staging\n(existing daily habit)"]
        TASK["task dev:pull-secrets ENV=staging"]
        ENV[".env.local.staging.generated\n(gitignored, never committed)"]
        SVC["service process\n(task run:staging)"]
    end

    subgraph aws["AWS Staging"]
        SM_MONGO["Secrets Manager\ndev/mongo-staging-dev-rw\n(IAM policy: staging SSO role only)"]
        RDS_TOKEN["RDS IAM auth token\n15-min expiry"]
    end

    subgraph dbs["Staging DBs"]
        ATLAS_STG["Atlas staging cluster\ndev_staging_rw role"]
        RDS_STG["RDS staging\ndev_rds_staging_ro role"]
    end

    SSO --> TASK
    TASK -->|secretsmanager:GetSecretValue| SM_MONGO
    TASK -->|rds:GenerateDbAuthToken| RDS_TOKEN
    SM_MONGO --> ENV
    RDS_TOKEN --> ENV
    ENV --> SVC
    SVC --> ATLAS_STG
    SVC --> RDS_STG
```

---

## Security Access Flows

### Flow 1 — Service-to-database (runtime)

```mermaid
sequenceDiagram
    participant Pod as Service Pod
    participant K8s as K8s Secret
    participant Atlas as MongoDB Atlas
    participant RDS as RDS PostgreSQL

    Note over Pod,K8s: At startup — credentials already present via Reflector/ESO
    Pod->>K8s: Read MONGO_USER / MONGO_PASSWORD
    K8s-->>Pod: connectors_prod_rw / <scoped password>
    Pod->>Atlas: authenticate as connectors_prod_rw
    Atlas-->>Pod: granted readWrite on organization_* only
    Note over Atlas: atlasAdmin not reachable from this credential

    Pod->>K8s: Read POSTGRES_USER / POSTGRES_PASSWORD
    K8s-->>Pod: connectors_app / <scoped password>
    Pod->>RDS: connect as connectors_app
    RDS-->>Pod: granted SELECT/INSERT/UPDATE/DELETE on owned tables only
    Note over RDS: No CREATE/DROP/ALTER — migration role separate
```

### Flow 2 — Human read-only access (engineer debugging staging)

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant SSO as AWS SSO (IAM Identity Center)
    participant SM as Secrets Manager
    participant Atlas as Atlas (staging)
    participant RDS as RDS (staging)

    Dev->>SSO: aws sso login --profile staging
    SSO-->>Dev: IAM session (Okta MFA, once per day)

    Note over Dev,SM: MongoDB — scoped Atlas user via SM
    Dev->>SM: get-secret-value dev/mongo-staging-dev-rw
    Note over SM: IAM policy allows staging SSO role → dev/mongo-* only
    SM-->>Dev: MONGO_USER=dev_staging_rw, MONGO_PASSWORD=<90d rotated>
    Dev->>Atlas: connect as dev_staging_rw
    Atlas-->>Dev: readWrite on organization_* (staging only)

    Note over Dev,RDS: RDS — IAM DB auth token
    Dev->>RDS: generate-db-auth-token (dev_rds_staging_ro)
    RDS-->>Dev: 15-min token
    Dev->>RDS: connect with token
    RDS-->>Dev: SELECT only on staging schemas
```

### Flow 3 — Break-glass access (on-call engineer, prod incident)

```mermaid
sequenceDiagram
    participant PD as PagerDuty
    participant GHA as GitHub Actions (hourly)
    participant Okta as Okta API
    participant Eng as On-call Engineer
    participant Atlas as MongoDB Atlas (prod)
    participant RDS as RDS (prod)

    Note over PD,GHA: Shift starts on prod-db-admin schedule
    PD-->>GHA: polled — engineer assigned to prod-db-admin
    GHA->>Okta: add engineer to sentra-db-admins group
    Okta-->>GHA: 200 OK
    GHA->>GHA: POST #db-security-alerts — access granted

    Note over Eng,Atlas: Engineer connects (within 1h of shift start)
    Eng->>Atlas: mongosh --authenticationMechanism MONGODB-OIDC
    Atlas->>Okta: SAML assertion — is engineer in sentra-db-admins?
    Okta-->>Atlas: yes
    Atlas-->>Eng: atlasAdmin role granted
    Note over Atlas: P1 Datadog alert fires on atlasAdmin auth

    Note over Eng,RDS: RDS break-glass
    Eng->>Eng: aws sso login --profile prod (Okta MFA)
    Eng->>RDS: generate-db-auth-token --username break_glass_admin
    RDS-->>Eng: 15-min token
    Eng->>RDS: connect as break_glass_admin
    Note over RDS: All queries logged via pgaudit → Datadog

    Note over PD,GHA: Shift ends
    PD-->>GHA: polled — engineer removed from prod-db-admin
    GHA->>Okta: remove engineer from sentra-db-admins
    GHA->>GHA: POST #db-security-alerts — access revoked
    Note over Atlas: Next SAML session attempt denied
```

### Flow 4 — Credential rotation (automated)

```mermaid
flowchart LR
    subgraph mongo["MongoDB (90-day cycle)"]
        CRD_UPDATE["AtlasDatabaseUser CRD\npasswordSecretRef updated"]
        ATLAS_OP["Atlas Operator\nrotates Atlas user password"]
        K8S_SECRET["K8s Secret updated\nReflector re-mirrors to all clusters"]
        POD_RESTART["Rolling restart triggered\nby secret hash annotation"]
    end

    subgraph rds["RDS (90-day cycle)"]
        SM_ROTATION["Secrets Manager\nautomatic rotation enabled\nLambda rotator"]
        SM_UPDATE["New password written\nto prod/rds-<service>-v2"]
        ESO_SYNC["ESO re-syncs\nK8s Secret updated"]
        POD_RESTART_RDS["Rolling restart triggered"]
    end

    CRD_UPDATE --> ATLAS_OP --> K8S_SECRET --> POD_RESTART
    SM_ROTATION --> SM_UPDATE --> ESO_SYNC --> POD_RESTART_RDS
```

---

## Viewpoint Analysis

### Security viewpoint

| Concern | Before | After |
|---|---|---|
| Compromised pod blast radius | Full admin on all customer data | Read/write on owned schema only |
| Credential on developer laptop | `admin` password, never expires | 90-day rotated secret fetched on demand; 15-min RDS token |
| Stolen laptop | Permanent prod admin access | SSO session invalid — credentials useless |
| Engineer offboarded | Manual rotation of shared secret | Okta group removal → all access revoked immediately |
| Audit trail | None | Per-service Atlas audit + pgaudit + CloudTrail → Datadog |
| Break-glass accountability | Implicit (anyone with the secret) | Explicit: PD schedule → Okta group → P1 alert on use |

**Threat model gaps addressed:**
- Lateral movement from compromised pod: ✅ contained to owned schema
- Credential stuffing from leaked `.env` file: ✅ no password on laptop in target state
- Insider threat: ✅ per-operation audit trail; break-glass requires schedule membership

### Developer experience viewpoint

| Scenario | Before | After |
|---|---|---|
| Local dev (most common) | `docker compose up` + `.env.local` | Identical — no change |
| Connect to staging DB | Edit `.env.local.staging` with hardcoded admin | `aws sso login` (already done) + `task dev:pull-secrets` |
| Debug prod (read-only) | `.env.local.prod` with prod admin 🚨 | `aws sso login --profile prod` + read-only Secrets Manager fetch |
| Break-glass (on-call) | Use the same shared admin credential | SSO + automatically granted via PD schedule (≤1h lag) |

**Friction delta:** One new command (`task dev:pull-secrets`) replaces manually copying credentials from Notion/1Password. Net improvement.

### Operations viewpoint

| Concern | Mitigation |
|---|---|
| Migration downtime | Parallel-role approach — new role created alongside old; service updated to new secret; old secret kept 2 weeks for rollback |
| Permission error storm | Staging validation for 48h before prod cutover per service |
| Rotation causing downtime | Atlas Operator + ESO update secrets in-place; rolling restart on hash change |
| Runbook for break-glass | Story #70395 — quarterly access review runbook covers emergency procedures |
| Phase 6 (Temporal/Dagster) risk | Last in rollout order; stateful workloads require schema ownership review before migration |

### Compliance viewpoint (SOC2 CC6.x)

| Control | Requirement | How addressed |
|---|---|---|
| CC6.1 | Logical access uses unique IDs | Per-service DB roles; no shared credentials |
| CC6.2 | Access provisioned based on job function | Atlas roles via CRD (PR-reviewed IaC); RDS roles via Pulumi |
| CC6.3 | Access removed promptly | Okta group removal = immediate revocation; ESO sync = <1h |
| CC6.6 | Restrictions on privileged access | `atlasAdmin` only via break-glass; PD schedule = security gate |
| CC7.2 | Monitor system components | Atlas audit log + pgaudit + CloudTrail → Datadog alerts |

### Architecture viewpoint

| Decision | Rationale |
|---|---|
| **ESO as unified password source for MongoDB** | ESO writes K8s Secret from SM; Atlas Operator reads same secret as `passwordSecretRef`; service reads same secret. Single secret, two consumers, no duplication. |
| **Fixed username prefix, rotating password only** | `connectors_prod_rw` never changes — service config is static. Only the password value rotates. Simplifies connection string management across environments. |
| **Reloader for rotation propagation** | Already deployed cluster-wide via `clusters: {}` ApplicationSet. Watches K8s Secret changes → rolling restart. Zero new tooling, zero manual steps on 90-day rotation. |
| **Centralized AtlasDatabaseUser CRDs (not per-service Helm)** | Per-service Helm creates circular dependency (password must pre-exist before Helm install) and bundles privilege changes into service deploys, evading security review. Centralized = one approval gate, CODEOWNERS enforced. |
| **IRSA + RDS Proxy for service RDS auth** | IRSA is already built (`service_account.py`); `iam_database_authentication_enabled` already on in prod. RDS Proxy removes 15-min token refresh from application code — no app changes required. |
| **Management plane split is intentional** | Atlas Operator for MongoDB (purpose-built, CRD lifecycle, secret generation); Pulumi for RDS (SQL Role/Grant, IRSA policy). Delivery plane is identical: K8s Secret → env vars for MongoDB; IRSA → proxy → no secret for RDS. |
| **GHA cron for PagerDuty→Okta sync** | Reuses existing hourly `on_callers.yaml` workflow. No n8n, no webhooks, no new infrastructure. Third step added to existing job. |
| **MongoDB human access via SM scoped credential** | Atlas SAML federation possible but requires Atlas org-admin + Okta admin coordination — deferred. SM credential fetched via `aws sso login` (existing habit) achieves equivalent security posture unblocked. |
| **MongoDB service auth: password in v1, OIDC in v2** | v1 uses ESO + K8s Secret + Atlas Operator (no code change, ships now). v2 upgrades to OIDC/IRSA (no stored password, parity with RDS) but requires MongoDB driver upgrade + connection string change per service. Non-destructive migration: services move one at a time. |

---

## Consequences

### Positive
- Any single service credential compromise is contained to its own schema
- Offboarding an engineer revokes all DB access in < 1 hour (Okta) or immediately (AWS SSO session)
- Credential rotation is automated — no coordinated multi-team rotation event
- Full per-operation audit trail to Datadog
- SOC2 CC6.x controls met with evidence

### Negative / Trade-offs
- **Migration complexity:** ~25 service secrets need updating; 6 migration phases with 48h staging validation each — estimated 8–12 weeks elapsed time
- **Initial setup cost:** Atlas Operator move to platform-tools, CRD authoring for all users, Pulumi role provisioning for all services
- **Break-glass lag:** Access granted on next hourly GHA cron run (≤60 min). Acceptable for planned on-call; for immediate incidents, `task db:break-glass` manual override needed as fallback
- **Atlas Identity Federation deferred:** Compass SSO login not available in v1 — developers use SM-fetched credentials instead

### Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Service deploys with new role before Pulumi grants are applied | Medium | High | Deployment pipeline checks for secret existence before rollout |
| `prod-db-admin` PD schedule misconfigured (wrong people) | Low | Critical | Security team owns schedule; quarterly audit |
| Okta `groups:manage` scope unavailable | Medium | Medium | Fallback: IAM Identity Center permission sets + dedicated Atlas user (no Okta group API needed) |
| Temporal/Dagster migration breaks stateful workloads | Low | High | Phase 6 last; schema ownership review in Story #70387 before migration |

---

## Implementation Stories

| Story | Title | Phase |
|---|---|---|
| #70385 | Design RFC (this ADR) | Pre-work |
| #70386 | MongoDB access discovery | Pre-work |
| #70387 | RDS access discovery + migration framework inventory | Pre-work |
| #70388 | Atlas Operator: move to platform-tools, create AtlasProject CRDs | Phase 1 |
| #70389 | MongoDB: create per-service AtlasDatabaseUser CRDs | Phase 1 |
| #70390 | RDS: create per-service Pulumi roles + enable staging IAM auth | Phase 1 |
| #70391 | Service migration Phase 1–2 (low blast radius services) | Phase 2 |
| #70392 | Service migration Phase 3–4 (core services + Debezium) | Phase 3 |
| #70393 | Human access: Okta groups, SM scoped secrets, dev workflow tasks | Phase 2 |
| #70394 | Break-glass: `okta_assign_db_admins.py` + GHA step + PD schedule | Phase 2 |
| #70395 | Quarterly access review runbook | Phase 3 |

---

## References

| Resource | Location |
|---|---|
| RFC | `sentra/docs/rfc-least-privilege-db-access.md` |
| Atlas Pulumi provisioning | `sentra-infrastructure/mongodb_provision/mongodb.py` |
| RDS Pulumi provisioning | `sentra-infrastructure/postgresql_provision/provision.py` |
| On-callers GHA workflow | `sentra-infrastructure/.github/workflows/on_callers.yaml` |
| PagerDuty on-callers script | `sentra-infrastructure/scripts/pager_duty_get_on_callers.py` |
| Slack on-callers script (template for Okta) | `sentra-infrastructure/scripts/slack_assign_on_call_groups.py` |
| Okta user sync script | `sentra-infrastructure/scripts/okta_user_sync.py` |
| Atlas Operator ArgoCD ApplicationSet | `sentra/argocd/infra/mongodb-operator_applicationset.yaml` |
| Prod RDS stack config | `sentra-infrastructure/Pulumi.prod.yaml` |
