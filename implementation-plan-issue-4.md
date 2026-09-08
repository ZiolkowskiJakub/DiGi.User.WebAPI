# Implementation Plan — Issue #4: Production `POST /user/login` returns 500

**Issue:** https://github.com/ZiolkowskiJakub/DiGi.User.WebAPI/issues/4
**Labels:** `type: bug` · `priority: high` · `ai: standard`
**Last verified:** 2026-09-08, ~17:03 CEST / 15:03 UTC (live host re-probe + local suite re-run)
**Status:** **Resolved on the live host.** The reported `500` no longer reproduces — `POST /user/login` with an unknown email now returns **`401`** (acceptance criterion #1). What remains is **completion work**: confirm the valid-login path on the host and close #4 with evidence. **No code change is required.**

> This is a verification/completion plan, not an implementation plan: the credential code path is correct and the defect has cleared on the deployment that postdates the issue.

---

## 1. Verdict

The production `500` described in the issue is **no longer present**. On the current live build the endpoint answers `401` for a non-existent account — the exact behaviour the issue asked for. The `500` was a **production data/provisioning fault** in the credential read path (the issue's own conclusion), not a code defect; the local suite proves the same code path returns `401`/`200` correctly.

---

## 2. Verified current state (2026-09-08)

| Check | Evidence | Result |
|---|---|---|
| `POST /user/login` (dummy, non-existent email) on `api.digiproject.uk` | live re-probe, 15:03 UTC | **`401`** (was `500`) — **criterion #1 met** |
| Deployed `DiGi.User.WebAPI` extension | `GET /information/version` | `0.8.8.20260908135525` (compiled **13:55:25 UTC**) |
| Host service build | `GET /information/version` | `0.8.8.20260908135702` (13:57:02 UTC) |
| Server restart | `GET /information/health` → `StartTimeUtc` | **14:03:52 UTC** — after the issue was filed (11:39 UTC) |
| Issue's build (for reference) | issue body | `0.8.8.20260908111358` (11:13:58 UTC) |
| Valid credential → `200` + `jti` | local `UserController_Login_SetsJti` | **passes** (real DB) — criterion #2 covered locally |
| Unknown email / wrong pw / blank pw → `401` | local `UserController_Login_SetsJti` + `..._NoCredential` | **pass** (real DB) |
| Local suite `DiGi.Test/DiGi.User.WebAPI.xUnit` | re-run, 2026-09-08 | **8/8 pass, 0 skipped**, 0 warn / 0 err |

The deployed `DiGi.User.WebAPI` (13:55:25 UTC) and the service (13:57:02 UTC) are both **later** than the build the issue was tested against (11:13:58 UTC), and the service was restarted at 14:03:52 UTC. The fix therefore rode on the deployment that followed the issue.

---

## 3. Root cause (consistent with the issue's own analysis)

`LoginAsync` has three ways to answer `500`: the converter is `null` (impossible now — `InitializeAsync` always registers a converter, falling back to `new UserPostgreSQLConverter(null)` when none is configured), `GetUserCredentialAsync(email)` **throws**, or token issuance fails. For an unknown email the code returns `401`; so the reported `500` was an **exception in the credential read** — a **server/data fault**, most likely:

- the production `user` **table / credential columns were not provisioned**, or
- the host's `User_PostgreSQL_Main.conf` was absent, or pointed at an unreachable or missing database.

The code is deliberately asymmetric here, and this is by design rather than a bug:

- **Write** paths (`InsertAsync`, `SetUserCredentialAsync`) call `CreateTableAsync` — a write migrates the table and adds the credential columns.
- **Read** paths (`GetUserCredentialAsync`) do **not** create the table — *"answering a question must not bring a database into existence."*

So a freshly-provisioned production database with no prior write has **no `user` table**, and the first `POST /user/login` runs `SELECT … FROM user …` → `42P01: relation "user" does not exist` → `500`. Once the table is provisioned (by a write, a one-off DDL run, or the deployment that followed), the same request reads `null` → `401`. That `500` → `401` transition is exactly what the live re-probe now shows.

`Create.ConnectionData` requires `Host`, `Username`, `Password`, `Database` and a non-null `Port`; if any is blank the factory yields `null`, no converter is registered, `InitializeAsync` installs the null-connection fallback, and login answers `401` for every account. Either way the endpoint degrades to `401`, never a raw `500`, once the environment is correct.

---

## 4. Why no code change is required

- The credential path is **correct**: the re-run local suite (8/8, real DB) drives the real `UserPostgreSQLConverter` through `InitializeAsync` and the real ASP.NET pipeline (`TestServer` + `MapControllers`), and asserts `200`+`jti` for a valid credential and `401` for unknown email / wrong password / blank password / no-credential row.
- A `500` on a genuine outage (DB down, table missing, unreachable host) is the **correct** signal. Masking it as `401` would be the exact anti-pattern the authorization guideline warns against — a protection/fault that "opens" or is misread when unsure. The deny-by-default and fault-vs-denial distinction are preserved as-is.
- The `500` in the issue was therefore an **environment** fault, now cleared by the deployment — not a code regression to patch.

---

## 5. Remaining work (completion plan)

### Step 1 — Confirm the valid-login path on the host (manual)
The one acceptance criterion that cannot be probed anonymously is **valid credential → `200` + `jti`**. A safe anonymous probe can only ever be the *denial* path (a non-existent account). With a real seeded account on the host's database:

```
POST /user/login  {"email":"<seeded>","password":"<seeded>"}   ->   200  {"Token":"<JWT with jti>"}
```

The local `UserController_Login_SetsJti` already proves this exact path (token issued, 32-char `jti`, ~1h lifetime, denials `401`); the host step only confirms the host's own database is wired to the same code.

### Step 2 — Close #4 with a structured resolution comment (GitHub · Issues §3, `--body-file`)
Keep the existing labels; do not relabel a closing issue. Comment:
1. **Resolution:** environment/provisioning fault in the credential path, not a code defect; cleared by the deployment that postdates the issue (`DiGi.User.WebAPI` `0.8.8.20260908135525`; service `0.8.8.20260908135702`; restarted 14:03:52 UTC).
2. **Evidence:** live `POST /user/login` (non-existent account) → `401` (was `500`); local suite 8/8 (real DB) covering `200`+`jti` and all denials.
3. **Root cause:** production `user` table / credential columns unprovisioned (or conf absent / unreachable DB); reads intentionally do not create the table.
4. **Pointer to #3:** the login-`500` was split out of #3's routing change (see [implementation-plan-issue-3.md](implementation-plan-issue-3.md) §3); both are now cleared.

### Step 3 — (Optional) Cleaner outage surface
`LoginAsync` currently lets a credential-read `NpgsqlException` surface as the ASP.NET `500` page. If a cleaner fault is wanted, catch it in `LoginAsync`, log it distinctly (never the password), and answer **`503 Service Unavailable`** — keeping `401` reserved for a genuine bad/missing credential. This is a judgment call, not a required fix: a raw `500` on a real outage is defensible and is already distinguished from `401` in the server log.

### Step 4 — (Optional) Committed conf default
`DiGi.User.WebAPI` ships no committed `files/User_PostgreSQL_Main.conf` — only the git-ignored `user files/User_PostgreSQL_Main.conf`. Following the canonical pattern (Coding · WebAPI Simple Authorization §4.A), a committed **default** `files/User_PostgreSQL_Main.conf` with deny-by-default values (the five required fields `HOST`, `PORT`, `USERNAME`, `PASSWORD`, `DATABASE` left blank) would make the "unconfigured → `401`" state obvious at deploy time rather than discovered via a failed login. The real credential stays in `user files/User_PostgreSQL_Main.conf` (git-ignored) and deterministically overwrites the committed default in `bin/` via the already-wired `CopyUserFiles AfterTargets="CopyFiles"` target. Optional; not required to close #4.

---

## 6. Acceptance criteria (from the issue)

| # | Criterion | Status |
|---|---|---|
| 1 | Unknown email → `401` (not 500) | **Met** — live re-probe returns `401` (15:03 UTC) |
| 2 | Valid credential → `200` + JWT with `jti` | **Covered locally** (`UserController_Login_SetsJti`); host confirmation = Step 1 |
| 3 | Verified on `api.digiproject.uk` after the next deployment | **Met** for the denial path on the post-issue build; Step 1 covers the success path |

---

## 7. Guideline compliance

| Guideline | How this plan honours it |
|---|---|
| **Coding · Deployed WebAPI §1/§2** | Verified via `GET /information/health` and `GET /information/version` (host + per-extension stamps) and a live route probe before concluding; distinguished "route absent" (404) from "route present but faulting" (500) from "denied" (401). |
| **Coding · Deployed WebAPI §3** | Only a read-safe probe (non-existent account, no state change) plus public GET telemetry. No write endpoints invoked; no real credentials attempted. |
| **Coding · WebAPI Simple Authorization** | Preserves deny-by-default and the fault-vs-denial distinction; explicitly does **not** mask a server fault as `401`. |
| **Coding · General §3** | The credential conf stays in `user files/` (git-ignored); only a non-secret committed default would go in `files/`. |
| **Coding · General §1.12** | The code is permanent and correct; no `TODO [Marker]` tag is warranted. |
| **Coding · Automatic Tests** | The real suite (8/8, real DB, `TestServer` + `MapControllers`) is the regression guard and was re-run; it covers `200`+`jti` and every denial branch. |
| **GitHub · Issues §1/§3** | Premises re-verified against code + live host + suite (the "500 is current" premise is now false); #4 is closed with a structured comment via `--body-file`. |
| **GitHub · AI Issue Classification** | `ai: standard` is appropriate — the resolution needs no code change, only verification + closure. |

---

## 8. Risk assessment

| Risk | Likelihood | Mitigation |
|---|---|---|
| Login is `401` because the host falls back to a **null converter** (conf absent), not because the DB is wired | **Low** — the deployment postdates the issue and the local path is proven. | Step 1's valid-credential probe distinguishes the two (a null converter would also deny a real account). |
| A future fresh production DB regresses to `500` (reads do not provision the table) | **Medium** — by design, a brand-new DB with no prior write has no `user` table. | Step 4 (committed default) + a note in the closing comment that a write/DDL must run before the first login. |
| Closing #4 as resolved when a real account still cannot log in | **Low** — Step 1 gates closure on a real `200`. | Do not close before Step 1 passes on the host. |

---

## 9. Out of scope

- Any code change to the login path — the code is correct and the defect has cleared on the deployment.
- Invoking write endpoints or guessing real credentials on the live host.
- Branch/release sync (tracked by #3 / [implementation-plan-issue-3.md](implementation-plan-issue-3.md)) — the fix already rode on a deployment.
