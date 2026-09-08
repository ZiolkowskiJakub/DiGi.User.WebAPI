# Implementation Plan — Issue #3: Remove Redundant `user` Segment from `UserController` Endpoints

**Issue:** https://github.com/ZiolkowskiJakub/DiGi.User.WebAPI/issues/3
**Labels:** `type: breaking-change` · `priority: medium` · `ai: standard`
**Last verified:** 2026-09-08 (live host + full local test suite)
**Status:** Fix is **implemented, deployed, live and verified**. What remains is **completion work**: sync the release branch to `main`, split off a separate production-login defect, and close #3 with evidence.

> This revision supersedes the earlier draft. Two of its premises are now **wrong** and are corrected below:
> - *"No xUnit project exists for `DiGi.User.WebAPI`"* — **false**. `DiGi.Test/DiGi.User.WebAPI.xUnit` exists and passes 8/8.
> - *"not yet on `main`, not yet deployed"* — the **deployed** part is now **false**. The fix is live on `api.digiproject.uk`.

---

## 1. Verified current state (2026-09-08)

| Check | Evidence | Result |
|---|---|---|
| Route in source | `UserController.cs:18` → `[Route("[controller]")]` | **Fixed** (was `user/[controller]`) |
| Fix commit | `fa4ebb0` on `0.8.8`, pushed to `origin/0.8.8` | **Committed** |
| Fix on `main`? | `main` = `9d44f03` = version **0.8.7** (`Build=7`); `0.8.8` = `Build=8` | **Not on `main`** (41 commits behind) |
| Deployed build | `ServiceVersion 0.8.8.0`, `InformationalVersion 0.8.8.20260908111358` → compiled **11:13:58 UTC** | **Later than** fix commit **06:51 UTC** → fix **is live** |
| New route `POST /user/login` | live probe | **500** (route resolves; server fault — see §3) |
| Old route `POST /user/user/login` | live probe | **404** (old route gone) |
| New route `GET /user/session` | live probe | **401** (route live, auth required) |
| Old route `GET /user/user/session` | live probe | **404** (old route gone) |
| Swagger + route catalog | `swagger.json`, `/information/endpoints` | only `user/*`, **no** `user/user/*` |
| Local test suite | `DiGi.Test/DiGi.User.WebAPI.xUnit` | **8/8 pass**, build 0 warn / 0 err |

### Route table (as committed and live)

| Method | Old route (now 404) | New route (live) |
|---|---|---|
| GET | `user/user/secure-data` | `user/secure-data` |
| POST | `user/user/login` | `user/login` |
| GET | `user/user/session` | `user/session` |
| POST | `user/user/session/refresh` | `user/session/refresh` |
| POST | `user/user/logout` | `user/logout` |

The issue proposed `[Route("user")]`; the commit used `[Route("[controller]")]`. For `UserController` both expand to `user`, so the two are equivalent; the `[controller]` form also matches the GIS controllers' convention.

---

## 2. Verification evidence

**Live host (`https://api.digiproject.uk`), 2026-09-08:**
- `POST /user/login` (dummy credentials, no such account) → `500` with the standard ASP.NET server-fault page. A `500` — not `401`/`404` — proves the **route resolves** and the request reaches `LoginAsync`; the failure is a server-side fault in the credential path, not routing.
- `POST /user/user/login` → `404`; `GET /user/user/session` → `404`. The doubled segment is gone.
- `GET /user/session` → `401` (auth required → route live).
- Swagger `paths`: `/user/secure-data`, `/user/login`, `/user/session`, `/user/session/refresh`, `/user/logout` — no `user/user/*`.
- `/information/endpoints` (public tier): same five `User/*` routes, `IsApiIgnored: false`.

**Local suite (`DiGi.Test/DiGi.User.WebAPI.xUnit`), 2026-09-08:**
- `dotnet build` → `0 Warning(s), 0 Error(s)` against the fixed controller.
- `dotnet test` → `Passed! - Failed: 0, Passed: 8, Skipped: 0, Total: 8`.
- The host is `Microsoft.AspNetCore.TestHost` driving the **real** `UserController` via `MapControllers()`, so a route regression would 404 and fail these facts. The facts call the **new** routes (`user/login`, `user/session`, `user/logout`, `user/secure-data`, `user/session/refresh`).
- `UserController_Login_SetsJti` passes: login **issues a JWT with a `jti`**, and wrong password / unknown email / blank password each return `401`. This proves the login code path is correct — the production `500` is therefore **environment/data**, not code.

**Consumer sweep (full DiGi tree, source files):** the only reference to these routes is the test suite itself, already on the new paths. No front-end, script, or sibling DiGi repository hard-codes `user/*` or `user/user/*`.

---

## 3. The production login `500` — a separate defect, not part of #3

`POST /user/login` returns `500` on the live host while the same code path passes locally (token issued, denials `401`). Reading `LoginAsync`, the only ways to reach `500` are: `userPostgreSQLConverter` is **null**, or `GetUserCredentialAsync(email)` **throws**. For a non-existent email the code should return `401`, so the `500` indicates the production host's credential path is not wired — most likely a **missing `User_PostgreSQL_Main.conf`** on the host (so the converter factory yields `null`) or an **unprovisioned credential table/schema** in the database the host points at.

This is a **deployment/data** defect in the auth flow, independent of the routing change in #3. It is **not** tracked anywhere yet (only #3 is open). It needs its own issue and its own fix before login is usable in production.

---

## 4. Remaining work (completion plan)

### Step 1 — Release / branch sync (GitHub · Branch Synchronization)

Both trigger conditions are met: `0.8.8` is a bare SemVer branch and it has unmerged commits relative to `main` (main is `0.8.7`). This is a **git operation only**; it does **not** redeploy — the host already runs `0.8.8.0` with the fix.

```bash
git checkout main
git merge --ff-only 0.8.8        # fast-forward; main (9d44f03 / 0.8.7) is the merge-base
git checkout -b 0.8.9
# Directory.Build.props: <Build>8</Build> -> <Build>9</Build>   (Major=0, Minor=8)
git add Directory.Build.props
git commit -m "chore: bump version to 0.8.9"
git push origin main
git push -u origin 0.8.9
```

Note: `0.8.8` carries more than #3 — it also ships issue #1 (session/logout/refresh), the PostgreSQL credential login, and the PBKDF2 derivation. Merging it to `main` lands all of that. A `0.8.9` **deployment** is only needed when the login-500 fix (Step 2) lands; it is not required for #3's routing, which is already live.

### Step 2 — File a separate issue for the production login `500`

Per GitHub · Issues §1, a new issue needs `type:*`, `priority:*`, `ai:*` and a default assignee. Recommended:
- `type: bug`, `priority: high` (a core auth flow is down in production), `ai: standard` — escalate to `ai: heavy` only if diagnosis becomes cross-layer (converter wiring + production schema).
- assignee `ZiolkowskiJakub`.
- Body: production `POST /user/login` → `500` (server-fault page) while the identical path passes locally (8/8 suite, token issued, denials `401`); likely a null `UserPostgreSQLConverter` or unprovisioned `User_PostgreSQL_Main.conf`/credential schema on the host; repro recipe; explicitly **out of scope for #3** (routing).
- Create with `--body-file` (never inline), per GitHub · Issues §1.

### Step 3 — Close #3 with a structured resolution comment (GitHub · Issues §3)

Keep the existing labels; do not relabel a closing issue. Comment (via `--body-file`):
1. **Resolution & commits:** `fa4ebb0` on `0.8.8` (merged to `main` in Step 1); repo `DiGi.User.WebAPI`.
2. **Summary:** `[Route("user/[controller]")]` → `[Route("[controller]")]`; endpoints now `user/*`.
3. **Tests:** `DiGi.Test/DiGi.User.WebAPI.xUnit` 8/8 pass, build clean.
4. **Live verification:** new routes resolve, old `user/user/*` → `404`, Swagger/catalog show `user/*` only.
5. **Pointer:** login `500` is tracked separately (the issue from Step 2) and is not a routing regression.

---

## 5. Acceptance criteria (from the issue) — all met

| # | Criterion | Status |
|---|---|---|
| 1 | Swagger lists `user/*`, not `user/user/*` | **Met** — Swagger + `/information/endpoints` show only `user/*` |
| 2 | Login, session, refresh, logout, secure-data work at new paths | **Met** for routing (all resolve; 8/8 local suite) — the login `500` is a separate prod env defect (§3) |
| 3 | Old `user/user/*` paths return 404 | **Met** — live probes `404` |
| 4 | All consumers updated | **Met** — only consumer is the test suite, already on new routes |
| 5 | Verified against deployed `api.digiproject.uk` | **Met** — live probes + host build postdates the fix |

---

## 6. Guideline compliance

| Guideline | How this plan honors it |
|---|---|
| **Coding · WebAPI Contracts §1** | Renamed/removed a route → swept every client and front-end by hand; the only consumer is the test suite, already on the new routes. No silent 404 for any real client. |
| **Coding · WebAPI Contracts §4** | The endpoint is deployed (host build postdates the fix) and the client that uses it (the test suite) targets it and passes. No code is built on an undeployed endpoint. |
| **Coding · Deployed WebAPI §1** | Checked `/information/version`, `/information/controllers`, `/information/endpoints` and the live routes before concluding; distinguished "route absent" from "route present but faulting" via the `500` vs `404`/`401` split. |
| **Coding · Deployed WebAPI §3** | Treat `api.digiproject.uk` as production: only read-safe probes (dummy credentials, no account, no state change) plus public GET telemetry. No write endpoints invoked without authorization. |
| **Coding · Automatic Tests** | A real suite exists and is the regression guard: it runs the real routing pipeline (TestHost + `MapControllers`) and passes 8/8 against the fix. The earlier "no test project" premise is corrected. |
| **GitHub · Branch Synchronization** | `0.8.8` is a bare SemVer branch differing from `main`; release sequence = ff-merge to `main`, bump patch to `0.8.9`, create branch, update `Directory.Build.props`, push both. |
| **GitHub · Issues §1/§2/§3** | Verify the issue's claims before acting (done: code + live + tests); the `500` is split into its own issue with mandatory `type/priority/ai` + assignee; #3 closed with a structured comment via `--body-file`. |
| **GitHub · AI Issue Classification** | New login-500 issue tiered `ai: standard` (escalate to `ai: heavy` if cross-layer prod diagnosis is needed); #3 stays `ai: standard`. |
| **Coding · General §1.12** | The change is permanent; no `TODO [Marker]` tag is warranted. |

---

## 7. Risk assessment

| Risk | Likelihood | Mitigation |
|---|---|---|
| A hidden (non-repo) client hard-codes `user/user/*` | **Very low** — full-tree sweep found none; issue author confirmed the GIS WebAPI has no references. | `type: breaking-change` label; note it in the closing comment / release notes. |
| Production login remains down (`500`) | **Confirmed** — core auth flow is 500 in prod today. | Step 2 files it as `priority: high`; fix rides on the next `0.8.9` deployment. |
| `main`/`0.8.8` surprise on merge | **None expected** — `main` (`9d44f03`) is the merge-base of `0.8.8`. | Step 1 uses `--ff-only`; abort and re-investigate if it fails. |
| Release does not fix login | **Certain** — Step 1 is git-only and does not redeploy. | Expectation set in §4 Step 1; the login fix is a separate issue + deploy. |

---

## 8. Out of scope

- The production login `500` — a deployment/data defect in the credential path, tracked as its own issue (§4 Step 2).
- Deploying `0.8.9` — not required for #3 (routing is already live); it carries the login fix later.
- Modifying any other controller — each sets its own route; the base class defines no route template.
