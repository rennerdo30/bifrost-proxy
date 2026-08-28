# Completeness audit

Four reports covering unfinished code and missing implementations, written
2026-08-23 against `9b1c8a9`. Each sorts findings into three buckets and does not
mix them: **genuinely unfinished**, **deliberately scoped out and honestly
disclosed**, and **fine**. An honest `ErrNotSupported` is a documented
limitation; one that fakes success is a defect.

| Report | Scope | Verdict |
|---|---|---|
| [`go-backend.md`](go-backend.md) | `internal/`, `cmd/` | Data path is genuinely built. The gaps are mostly knobs wired to nothing, plus failures that report success |
| [`web-dashboards.md`](web-dashboards.md) | `web/server/src`, `web/client/src` | Server dashboard is complete in surface area but three of nine pages break in the configuration they were written for; client dashboard's two blocking gaps are Go-side serialisation |
| [`mobile.md`](mobile.md) | `mobile/` | Cannot ship — and the native VPN scaffold is not the reason. The REST management client, which the docs present as the working part, has never run against a live client |
| [`desktop.md`](desktop.md) | `desktop/`, `internal/tray`, `internal/service` | Was not compiling at all; fabricates connection state and telemetry; docs describe roughly twice the app that exists |

## How to read these

Findings cite `file:line`, and each report states what was verified by execution
versus by reading. Where a report could not check something — a Windows or Linux
code path, an iOS build, a browser flow that did not complete — it says so
instead of implying confirmation. Treat an unverified claim as a lead.

The reports were written independently and disagree with each other in places, and
with the briefs they were given. Those disagreements were usually the reports being
right: the `network.dial_timeout` field the brief described as inert is in fact
applied (`internal/backend/netconfig.go:37`), and the documentation that said
otherwise has been corrected.

## Retired documents

This directory replaces four root-level files, removed in the same change that
added this index. Git history preserves all of them.

- **`AUDIT.md`** and **`AUDIT-FINDINGS.md`** — a multi-agent audit from
  2026-06-27 and its follow-up from 2026-07-02. Substantially overtaken: the
  headline security finding no longer reproduced, the UI gaps it listed were
  filled by #277 and #281, and the Go backend report itemises fourteen further
  claims that no longer hold. Its font finding cited a build artifact that is not
  in the tree.
- **`TODO.md`** — a 1791-line implementation checklist, 789 of 791 items ticked.
  The two open ones were test-coverage notes, one marked deferred.
- **`IMPLEMENTATION_PLAN.md`** — a 2791-line build plan for work now shipped.

The reports here cite `AUDIT-FINDINGS.md` and `TODO.md` as evidence about their
staleness — for example that `TODO.md:986-993` marked brute-force protection as
shipped when no config key exists for it. Those citations point at files that are
now only in git history; `git show 9b1c8a9:TODO.md` retrieves them.

## Current status

The findings have been worked through on a set of branches, each with its own
pull request. **None of the remediation has been independently reviewed yet** —
see "What is still open" below.

| Area | State |
|---|---|
| `go-backend.md` §1–3 (inert config, silent stubs, fake success) | Fixed across #292–#297, #302, #303, #304 |
| `go-backend.md` §3 (fabricated telemetry, NAT detection, Windows TUN spin) | Fixed in #307 |
| `go-backend.md` §4 (dead code) | Mostly removed in #312; the rest waits on the PRs that rewrite the same files |
| `web-dashboards.md` items 1–14 | Fixed in #301, #305 and earlier |
| `web-dashboards.md` items 15–29 | Fixed in #308 |
| `desktop.md` P0–P1 | Fixed in #292 |
| `desktop.md` P2 | Fixed in #309, plus service start/stop in #310 |
| `mobile.md` items 1–14 | Fixed in #295, #311 (#306 superseded) |

### What is still open

1. **No independent review.** Every branch above was written and self-checked by
   the same pass. The adversarial second-opinion review these changes are
   supposed to get could not be run — the tooling for it failed for the whole
   session — so treat all of it as unreviewed.
2. **Remaining dead code** (`go-backend.md` §4): the duplicate API route tables,
   the copy helpers, the thin constructors, and `util`'s `WithStartTime`/
   `WithDomain` pair. Each lives in a file that an open PR rewrites; removing
   them now would only create conflicts. Do them after those merge.
3. **The session/login flow** (`go-backend.md` §4): the server half is built and
   config-gated, but the dashboard still keeps a bearer token in
   `localStorage` — which is what the session flow exists to avoid. Finishing it
   is a feature, not a cleanup.
4. **HTTP/1.1 keep-alive request loop.** The proxy answers one request per
   connection and advertises that honestly with `Connection: close`. The full
   loop fits the phase machinery added in #297.
5. **Client-side caching** (`web-dashboards.md` item 20). No implementation
   exists; the inert dashboard tab was removed rather than left showing zeros.
6. **On-device VPN** (`mobile.md` item 15). Weeks of work, a paid Apple
   Developer account and real devices. The scaffold stays gated off and
   documented as insecure.

One correction was made to a report while acting on it: `go-backend.md`'s verdict
that all of `internal/auth/middleware.go` was dead is wrong — four symbols in it
are on live paths, and deleting the file wholesale breaks the build. The row now
says so. Treat the remaining REMOVE rows as leads to verify, not as instructions.

`ISSUES.md` at the repo root carries the short list of deliberate limitations and
open work. This directory is the detail behind it.
