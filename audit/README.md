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

`ISSUES.md` at the repo root carries the short list of deliberate limitations and
open work. This directory is the detail behind it.
