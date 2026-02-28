# Ybe Check — Bug Fix Tracker

## Phase 1: Critical Bugs
- [x] **B3** — `loggingUtils.ts`: Fix infinite recursion risk in error handlers
- [x] **B4** — `loggingUtils.ts`: Fix variable shadowing (renamed to archiveTimestamp)
- [x] **B5/B6** — `fileUtils.ts`: Fix busy-wait spin lock + deadlock potential (atomic wx flag, stale lock detection, timeout)

## Phase 2: High Bugs  
- [x] **B7** — `webviewUtils.ts`: Fix XSS vulnerabilities — escapeHtml applied to all user-controlled data
- [x] **B8** — `webviewUtils.ts`: Fix version mismatch in footer (v0.1.0 → v0.1.2)
- [x] **B9** — `webviewUtils.ts`: Handle null module scores properly (show N/A)
- [x] **I1** — `webviewUtils.ts`: Remove dead code (getScoreClass)
- [x] **B1** — `extension.ts` + `scanUtils.ts` + `cli.py`: Differentiate fullScan vs staticScan
- [x] **B2** — `cli.py`: Respect --json flag (added plain-text output mode)
- [x] **B10** — `dependencies.py`: Add npm hallucination check (exists_on_npm)
- [x] **B11** — `dependencies.py`: Fix npm line numbers (parse raw lines)
- [x] **B13** — `secrets.py`: Fix global pip install (use --user flag)
- [x] **B14** — `scanUtils.ts`: Replace dynamic require() with static import
- [x] **I2** — `scanUtils.ts`: Fix void/await mismatch (removed await)
- [x] **I11** — `cli.py`: Fix error output to stderr when not --json

## Phase 3: Medium Bugs
- [x] **B12** — `Dockerfile`: Fix port mismatch (3000 → 8000)
- [x] **I3** — `fileUtils.ts`: Fix parameter shadowing import (path → newPath)
- [x] **I7** — `auth_guards.py`: Add simple CORS assignment pattern detection
- [x] **I12** — Created shared `modules/_utils.py` with common utilities

## Remaining (Informational — No Code Changes Needed)
- [ ] **I4** — `__mocks__/vscode.ts`: Note about jest dependency (informational only)
- [ ] **I5** — `tests/extension.test.ts`: Zero test coverage (informational only)

## Verification Results ✅
All tests passed:
- [x] TypeScript compilation (`tsc --noEmit`) — zero errors
- [x] Python syntax compilation (`py_compile`) — all 7 files pass
- [x] **Test 1**: Full scan (all 5 modules) — 35 issues detected correctly across secrets, prompt injection, PII, dependencies, auth guards
- [x] **Test 2**: `--static` flag — correctly excludes Dependencies module (4 modules only)
- [x] **Test 3**: Plain-text output — properly formatted with severity labels, file:line refs, top fixes
- [x] **Test 4**: npm hallucination detection — `express`→True, `some-hallucinated-npm-package`→False, `lodash`→True
- [x] **Test 5**: CORS pattern detection — `CORS_ORIGIN = "*"` in settings.py:6 detected
- [x] **Test 6**: npm line number accuracy — Line 5 (express), Line 6 (hallucinated) match actual file
