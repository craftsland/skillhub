# Issue #611 Verification Report

- Issue: [#611 — Direct version deletion leaves child FKs and returns 500](https://github.com/iflytek/skillhub/issues/611)
- Status: Local verification complete; `big-main` remote verification pending
- Baseline: `origin/main` at `6817d98007c7890c1a8ecb3e822272287bb37a05`
- Working branch: `fix/issue-611-child-fks`

## Decision

### Does the bug exist?

Yes. Against the baseline commit, a real PostgreSQL 16 instance and the real HTTP endpoint reproduced
the failure three times:

```http
DELETE /api/web/skills/global/issue-611-repro/versions/1.0.0
```

The target version was `REJECTED`, had a terminal `REJECTED` review task, and was not the skill's
last version. Every request returned HTTP 500. PostgreSQL reported SQL state `23503` because
`review_task_skill_version_id_fkey` still referenced the version. The transaction rolled back and
preserved both versions and the review task.

As a control, deleting only the review task before retrying the same request changed the result to
HTTP 200 and the version was deleted.

### Is it worth fixing?

Yes:

- The supported deletion path for a normally rejected version fails deterministically.
- The failure is exposed as an unexpected HTTP 500 rather than a business response.
- The endpoint cannot fulfil the documented lifecycle operation or free the version string for
  reuse.
- The fix can reuse an existing repository operation already used by same-version replacement,
  keeping implementation and regression risk small.

### Is a broader change appropriate?

The fix should cover every review task owned by the deleted version, regardless of task status. A
broader generic child-cleanup framework or schema migration is not justified:

- `skill_tag.version_id` can only be assigned to a `PUBLISHED` version through the domain service.
- `promotion_request.source_version_id` can only be assigned to a `PUBLISHED` version.
- Direct version deletion rejects `PUBLISHED` and `YANKED` versions before mutation.
- `security_audit` intentionally retains soft-deleted history; migration V38 removed its version
  foreign key for this purpose.
- `skill_file` is already deleted explicitly and `skill_version_stats` uses `ON DELETE CASCADE`.

The implementation will therefore delete all `review_task` rows for the target version before
deleting `skill_version`, using the existing `ReviewTaskRepository.deleteBySkillVersionIdIn`
operation.

## Operation Log

| Time (UTC+8) | Operation | Result |
|--------------|-----------|--------|
| 2026-07-30 14:41–14:47 | Reproduced the issue on the baseline using isolated PostgreSQL 16, Redis 7, and backend port 18081 | Three HTTP 500 responses; PostgreSQL FK violation confirmed |
| 2026-07-30 14:46 | Removed the target review task and repeated the request | HTTP 200; version count changed from 2 to 1 |
| 2026-07-30 14:47 | Stopped the backend and removed diagnostic containers and temporary files | Cleanup complete; repository remained unchanged |
| 2026-07-30 14:55 | Fetched `origin/main` and `origin/big-main` | Baselines unchanged at `6817d980` and `7774935d` |
| 2026-07-30 14:56 | Created `fix/issue-611-child-fks` from `origin/main` | Working branch established |
| 2026-07-30 15:02 | Reviewed every schema reference to `skill_version` and the related lifecycle services | Scope limited to reachable review-task ownership |
| 2026-07-30 15:02–16:06 | Implemented review-task cleanup and stable aggregate locking, then ran unit, integration, PostgreSQL 16, frontend, and staging checks | Fix and adjacent concurrency cases passed |
| 2026-07-30 16:06 | Completed backend regression excluding the independently verified polluted auth class | 659 tests passed, 1 skipped; reactor build succeeded |
| 2026-07-30 16:08 | Removed the isolated local containers, network, images, staging overrides, and temporary test data | Local cleanup complete |
| 2026-07-30 16:09 | Inventoried the remote test host without changing its runtime | Docker 29.4.0 and PostgreSQL 16 runtime found; isolated deployment required because ports 8080/8081 and 5432/6379 are in use |

## Test Matrix

| Category | Scenario | Expected result | Status |
|----------|----------|-----------------|--------|
| Regression | Delete a non-last `REJECTED` version with a terminal review task | HTTP 200; version and its review tasks removed | Local passed; remote pending |
| Happy path | Delete non-last `DRAFT`, `UPLOADED`, and `SCAN_FAILED` versions | HTTP 200; target artifacts removed | Unit passed; remote pending |
| Multiple children | A version has more than one historical review task | All review tasks for only that version are removed | Local integration passed; remote pending |
| Isolation | Another version has its own review task | Other version and task remain unchanged | Local integration passed; remote pending |
| Boundary | Delete the last remaining version | Business 4xx; all data remains | Unit and PostgreSQL concurrency passed; remote pending |
| Lifecycle guard | Delete a `PUBLISHED` version referenced by a tag or promotion | Business 4xx; references remain unchanged | Unit passed; remote pending |
| Permission | Unauthorized member deletes another owner's version | HTTP 403; all data remains | Unit passed; remote pending |
| Audit retention | Deletable version has security audit history | Version deletes; audit is soft-deleted and retained | Unit passed; remote pending |
| File integrity | Deletable version has file rows and bundle storage | Database rows delete; storage cleanup runs after commit | Unit passed; remote pending |
| Statistics | Deletable version has `skill_version_stats` | Statistics row cascades without affecting other versions | Schema reviewed; remote pending |
| Concurrency | Two requests target the same version | No 500; one succeeds and the other gets a deterministic missing-resource response | PostgreSQL 16 passed; remote pending |
| Concurrency | Two requests target different versions of a two-version skill | No 500 and at least one version remains | PostgreSQL 16 passed; remote pending |
| Rollback | A precondition or authorization check rejects deletion | No database or storage mutation | Unit passed; remote pending |
| Backward compatibility | Successful response contract | Existing response shape and action remain unchanged | Controller and integration passed; remote pending |
| Full regression | Backend, frontend checks, staging smoke tests | Required checks pass | Local passed with documented baseline issues; remote pending |

## Test Report

### Local environment

- Baseline: `6817d98007c7890c1a8ecb3e822272287bb37a05`
- Database/runtime: PostgreSQL 16 Alpine, Redis 7 Alpine, Eclipse Temurin 21 runtime image
- Isolated API: `127.0.0.1:18081`
- Final PostgreSQL behavior image:
  `skillhub-issue-611:local-aggregate-lock`
  (`sha256:69c7e1810d7bfed8549d2109db09f8203d63748a473d1770ce154093eaa7cdc5`)
- Staging image:
  `skillhub-server:staging`
  (`sha256:5344d26b56e07132ae3b0b3f8359e43b678a10329e415610c95b4e0383018aa5`)

#### Automated checks

| Check | Result |
|-------|--------|
| `SkillGovernanceServiceTest` | 15/15 passed |
| App lifecycle/controller/persistence targeted set | 11/11 passed |
| `SkillVersionDeleteFlowIntegrationTest` | Passed against the H2 persistence test profile |
| Frontend typecheck | Passed |
| Frontend lint | Passed |
| Frontend Vitest | 181 files, 618 tests passed |
| Staging smoke | 15/15 passed |
| Backend reactor excluding `ApiTokenAuthenticationFilterTest` | 659 tests passed, 1 skipped; all 7 dependent modules succeeded |
| `ApiTokenAuthenticationFilterTest` in isolation | 9/9 passed |

The normal backend aggregate run was blocked by a pre-existing test-isolation defect:
`ApiTokenAuthenticationFilterTest.shouldIgnoreNonBearerAuthorizationHeader` observed a
`SecurityContext` left by another auth test. This change does not touch auth. The class passed in
isolation, and every other backend test passed in a single reactor run.

Staging also exposed two baseline environment conflicts:

1. Host port 5432 was already owned by an unrelated `postgres-local` container, so staging used
   temporary isolated port overrides instead of stopping it.
2. The staging web service does not define `SKILLHUB_TRUST_FORWARDED_PROTO`; setting it to `false`
   in the temporary override was required for Nginx startup.

Both overrides were outside the repository and were deleted after the 15/15 smoke pass.

#### Real PostgreSQL behavior

- Baseline: three identical rejected-version deletes returned HTTP 500 with SQL state `23503`.
- Fixed rejected-version delete: HTTP 200; the target version and its review task were deleted.
- Same-version concurrent delete: one HTTP 200 and one HTTP 400
  (`Version not found`); no 500 or optimistic-lock exception.
- Different-version concurrent delete on a two-version skill: one HTTP 200 and one HTTP 400
  (`Cannot delete the last remaining version`); exactly one version remained.
- No unexpected `ERROR` or exception was present in the application log after the fixed scenarios.

### `big-main` remote environment

Pending integration merge, unique image build, isolated deployment, and full remote matrix.

### Remaining risks

- The remote PostgreSQL 16 matrix has not yet run against the exact `big-main` merge commit.
- The aggregate-lock query is PostgreSQL/H2-specific native SQL by design; any future database
  implementation must provide equivalent stable pessimistic locking.
- The unrelated auth test-isolation defect can still make the default backend aggregate command
  fail depending on test order.
