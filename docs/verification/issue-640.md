# Issue #640 unified identity core verification

## Scope

- Issue: <https://github.com/iflytek/skillhub/issues/640>
- Pull request: <https://github.com/iflytek/skillhub/pull/643>
- Integration target: `big-main`
- Validation environment: isolated, production-equivalent test deployment
- Production/default branch: not modified

This record covers P1 / PR 1 from
`docs/21-unified-identity-federation-design.md`. LDAP, DingTalk, CAS, SAML,
SCIM, trusted gateway, Binding V2, profile-sync redesign, and runtime provider
plugins remain outside this PR.

## Automated gates

The following checks ran against the isolated test deployment:

| Gate | Result |
|---|---|
| `./mvnw -pl skillhub-app -am test -B` with Java 21 | 671 tests, 0 failures, 0 errors, 1 skipped |
| `pnpm run typecheck` | passed |
| `pnpm run lint` | passed |
| `pnpm run build` | passed; only the existing Vite chunk-size warning remained |
| `scripts/smoke-test.sh` against the isolated deployment | 21 passed, 0 failed |
| DCO | passed |
| CLA | passed |

The clean PR branch was rebuilt from the latest `big-main`; its unified-identity
file tree is identical to the validated feature tree. Runtime artifact identity
and operational logs are intentionally omitted from the public repository.

## PostgreSQL and runtime scenarios

All database scenarios used isolated PostgreSQL 16 and Redis 7 containers.
They did not connect to or modify the shared test-environment database.

| Scenario | Observable result |
|---|---|
| Fresh migration | Flyway V44 applied successfully and created `identity_provider_state` |
| Fixed GitHub authority vector | `oauth2-github`, `https://github.com`, fingerprint `b2a93d58465e3de9e8b6cd127ba18425ae0f80c49c85f18f76086832923ca619`, state `READY` |
| Concurrent first pin | Two application instances converged to one READY row with the same fingerprint; no unique-constraint error |
| Legacy OAuth binding | Existing `identity_binding` row remained byte-for-byte equivalent while the provider moved through first pin to READY |
| Sticky mismatch | State remained `AUTHORITY_MISMATCH` across two application restarts; provider catalog was empty and the authorization route returned 503 |
| Same-authority recovery | SUPER_ADMIN recovery returned 200, changed the state to READY, wrote `PROVIDER_AUTHORITY_RECOVERED`, and updated the catalog without restart |
| Idempotent recovery | Repeating recovery returned `recovered=false` and did not append an audit record |
| Stale READY mismatch window | Recovery returned 409, persisted `AUTHORITY_MISMATCH`, retained the pinned authority/fingerprint, and wrote no recovery audit |
| Transaction rollback | A forced audit insert failure returned 500; the provider state update rolled back and no audit record was added |
| Unknown provider routes | Authorization and callback routes returned 403 without an upstream redirect |
| V43 to V44 upgrade | A database initialized by `v0.2.15` upgraded successfully and retained its legacy OAuth binding |
| Mixed-version and rollback | Current and `v0.2.15` servers were simultaneously healthy against the V44 database; the old provider endpoint returned 200 |
| Redis session compatibility | A local session created by `v0.2.15` was accepted by the current server for the same user |

## Remaining integration gate

After PR #643 is merged into `big-main`, build immutable Server/Web images from
the merge commit, deploy them to the shared test environment, and verify:

1. health, login catalog, and local-password login through the configured test
   domain;
2. unknown provider authorization/callback rejection;
3. V44 migration and READY provider state in the shared database;
4. existing Redis sessions and OAuth bindings;
5. recovery authorization and audit behavior;
6. logs contain no credentials or unexpected identity errors.

Do not merge this work into `main` until the shared-environment gate is
recorded here.
