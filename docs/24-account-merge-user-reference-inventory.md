# Account Merge user reference inventory

> Status: implementation gate for [#662](https://github.com/iflytek/skillhub/issues/662)
>
> Parent design:
> [`22-secure-account-merge-acceptance-design.md`](./22-secure-account-merge-acceptance-design.md)
>
> Baseline: `big-main@e7bde3e177142d24b99e438d78b11f438bcb80f1`

## 1. Purpose

Safe Account Merge cannot be implemented by updating only authentication tables. This inventory
classifies every persisted or externally cached platform-user reference found in the Flyway schema
and server code before PR 6 starts changing data.

The four classifications are:

1. **Current ownership** — migrate to the primary account.
2. **Current authorization** — migrate, merge, block, or revoke according to an explicit rule.
3. **Historical fact** — retain the secondary user ID; history is not rewritten.
4. **Derived/transient state** — rebuild, invalidate, close, or let expire under an explicit rule.

Any new user reference added before #662 merges must be added here and covered by preview, confirm,
or a documented preservation rule.

## 2. Account and authentication references

| Store / column | Classification | Preview and confirm rule |
|---|---|---|
| `user_account.id` | Account identity | Keep both rows. Lock both in stable ID order. The secondary row becomes `MERGED`; it is never deleted or reused. |
| `user_account.merged_to_user_id` | Account lineage | Set only on the secondary row, in the same transaction as all migrations. It must reference the primary account and cannot form a chain or cycle. |
| `identity_binding.user_id` | Current authorization | Move only `ACTIVE` bindings. Block when the primary already has another ACTIVE binding for the same Provider instance. Keep REVOKED bindings on the secondary account as historical security records. `identity_binding_subject` follows its binding and its uniqueness constraints remain authoritative. |
| `identity_binding.revoked_by` | Historical fact | Never rewrite. It records the actor who revoked a binding. |
| `local_credential.user_id` | Current authorization | If only the secondary has a local credential, move it. If both have one, retain the primary credential and delete the secondary credential inside the merge transaction; never copy the password hash or keep it usable for both accounts. The preview must state which outcome applies. |
| `api_token.user_id` and USER `subject_id` | Current authorization | Revoke every active secondary token in place. Do not change ownership or subject. Historical revoked tokens remain attached to the secondary account. Preview exposes only token name, prefix, and count. |
| `user_role_binding.user_id` | Current authorization | Any persisted non-default platform role on the secondary account blocks merge. Do not union roles. The default `USER` role is projected by `PlatformRoleDefaults` and is not migrated. |
| `identity_link_request.primary_user_id` | Current security workflow | Any active secondary Identity Link request blocks merge. Completed, expired, or cancelled requests remain unchanged as history. |
| legacy `account_merge_request.primary_user_id` / `secondary_user_id` | Historical fact | Never convert, complete, delete, or attach these rows to a new intent. The legacy endpoints remain fail-closed. |
| new `account_merge_intent.primary_user_id` / `secondary_user_id` | Current security workflow | Owned by the new flow. The secondary ID stays NULL until independent authentication succeeds. Completed intents remain as audit evidence. |
| new session-revocation task `user_id` | Derived/transient state | Enqueue the secondary user in the same PostgreSQL transaction. Retry Redis deletion until complete; do not treat task insertion as equivalent to session deletion. |

## 3. Namespace, skill, and social references

| Store / column | Classification | Preview and confirm rule |
|---|---|---|
| `namespace_member.user_id` | Current authorization | If only the secondary is a MEMBER or ADMIN, move it. If both accounts are members, retain the higher role and delete the duplicate secondary membership. Any move that newly grants OWNER to the primary blocks merge. Existing last-owner invariants still apply. |
| `skill.owner_id` | Current ownership | Move every owned Skill to the primary account. Block when this would violate `(namespace_id, slug, owner_id)` uniqueness. |
| `skill_search_document.owner_id` | Derived state | Rebuild or update from the migrated Skill owner in the same release. It is not an independent source of truth. |
| `skill_star.user_id` | Current user state | Move secondary-only stars. If both accounts starred the same Skill, keep the primary row and delete the duplicate secondary row. Recompute `skill.star_count` for affected Skills. |
| `skill_rating.user_id` | Current user state | Move secondary-only ratings. If both accounts rated the same Skill, retain the primary rating and delete the secondary duplicate; the preview reports the discarded secondary score. Recompute rating count and average for affected Skills. |
| `skill_subscription.user_id` | Current user state | Move secondary-only subscriptions. If both accounts subscribed to the same Skill, retain the primary row and delete the duplicate secondary row. Recompute `skill.subscription_count` for affected Skills. |

## 4. Profile, notification, and temporary references

| Store / column | Classification | Preview and confirm rule |
|---|---|---|
| `user_profile_field_source.user_id` | Historical/profile provenance | Keep the primary profile and its provenance. Preserve secondary provenance on the secondary account; do not let a merge overwrite manually or administratively managed primary fields. |
| `profile_change_request.user_id` | Current workflow plus history | A PENDING secondary request blocks merge because it could mutate a merged account later. Completed/rejected/cancelled rows remain on the secondary account. |
| `profile_change_request.reviewer_id` | Historical fact | Never rewrite. |
| `password_reset_request.user_id` | Derived security state | Consume/invalidate every unconsumed secondary reset request inside the transaction. Keep consumed requests as history. |
| `password_reset_request.requested_by_user_id` | Historical fact | Never rewrite. |
| `notification.recipient_id` | Current user state | Move notification inbox rows to the primary account so unread/read history remains visible after consolidation. Embedded `body_json` is historical content and is not rewritten. |
| `notification_preference.user_id` | Current user state | Move secondary-only preferences. If both accounts define the same category/channel, retain the primary preference. |
| `user_notification.user_id` | Current user state | Move governance-notification inbox rows to the primary account. Embedded `body_json` remains unchanged. |
| in-memory `SseEmitterManager` key | Derived/transient state | Close all secondary emitters after commit. Never re-key a live emitter to the primary account. |
| Redis `DeviceCodeData.userId` | Derived security state | A stale authorized device code must not mint a token after merge. Token redemption rechecks that the account is ACTIVE; existing codes then fail closed and expire within their normal TTL. |
| Spring Session principal index | Derived security state | New and touched sessions must be indexed by the stable platform user ID. Merge enqueues deletion of every indexed secondary session. Account-status checking on every API request is the immediate guard while deletion retries. |
| Account Merge primary proof / browser state / session nonce | Derived security state | Store raw values only in the bound server session, with a short TTL and one-time consumption. Persist only hashes and timestamps. Never return or log raw proof/state/nonce. |

## 5. Historical actor references that must not move

The following columns describe who performed an action at that time. They continue to reference the
secondary account after merge:

- `audit_log.actor_user_id`
- `namespace.created_by`
- `skill.created_by`, `skill.updated_by`, `skill.hidden_by`
- `skill_version.created_by`, `skill_version.yanked_by`
- `skill_tag.created_by`
- `label_definition.created_by`
- `skill_label.created_by`
- `review_task.submitted_by`, `review_task.reviewed_by`
- `promotion_request.submitted_by`, `promotion_request.reviewed_by`

JSON audit details, notification bodies, domain-event payloads, request logs, and metrics are not
rewritten. Secrets and raw authentication proof remain prohibited in all of them.

## 6. Confirmation lock and consistency order

Confirmation uses this stable order:

1. lock Merge Intent;
2. lock primary and secondary `user_account` rows by ascending user ID;
3. recompute the complete preview and digest;
4. lock and migrate current authorization and ownership records;
5. revoke credentials/tokens and invalidate temporary security state;
6. mark the secondary account `MERGED`;
7. mark the intent `COMPLETED`, write audit/outbox evidence, and enqueue session revocation;
8. commit PostgreSQL;
9. close SSE connections and process Redis Session deletion idempotently.

Any unsupported or newly discovered current-state reference is a blocking conflict, not a reason to
silently leave data behind.
