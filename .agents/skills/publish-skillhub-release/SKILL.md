---
name: publish-skillhub-release
description: Prepare, publish, monitor, and verify a SkillHub server release through an annotated vX.Y.Z tag, the AI Release Notes draft workflow, final curated notes, container images, and the Helm chart. Use for public SkillHub releases, release dry-runs, release recovery, or audits of the server release process; do not use for cli-vX.Y.Z npm releases.
---

# Publish SkillHub Release

Publish a public server release without moving an existing tag or exposing unreviewed notes. Treat Git history, GitHub workflows, the release template, and remote artifacts as the observable sources of truth.

## Route the request

- Use this workflow for server tags matching `vX.Y.Z`.
- For CLI tags matching `cli-vX.Y.Z`, stop and follow `cli/RELEASE.md` and `.github/workflows/release-cli.yml` instead.
- For a dry-run, complete discovery, validation, and release-note generation, but do not create or push a tag, edit a Release, publish packages, or dispatch workflows.
- For recovery, preserve the remote tag and inspect the existing Release and workflow runs before changing anything.

## 1. Discover the authoritative release path

1. Read the applicable `AGENTS.md`, `README.md`, `CONTRIBUTING.md`, `.github/release-template.md`, and these workflows from the target commit:
   - `.github/workflows/release-notes.yml`
   - `.github/workflows/publish-images.yml`
   - `.github/workflows/publish-chart.yml`, when present
   - every other workflow whose `on.release.types` includes `published`
2. Inspect `git status`, the current branch, worktrees, remotes, GitHub authentication, and repository visibility.
3. Work from a clean release worktree or an exact commit SHA. Never infer the release target from a dirty or unrelated current branch.
4. Run `git fetch --tags --prune origin`, resolve the default branch with `gh repo view`, and record the full `origin/<default-branch>` SHA.
5. List stable tags with `git tag --list 'v[0-9]*' --sort=-version:refname`. Exclude `cli-v*`, chart-only tags, and prereleases when choosing the previous server tag.
6. Select the next semantic version from repository convention and the actual change surface. Ask before proceeding when the version is ambiguous or implies a different compatibility promise.

## 2. Run the release preflight

Record all results before creating a tag:

- Confirm the candidate tag is absent locally, from `git ls-remote --tags origin`, and from `gh release view`.
- Confirm the target SHA is contained in the default branch and is the intended release tip.
- Review the full `previous_tag..target_sha` commit and file range.
- Enumerate merged PRs and inspect their titles, authors, bodies, labels, and relevant diffs. Do not derive user impact from commit subjects alone.
- Check CI, required checks, DCO/CLA results, security results, and project-specific staging evidence for the included PRs or target SHA.
- Surface failed, skipped, missing, or stale checks. Obtain explicit approval before accepting a compliance, deployment, security, or artifact-publishing exception.
- Verify the expected downstream workflows at the target SHA. In the current design, pushing `v*` creates a draft Release; publishing that draft triggers image, Helm chart, and other release consumers.
- Verify `gh`, Git, and any artifact-verification tools required by the repository are authenticated and available without printing credentials.

Stop if the default branch advances after release-note analysis. Re-fetch, update the target SHA, recompute the range, and regenerate the notes before asking for approval again.

## 3. Generate curated release notes

Use `.github/release-template.md` as the structural source of truth.

1. Compare the previous server tag with the target SHA.
2. Build a deduplicated PR list. Attribute entries to GitHub PR authors and use `#123` and `@author` formatting.
3. Write for operators and end users. State behavior, impact, required configuration, and migration steps; avoid implementation-only summaries.
4. Verify every claim against code, tests, documentation, PR evidence, or generated artifacts.
5. Remove empty sections. Do not invent performance gains, breaking changes, contributors, or compatibility guarantees.
6. Check whether each contributor had a merged PR before the previous release. List only actual first-time contributors.
7. When the range contains CLI changes but `cli/package.json` still has an already-published version, state that those changes require a later `cli-v*` release; do not imply they are already on npm.
8. End with the exact full changelog link: `https://github.com/iflytek/skillhub/compare/<previous_tag>...<tag>`.
9. Save the final Markdown in a task-local file for exact reuse and review it for unresolved `{{...}}` placeholders.

The Tag does not need to exist to write curated notes. If testing the repository generator locally, use its dry-run mode and treat the result as input for review, not as authoritative copy.

## 4. Present the publish gate

Before the first external mutation, show:

- repository and visibility;
- new tag and previous tag;
- exact target SHA and subject;
- whether the tag and Release are absent;
- known check or compliance exceptions;
- workflows that the Tag and Release publication will trigger;
- the final release-note summary or file;
- whether the Release is stable, prerelease, or draft-only.

Proceed only when the user has explicitly authorized the external release actions and any material exceptions.

## 5. Create and push the tag

Immediately before tagging:

1. Re-run `git fetch --tags --prune origin`.
2. Confirm the recorded target still equals `origin/<default-branch>`.
3. Recheck that the tag and Release do not exist remotely.
4. Create an annotated tag at the full SHA:

   ```bash
   git tag -a "<tag>" "<full-target-sha>" -m "Release <tag>"
   ```

5. Verify the tag object and peeled commit with `git cat-file`, `git show`, and `git rev-parse "<tag>^{}"`.
6. Push only the explicit tag ref:

   ```bash
   git push origin "refs/tags/<tag>"
   ```

Never force-push, move, delete, or recreate a remote release tag automatically. If it points to the wrong commit, stop and request a recovery decision.

## 6. Monitor draft generation

1. Locate the `AI Release Notes` run for the new tag and exact SHA.
2. Watch it to completion with `gh run watch <run-id> --exit-status`.
3. Inspect failed logs if it does not succeed.
4. Verify that a draft Release exists for the tag.

If the workflow fails before creating a draft, report the failure. With authorization, create a draft from the already-reviewed notes rather than pushing another tag. If a draft already exists, edit it; do not create a duplicate.

## 7. Replace the draft body and publish atomically

Inspect the draft before editing. Then replace its title and body and publish it in one operation so downstream `release.published` workflows observe the curated content:

```bash
gh release edit "<tag>" \
  --repo "<owner>/<repo>" \
  --verify-tag \
  --title "<tag>" \
  --notes-file "<release-notes-file>" \
  --draft=false \
  --latest
```

Use `--prerelease` only when the approved version is a prerelease. Do not publish first and replace the default body afterward.

## 8. Monitor downstream publication

Find all runs created by the Release publication for the exact tag and watch each required workflow. At minimum, inspect:

- `Publish Images` for server, web, scanner, and optional mirror jobs;
- `Publish Helm Chart` when the chart workflow exists;
- documentation or indexing workflows that listen to `release.published`.

Do not treat the Release page alone as proof that images or charts were published. On failure, preserve the tag and Release, inspect logs, and rerun or repair the failed workflow through its supported entry point.

## 9. Verify the public result

Verify and record:

- remote annotated tag and peeled commit equal the approved SHA;
- Release is public, non-draft, has the intended prerelease/latest flags, and contains the curated body;
- full changelog URL resolves to the intended range;
- all required release workflows completed successfully;
- `ghcr.io/iflytek/skillhub-server:<tag>`, `skillhub-web:<tag>`, and `skillhub-scanner:<tag>` manifests exist for the expected platforms;
- the OCI Helm chart exists at `oci://ghcr.io/iflytek/charts/skillhub` with the tag version, when applicable;
- optional mirror jobs are either successful or explicitly skipped because their secrets are not configured.

Report exact URLs, run IDs, artifact versions, commands, failures, skipped checks, and remaining risks. Remove only task-local temporary notes created for the release; preserve committed evidence and unrelated user files.

## Recovery rules

- If draft generation fails, use the reviewed notes to create or edit one draft after authorization.
- If final publication fails, do not move the Tag. Repair or rerun the failed downstream workflow.
- If the Release body is wrong but the Release is already public, edit the body and state that downstream workflows may already have observed the earlier content.
- If an image or chart exists with conflicting contents for the same immutable version, stop and escalate; do not overwrite it silently.
- If the default branch advanced before Tag creation, regenerate the release rather than silently releasing a different range.
