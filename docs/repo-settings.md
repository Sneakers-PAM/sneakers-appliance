# Repository settings

The settings that protect releases of this repo. They live on GitHub, not in the tree; the JSON
files here are what was applied, so they can be reapplied or reviewed.

## Branch ruleset (`main`)

Applied with the hub's `scaffold/apply-ruleset.sh`. It blocks deletion and force-push, requires a
squash-merged pull request, and requires these checks: `checks / scrub`, `🧪 Build & Test`,
`🔐 Gosec`, `🛡️ Govulncheck`, `🔏 License headers` and `⚖️ Dependency licenses (Go)`.

## Tag rulesets (`refs/tags/v*`)

- `build/ci/tag-ruleset.json` (`v-tags-immutable`): a `v*` tag can't be moved or deleted. No bypass
  actors, so nobody can rewrite a published release tag.
- `build/ci/tag-create-ruleset.json` (`v-tags-owner-only`): only an organization admin (the owner)
  can create a `v*` tag. Nothing in CI creates tags.

```bash
gh api -X POST repos/Sneakers-PAM/sneakers-appliance/rulesets --input build/ci/tag-ruleset.json
gh api -X POST repos/Sneakers-PAM/sneakers-appliance/rulesets --input build/ci/tag-create-ruleset.json
```

## The `production` environment

Read only by the tag release job's `sign` step. The owner is its required reviewer, and its
deployment rule allows `v*` tags only. Its secrets (`SB_PK_KEY`, `SB_KEK_KEY`, `SB_DB_KEY`,
`RELEASE_COSIGN_KEY`, `RELEASE_COSIGN_PASSWORD`) are set by the owner from the production keys
runbook; pull requests and tests never read them and use throwaway lab keys instead.

The `sign` job reads only `SB_DB_KEY`, `RELEASE_COSIGN_KEY` and `RELEASE_COSIGN_PASSWORD`; the PK and
KEK keys sign the committed enrolment files once, by hand. The `.bin` is encrypted to the committed
`keys/production/update.pub`, so no secret holds the update key ([release.md](release.md)).
