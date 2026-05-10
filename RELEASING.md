# Releasing phip-py

Releases are driven by a git tag of the form `vX.Y.Z` on `main`. The
[release workflow](.github/workflows/release.yml) builds an sdist + a
wheel, publishes to PyPI via [trusted publishing](https://docs.pypi.org/trusted-publishers/)
(OIDC — no API token in CI), and creates a GitHub Release with notes
pulled from `CHANGELOG.md`.

## One-time setup

Before the first release publishes successfully, register this repo as
a trusted publisher on PyPI:

1. Reserve the project name on PyPI (one-time, manual): upload an
   initial sdist with `twine` from a workstation, or pre-register the
   name via PyPI's web UI.
2. Go to <https://pypi.org/manage/project/phip/settings/publishing/>
   and add a **GitHub Actions trusted publisher** with:
   - Owner: `mfgs-us`
   - Repository: `phip-py`
   - Workflow filename: `release.yml`
   - Environment name: `pypi`
3. In this repo's GitHub settings, create an environment named `pypi`
   under **Settings → Environments**. No secrets required; the OIDC
   token authenticates the publish step.

After that, every tag push triggers a fully automated release.

## Cutting a release

1. **Bump the version** in `pyproject.toml`. Follow
   [PEP 440](https://peps.python.org/pep-0440/) and the project's
   pinning rules (spec-MAJOR alignment per
   [VERSIONING.md](https://github.com/mfgs-us/phip/blob/main/VERSIONING.md)).
   - Alpha: `0.1.0a3`
   - Beta:  `0.1.0b1`
   - RC:    `0.1.0rc1`
   - Final: `0.1.0`
2. **Update `CHANGELOG.md`**: change `## [X.Y.Z] — Unreleased` to
   `## [X.Y.Z] — YYYY-MM-DD` and add a fresh `## [next] — Unreleased`
   stub above it for the next cycle's accumulating notes.
3. **Confirm CI is green** on `main`. The release workflow does not
   re-run pytest/ruff/mypy; the `ci.yml` run on the merge commit is
   the gate.
4. **Commit** the version + changelog bumps with a message like
   `Release vX.Y.Z`.
5. **Tag and push**:
   ```bash
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin main --follow-tags
   ```
6. **Watch the workflow**: <https://github.com/mfgs-us/phip-py/actions/workflows/release.yml>.
   It will:
   1. Verify the tag matches `pyproject.toml`'s `version`.
   2. Build sdist + wheel via `python -m build`.
   3. Publish to PyPI (trusted publisher, OIDC).
   4. Create a GitHub Release with the corresponding CHANGELOG
      section as the body.
7. **Smoke-test the published artifact**:
   ```bash
   pip install --upgrade phip==X.Y.Z
   python -c "from phip import PROTOCOL_VERSION; print(PROTOCOL_VERSION)"
   ```

## What the workflow does NOT do

- **Auto-bump versions** — intentional. Releases are a deliberate act.
- **Auto-write CHANGELOG entries** — the changelog is curated, not
  generated.
- **Push to TestPyPI first** — for `0.x` alphas this is an acceptable
  tradeoff. Add a TestPyPI gate before `1.0`.
- **Sign artifacts with sigstore** — Python wheels are not yet
  routinely consumed with sigstore verification. Revisit at `1.0`.

## Yanking a release

If a release ships broken:
1. Yank from PyPI: <https://pypi.org/manage/project/phip/releases/>
   → select version → **Yank**. Yanked versions stay installable by
   exact pin but are skipped by resolvers.
2. Mark the corresponding GitHub Release as a pre-release or delete it.
3. Publish a follow-up patch (`X.Y.Z+1`) — never re-tag the same
   version.

## Spec-version alignment

This library's MAJOR.MINOR pins to the PhIP spec it implements:

| Library version | PhIP spec version |
|---|---|
| `0.1.x`         | `0.1.x` (currently `0.1.0-draft`) |
| `0.2.x`         | `0.2.x`                            |
| `1.0.x`         | `1.0.x`                            |

PATCH versions are independent on each side. Breaking spec changes
require a coordinated MAJOR bump on both repos.
