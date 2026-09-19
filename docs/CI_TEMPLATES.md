# CI Templates *(next release)*

Copy-paste pipeline snippets for platforms without a native SessLint
action — GitLab CI, Azure Pipelines, CircleCI. GitHub users should use the
composite action instead (`.github/actions/sesslint-check`).

<!-- next-release -->

Conventions shared by every template below:

- **Pinned install**: `pip install sesslint==X.Y.Z` — never a floating
  `latest`; bump deliberately.
- **Exit codes**: `0` clean · `1` findings at or above `--fail-on`
  threshold · `2` usage/I-O error. CI steps fail naturally on `1`.
- **Flags**: `--fail-on error|warning`, `--output-format human|json|sarif|html`,
  `--profile`, `--format`, `--select`, `--ignore`, `--baseline`,
  `--exclude`, `--ext`, `--skip-undetected`, `--config` — same surface as
  the GitHub action inputs (parity table below).
- **Reports**: JSON/SARIF are emitted on stdout — redirect to a file and
  upload as an artifact.
- Templates are **reference implementations** — adapt job names, stages,
  and images to your pipeline.

## GitLab CI

<!-- next-release -->

```yaml
# ci-template: gitlab
sesslint-check:
  stage: test
  image: python:3.12-slim
  script:
    - pip install sesslint==0.2.0
    - sesslint scan sessions/ --output-format json --fail-on error > sesslint-report.json
  artifacts:
    when: always
    paths:
      - sesslint-report.json
    expire_in: 30 days
```

Notes: `scan` on a directory walks the tree with the standard exclusions;
add `--skip-undetected` if the tree mixes non-session files.

## Azure Pipelines

<!-- next-release -->

```yaml
# ci-template: azure
steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: "3.12"
  - script: |
      pip install sesslint==0.2.0
      sesslint scan sessions/ --output-format json --fail-on error > $(Build.ArtifactStagingDirectory)/sesslint-report.json
    displayName: "Run SessLint integrity scan"
  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: "$(Build.ArtifactStagingDirectory)"
      artifactName: "sesslint-report"
    condition: always()
```

For SARIF-based code scanning surfaces (e.g. a SARIF results tab
extension), switch the invocation to `--output-format sarif` and publish
that file instead.

## CircleCI

<!-- next-release -->

```yaml
# ci-template: circleci
version: 2.1
jobs:
  sesslint-check:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
      - run:
          name: "Install SessLint (pinned)"
          command: pip install sesslint==0.2.0
      - run:
          name: "Run integrity scan"
          command: sesslint scan sessions/ --output-format json --fail-on error > sesslint-report.json
      - store_artifacts:
          path: sesslint-report.json
workflows:
  integrity:
    jobs:
      - sesslint-check
```

## Flag parity vs the GitHub action

<!-- next-release -->

Every action input maps to the identical CLI flag:

| Action input | CLI flag | Template default |
| --- | --- | --- |
| `path` | positional `PATH` | `sessions/` — point at your tree |
| `profile` | `--profile` | `neutral` |
| `format` | `--format` | `auto` |
| `fail-on` | `--fail-on` | `error` |
| `select` | `--select` | — |
| `ignore` | `--ignore` | — |
| `baseline` | `--baseline` | — |
| `write-baseline` | `--write-baseline` | — |
| `exclude` | `--exclude` | — |
| `ext` | `--ext` | — |
| `skip-undetected` | `--skip-undetected` | — |
| `config` | `--config` | — |
| `output-format` | `--output-format` | `json` (redirect to artifact) |
| `package` / `source-ref` | install line | `sesslint==0.2.0` |
| `python-version` | runner image | `3.12` |
| `sarif` output | `--output-format sarif` | redirect to artifact file |
