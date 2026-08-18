# Infragr.am Action

Generate Infragr.am architecture diagrams from Terraform pull requests without sending raw plans or credentials outside the GitHub runner.

## Data boundary

This repository contains the complete collection and sanitization path:

1. An OIDC-authenticated preflight checks repository activation and account eligibility.
2. Terraform creates a binary plan locally only when eligible.
3. `infragram-collect` retains resource topology and removes Terraform-sensitive paths plus credential-shaped attributes.
4. Gitleaks independently scans the exact serialized bundle.
5. Only that scanned bundle is sent to Infragr.am.

Standard profile keeps useful topology, including IP addresses, CIDRs, ports, names, regions, zones, and relationships. It removes passwords, keys, tokens, private key material, user data, connection strings, and all values marked sensitive by Terraform. More privacy profiles may be added through later bundle schema versions; only `standard` exists today.

Gitleaks is defense in depth, not proof that arbitrary data contains no secret. Review collector source and `schemas/bundle-v1.schema.json` before adoption.

### Secret scan mode

`secret-scan` governs step 4 only. Steps 1–3 run identically in every mode, so the collector's redaction is never skipped.

| Mode | On a Gitleaks finding | Upload |
| --- | --- | --- |
| `block` (default) | Fails the run | Nothing is sent |
| `warn` | `::warning::` annotation | Bundle is sent anyway |
| `off` | Scan does not run | Bundle is sent unscanned |

A Gitleaks process that cannot complete — any exit status other than 0 or 1 — fails the run in every mode. A scanner that did not run is not a passing scan.

Lower `block` only for a specific, understood false positive. `warn` and `off` both mean bytes can leave the runner that the independent pass never approved.

## Usage

```yaml
name: Infrastructure diagram

on:
  pull_request:
    paths:
      - "**/*.tf"
      - "**/*.tfvars"
      - "**/.terraform.lock.hcl"

permissions:
  contents: read
  id-token: write

concurrency:
  group: infragram-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  diagram:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - uses: Tekchbila-Studios/infragram-action@v1
        with:
          working-directory: infrastructure
          var-files: |
            environments/common.tfvars
            environments/production.tfvars
```

Variable files form one Terraform plan. Order matters: later files override earlier files. Create another Action step when a second environment needs a separate plan and diagram build.

Individual variables can be overridden with `vars`, one `key=value` per line, passed as `-var`:

```yaml
- uses: Tekchbila-Studios/infragram-action@v1
  with:
    working-directory: infrastructure
    vars: |
      environment=production
      region=eu-west-1
```

Values are read line by line, so spaces are preserved without quoting. `vars` is committed to the repository in plain text and appears in plan output — never put a credential there. Secret-valued inputs belong in `TF_VAR_*` environment variables backed by GitHub secrets, which Terraform reads directly and which never pass through this Action.

Pin the Terraform version through `hashicorp/setup-terraform`, not this Action. Note that its `terraform_version` uses npm semver ranges, so a Terraform constraint such as `~> 1.9` is not valid there — use an exact version.

Existing pipelines may provide a binary plan instead:

```yaml
- uses: Tekchbila-Studios/infragram-action@v1
  with:
    working-directory: infrastructure
    plan-path: ${{ runner.temp }}/terraform.tfplan
```

`plan-path` avoids another `terraform init` and `terraform plan`. Infragr.am never requests cloud credentials; Terraform receives them from the surrounding customer workflow.

Preflight exits successfully without planning when the repository is inactive, not activated, over its monthly build allowance, rate-limited, or already at its concurrent-run limit. Submission repeats these checks to prevent races between workflows.

## Current constraints

- Linux runners only
- Terraform and Go must be available
- GitHub OIDC requires `id-token: write`
- GitHub App must be installed and repository activated in Infragr.am
- One Terraform root and one ordered variable-file set per Action invocation
- Additional Terraform arguments must not contain secrets; use `TF_VAR_*` environment variables backed by GitHub secrets

## Development

```bash
go test ./...
go vet ./...
go build ./cmd/infragram-collect
```
