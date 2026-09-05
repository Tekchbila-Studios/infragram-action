# Infragr.am Action

Generate Infragr.am architecture diagrams from Terraform pull requests without sending raw plans or credentials outside the GitHub runner.

## Data boundary

This repository contains the complete collection and sanitization path:

1. An OIDC-authenticated preflight checks repository activation and account eligibility.
2. Terraform creates a binary plan locally only when eligible.
3. `infragram-collect` retains resource topology and removes Terraform-sensitive paths plus credential-shaped attributes. It also reads `locals` blocks from the configuration's `.tf` files — see below.
4. Gitleaks independently scans the exact serialized bundle.
5. Only that scanned bundle is sent to Infragr.am.

Standard profile keeps useful topology, including IP addresses, CIDRs, ports, names, regions, zones, and relationships. It removes passwords, keys, tokens, private key material, user data, connection strings, and all values marked sensitive by Terraform. More privacy profiles may be added through later bundle schema versions; only `standard` exists today.

### What is read from your `.tf` files

Terraform's JSON plan contains no locals. A module that writes `vpc_id = local.vpc_id` — which is how the widely used registry modules are built — produces a plan saying an attribute references `local.vpc_id` and never saying what that is. Every such reference used to be discarded, which cost those modules the links between their resources.

So the collector also reads the configuration directory it just planned. What it takes is deliberately narrow:

- **only** `locals` blocks, and **only** the names and the references inside them
- **never** an attribute's value, never file contents, never anything else

A local holding a literal contributes nothing. `locals { db_password = "hunter2" }` has no references and is dropped entirely. Even a mixed expression yields only the reference: `locals { x = "prefix-${aws_vpc.main.cidr_block}-suffix" }` emits `aws_vpc.main` and no part of the string. `TestScanLocalsNeverEmitsValues` pins this.

The bundle carries what the configuration says and stops there: `references` is every reference each resource makes, unresolved, and `symbols` is what the locals name. Resolving them — matching a reference to a resource, deciding which instance of a counted resource it means — happens after upload.

That split is deliberate. Extraction and redaction are this repository's job and are auditable here. Interpreting a reference for a diagram is not, and keeping it here meant every change to it needed a new release of this action in every workflow using it.

Gitleaks is defense in depth, not proof that arbitrary data contains no secret. Review collector source and `schemas/bundle-v3.schema.json` before adoption.

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
      - uses: actions/checkout@v7
      - uses: hashicorp/setup-terraform@v4
      - uses: Tekchbila-Studios/infragram-action@v1
        with:
          working-directory: infrastructure
          var-files: |
            environments/common.tfvars
            environments/production.tfvars
```

Variable files form one Terraform plan. Order matters: later files override earlier files.

A second environment needs its own plan and its own diagram build. Reach for a matrix rather than a second step: steps in a job run one after another, so two environments mean two full `init` + `plan` + scan cycles back to back, while matrix legs are separate jobs that run at the same time.

```yaml
jobs:
  diagram:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        environment: [staging, production]
    steps:
      - uses: actions/checkout@v7
      - uses: hashicorp/setup-terraform@v4
      - uses: Tekchbila-Studios/infragram-action@v1
        with:
          working-directory: infrastructure
          environment: ${{ matrix.environment }}
          var-files: |
            environments/common.tfvars
            environments/${{ matrix.environment }}.tfvars
```

Passing `environment` is required here, not decorative. Runs supersede each other within an environment, so two builds that both leave it unset are read as the same build and the later one replaces the earlier — the pull request ends up with one diagram instead of two.

`fail-fast: false` stops a plan failure in one environment from cancelling the other environment's diagram.

Leave `concurrency` at the workflow level, as in the example above. Moving it onto the job puts every matrix leg in one group, where `cancel-in-progress: true` has the legs cancel each other. A per-job group has to carry the matrix value in its name to stay correct.

Legs post within seconds of each other and are expected to reach the account's concurrent-build limit; submission queues rather than failing, as described below.

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

Preflight exits successfully without planning when the repository is inactive, not activated, over its monthly build allowance, or rate-limited. Submission repeats these checks to prevent races between workflows.

Reaching the account's concurrent-build limit is not one of those cases. A workflow that builds several variants of one repository posts them within seconds of each other and is expected to reach it, so submission waits and retries for up to five minutes rather than skipping the build. Every other refusal fails the step immediately, because none of them clear inside a workflow run.

## Reporting a problem

Every accepted build prints its run ID to the job log, raises it as a job annotation, and writes it to the job summary along with the build URL and, when set, the environment. It is also available to later steps as the `run-id` output. Quote that ID when raising a support case — it is how a build is located.

## Current constraints

- Linux runners only
- Terraform and Go must be available
- GitHub OIDC requires `id-token: write`
- GitHub App must be installed and repository activated in Infragr.am
- One Terraform root and one ordered variable-file set per Action invocation
- Additional Terraform arguments must not contain secrets; use `TF_VAR_*` environment variables backed by GitHub secrets
- A root whose `count` or `for_each` depends on values that only exist after apply cannot be planned, so it cannot be diagrammed

### Roots that cannot be planned

Terraform refuses to plan a configuration whose `count` or `for_each` depends on a value that does not exist until apply — an IPAM-allocated CIDR, an ID from a resource not yet created:

```
Error: Invalid count argument
The "count" value depends on resource attributes that cannot be determined
until apply, so Terraform cannot predict how many instances will be created.
```

There is no plan to diagram, and retrying cannot produce one. The Action reports this as a warning and exits successfully, so one such root does not turn a whole matrix red when every other environment produced a diagram. Apply what those counts depend on first, or point the Action at a root that can be planned.

The Action skips only when every error diagnostic is this known limitation. Mixed errors, other invalid `count` or `for_each` arguments, and unrecognized diagnostics still fail the step. Terraform's normal readable logs are preserved.

## Development

```bash
go test ./...
go vet ./...
bash scripts/run_test.sh
bash -n scripts/run.sh scripts/run_test.sh
go build ./cmd/infragram-collect
```
