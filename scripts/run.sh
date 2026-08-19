#!/usr/bin/env bash
set -euo pipefail

readonly GITLEAKS_VERSION="8.28.0"
readonly GITLEAKS_LINUX_X64_SHA256="a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb"
readonly GITLEAKS_LINUX_ARM64_SHA256="eff65261156100e5d94a6b3dec313d532fddfe19ae1590bf7a2b4f2699128356"
readonly AUDIENCE="infragr.am"

fail() {
  printf '::error::%s\n' "$1" >&2
  exit 1
}

get_oidc_token() {
  [[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" && -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]] || \
    fail "GitHub OIDC unavailable. Add 'id-token: write' to workflow permissions."
  local response
  response="$(curl --fail --silent --show-error \
    -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
    "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${AUDIENCE}")"
  node -e 'const fs=require("fs"); const value=JSON.parse(fs.readFileSync(0,"utf8")).value; if(!value) process.exit(1); process.stdout.write(value)' <<< "$response" || \
    fail "GitHub did not issue an OIDC token."
}

[[ "${RUNNER_OS:-}" == "Linux" ]] || fail "Infragr.am Action currently supports Linux runners only."
command -v curl >/dev/null || fail "curl is required."
command -v node >/dev/null || fail "Node.js is required."

# Validated before anything expensive runs. Discovering a typo here after a
# ten-minute plan, at the point of upload, is the worst possible time.
secret_scan="${INPUT_SECRET_SCAN:-block}"
case "$secret_scan" in
  block|warn|off) ;;
  *) fail "secret-scan must be one of: block, warn, off. Got: $secret_scan" ;;
esac

preflight_file="$(mktemp "${RUNNER_TEMP:-/tmp}/infragram-preflight.XXXXXX")"
temp_dir=""
cleanup() {
  rm -f "$preflight_file"
  if [[ -n "$temp_dir" ]]; then
    rm -rf "$temp_dir"
  fi
}
trap cleanup EXIT
oidc_token="$(get_oidc_token)"
preflight_status="$(curl --silent --show-error --output "$preflight_file" --write-out '%{http_code}' \
  -X POST "${INPUT_API_URL%/}/api/action/preflight" \
  -H "Authorization: Bearer $oidc_token" \
  -H "Content-Type: application/json")"
if [[ "$preflight_status" -lt 200 || "$preflight_status" -ge 300 ]]; then
  message="$(node -e 'const fs=require("fs"); try { const x=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(x.error||"request failed") } catch { process.stdout.write("request failed") }' "$preflight_file")"
  fail "Infragr.am preflight returned HTTP $preflight_status: $message"
fi
eligible="$(node -e 'const fs=require("fs"); const x=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(x.eligible === true ? "true" : "false")' "$preflight_file")"
if [[ "$eligible" != "true" ]]; then
  reason="$(node -e 'const fs=require("fs"); const x=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(x.reason||"ineligible")' "$preflight_file")"
  printf '::notice::Infragr.am skipped this run: %s.\n' "$reason"
  exit 0
fi

command -v terraform >/dev/null || fail "terraform is required. Run hashicorp/setup-terraform before this action."
command -v go >/dev/null || fail "Go is required to build the auditable collector."

workdir="$(realpath "${INPUT_WORKING_DIRECTORY:-.}")"
[[ -d "$workdir" ]] || fail "Terraform working directory does not exist: $workdir"
temp_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/infragram.XXXXXX")"

collector="$temp_dir/infragram-collect"
(cd "$GITHUB_ACTION_PATH" && go build -trimpath -o "$collector" ./cmd/infragram-collect)

if [[ -n "${INPUT_PLAN_PATH:-}" ]]; then
  plan_path="$(realpath "$INPUT_PLAN_PATH")"
  [[ -f "$plan_path" ]] || fail "Terraform plan does not exist: $plan_path"
else
  plan_path="$temp_dir/terraform.tfplan"

  # Deliberately NOT -lockfile=readonly. A committed lock file is still honoured
  # in full — plain init selects exactly the versions it records and only
  # resolves what the lock cannot satisfy. Readonly turned two ordinary
  # situations into a dead end instead: a repository that never committed a lock
  # file, and the far more common one where the lock was generated on a
  # developer's macOS machine and carries no linux_amd64 hashes for this runner.
  # Nothing is written back either way; the checkout dies with the runner.
  if [[ ! -f "$workdir/.terraform.lock.hcl" ]]; then
    printf '::notice::No .terraform.lock.hcl in %s. Provider versions for this plan were resolved from your version constraints. Commit a lock file (terraform providers lock -platform=linux_amd64) to pin them.\n' "${INPUT_WORKING_DIRECTORY:-.}"
  fi
  terraform -chdir="$workdir" init -input=false

  plan_args=(plan -input=false -no-color -out="$plan_path")
  while IFS= read -r var_file; do
    [[ -z "$var_file" ]] && continue
    [[ "$var_file" != -* ]] || fail "var-files entries must be file paths."
    plan_args+=("-var-file=$var_file")
  done <<< "${INPUT_VAR_FILES:-}"

  # Read line by line rather than word-split, so a value containing spaces
  # reaches Terraform as one argument instead of several.
  while IFS= read -r var_override; do
    [[ -z "$var_override" ]] && continue
    [[ "$var_override" != -* ]] || fail "vars entries must be key=value, not flags."
    [[ "$var_override" == *=* ]] || fail "vars entries must be key=value. Got: $var_override"
    plan_args+=("-var=$var_override")
  done <<< "${INPUT_VARS:-}"

  if [[ -n "${INPUT_TERRAFORM_ARGS:-}" ]]; then
    read -r -a extra_args <<< "$INPUT_TERRAFORM_ARGS"
    plan_args+=("${extra_args[@]}")
  fi
  terraform -chdir="$workdir" "${plan_args[@]}"
fi

bundle="$temp_dir/bundle.json"
terraform -chdir="$workdir" show -json "$plan_path" | "$collector" -output "$bundle"

if [[ "$secret_scan" == "off" ]]; then
  # Said loudly on purpose. The collector still removed Terraform-sensitive
  # paths and credential-shaped attributes above; what is skipped is the
  # independent pass over the exact bytes about to be uploaded.
  printf '::warning::Infragr.am secret scanning is off for this run. The bundle was sanitized but not independently scanned before upload.\n'
else
  case "$(uname -m)" in
    x86_64|amd64)
      gitleaks_arch="x64"
      gitleaks_sha="$GITLEAKS_LINUX_X64_SHA256"
      ;;
    aarch64|arm64)
      gitleaks_arch="arm64"
      gitleaks_sha="$GITLEAKS_LINUX_ARM64_SHA256"
      ;;
    *) fail "Unsupported runner architecture: $(uname -m)" ;;
  esac

  archive="$temp_dir/gitleaks.tar.gz"
  curl --fail --silent --show-error --location \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gitleaks_arch}.tar.gz" \
    --output "$archive"
  printf '%s  %s\n' "$gitleaks_sha" "$archive" | sha256sum --check --status || fail "Gitleaks checksum verification failed."
  tar -xzf "$archive" -C "$temp_dir" gitleaks

  # Gitleaks exits 1 for findings. Any other non-zero status means Gitleaks
  # itself failed, and a scanner that could not run is never a warning — that
  # path uploads nothing regardless of the configured mode.
  scan_status=0
  "$temp_dir/gitleaks" stdin --no-banner --redact=100 < "$bundle" || scan_status=$?
  if [[ "$scan_status" -gt 1 ]]; then
    fail "Gitleaks could not complete the scan (exit $scan_status); nothing was uploaded."
  fi
  if [[ "$scan_status" -eq 1 ]]; then
    [[ "$secret_scan" == "warn" ]] || fail "Gitleaks found a potential secret in sanitized output; nothing was uploaded."
    printf '::warning::Gitleaks flagged a potential secret in the sanitized bundle. secret-scan is set to warn, so it was uploaded anyway.\n'
  fi
fi

oidc_token="$(get_oidc_token)"

response_file="$temp_dir/response.json"
status="$(curl --silent --show-error --output "$response_file" --write-out '%{http_code}' \
  -X POST "${INPUT_API_URL%/}/api/action/runs" \
  -H "Authorization: Bearer $oidc_token" \
  -H "Content-Type: application/json" \
  -H "X-Infragram-Event: ${GITHUB_EVENT_NAME:-unknown}" \
  -H "X-Infragram-Environment: ${INPUT_ENVIRONMENT:-}" \
  -H "X-Infragram-PR: $(node -e 'const fs=require("fs"); try { const e=JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH,"utf8")); process.stdout.write(String(e.number||e.pull_request?.number||"")) } catch {}')" \
  --data-binary "@$bundle")"
if [[ "$status" -lt 200 || "$status" -ge 300 ]]; then
  message="$(node -e 'const fs=require("fs"); try { const x=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(x.error||"request failed") } catch { process.stdout.write("request failed") }' "$response_file")"
  fail "Infragr.am API returned HTTP $status: $message"
fi

node - "$response_file" "$GITHUB_OUTPUT" <<'NODE'
const fs = require("fs");
const response = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
fs.appendFileSync(process.argv[3], `run-id=${response.run.id}\nrun-url=${response.run_url}\n`);
NODE
printf 'Sanitization and independent Gitleaks scan passed. Diagram build submitted.\n'
