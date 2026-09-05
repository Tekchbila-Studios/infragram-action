#!/usr/bin/env bash
set -euo pipefail

export GITHUB_ACTION_PATH
GITHUB_ACTION_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export RUNNER_TEMP
RUNNER_TEMP="$(mktemp -d "${TMPDIR:-/tmp}/infragram-test.XXXXXX")"
trap 'rm -rf "$RUNNER_TEMP"' EXIT
export RUNNER_OS=Linux INPUT_API_URL=https://example.invalid
export INPUT_WORKING_DIRECTORY="$RUNNER_TEMP"
export ACTIONS_ID_TOKEN_REQUEST_URL=https://example.invalid/oidc
export ACTIONS_ID_TOKEN_REQUEST_TOKEN=test
export INPUT_PLAN_PATH="" INPUT_VAR_FILES="" INPUT_VARS="" INPUT_TERRAFORM_ARGS="" INPUT_SECRET_SCAN=off

# Run the real entrypoint without network access, Go builds, or cloud resources.
curl() {
  local output=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --output) output="$2"; shift ;;
    esac
    shift
  done
  if [[ -n "$output" ]]; then
    printf '{"eligible":true}' > "$output"
    printf '200'
  else
    printf '{"value":"test-token"}'
  fi
}
go() { :; }
terraform() {
  case "$2" in
    init) return 0 ;;
    plan)
      printf 'plan\n' >> "$RUNNER_TEMP/calls"
      printf '%s\n' "$TEST_LOG"
      return "$TEST_PLAN_STATUS"
      ;;
    *) printf 'Unexpected Terraform command\n' >&2; return 99 ;;
  esac
}
export -f curl go terraform

count='Error: Invalid count argument

  on main.tf line 5, in resource "terraform_data" "example":
   5:   count = terraform_data.source.output

The "count" value depends on resource attributes that cannot be determined
until apply, so Terraform cannot predict how many instances will be created.
To work around this, use the -target argument to first apply only the resources
that the count depends on.'
for_each_map='Error: Invalid for_each argument

The "for_each" map includes keys derived from resource attributes that cannot
be determined until apply, and so Terraform cannot determine the full set of
keys that will identify the instances of this resource.'
for_each_set="${for_each_map/map includes keys/set includes values}"
invalid_each='Error: Invalid for_each argument

The given "for_each" argument value is unsuitable: the given "for_each"
argument value is null. A map, or set of strings is allowed.'
other='Error: Unsupported attribute

This object does not have an attribute named "missing".'
warning='Warning: Deprecated attribute

Use the replacement attribute instead.'

check() {
  local name="$1" expected="$2" status=0 output
  export TEST_LOG="$3" TEST_PLAN_STATUS="${4:-1}"
  : > "$RUNNER_TEMP/calls"
  output="$(bash "$GITHUB_ACTION_PATH/scripts/run.sh" 2>&1)" || status=$?
  if [[ "$status" -ne "$expected" || "$output" != *"$TEST_LOG"* ]]; then
    printf 'FAIL %s: exit=%s, expected=%s\n%s\n' "$name" "$status" "$expected" "$output" >&2
    exit 1
  fi
  if [[ "$expected" -eq 0 ]]; then
    [[ "$output" == *'::warning::No diagram'* ]] || exit 1
  else
    [[ "$output" == *'::error::terraform plan failed'* && "$output" != *'::warning::No diagram'* ]] || exit 1
  fi
  [[ "$(< "$RUNNER_TEMP/calls")" == plan ]] || { printf 'Plan ran more than once\n' >&2; exit 1; }
  printf 'PASS %s\n' "$name"
}

check count 0 "$count"
check for_each_map 0 "$for_each_map"
check for_each_set 0 "$for_each_set"
check multiple_limitations 0 "$count

$for_each_map

$for_each_set"
check warnings 0 "$warning

$count

$warning"
check mixed_other_after 1 "$count

$other"
check mixed_other_before 1 "$other

$count"
check invalid_for_each 1 "$invalid_each"
check mixed_invalid_for_each 1 "$for_each_map

$invalid_each"
check sensitive_for_each 1 "$for_each_set

Error: Invalid for_each argument

Sensitive values, or values derived from sensitive values, cannot be used as
for_each arguments."
check mixed_invalid_count 1 "$count

Error: Invalid count argument

The given \"count\" argument value is null. An integer is required."
check phrase_in_other_diagnostic 1 "$invalid_each

Error: Other failure

Values cannot be determined until apply."
check phrase_in_warning 1 "$invalid_each

Warning: Unknown values

${for_each_map#*$'\n\n'}"
check empty 1 ""
check no_errors 1 "$warning"
check missing_body 1 'Error: Invalid count argument'
check mixed_missing_body 1 "Error: Invalid count argument

$count"
check mismatched_detail 1 "Error: Invalid for_each argument

${count##*$'\n\n'}"
check source_code_not_detail 1 'Error: Invalid count argument

  on main.tf line 5:
   5: description = "The \"count\" value depends on resource attributes that cannot be determined until apply, so Terraform cannot predict how many instances will be created."

The given "count" argument value is null. An integer is required.'
check truncated_body 1 'Error: Invalid count argument

The "count" value depends on resource attributes that cannot be determined'
check malformed_heading 1 "$count

Error

Malformed diagnostic"
check malformed_json 1 '{"type":"diagnostic","diagnostic":'
check json_not_human_output 1 '{"type":"diagnostic","diagnostic":{"severity":"error","summary":"Invalid count argument","detail":"cannot be determined until apply"}}'
check interrupted_plan 1 "$count" 130
check crlf 0 "${count//$'\n'/$'\r\n'}"
