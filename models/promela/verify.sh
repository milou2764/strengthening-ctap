#!/usr/bin/env bash
#
# Verifies the SPIN/Promela models against their expected outcomes.
#
# For each scenario it runs `spin -a` (with the scenario's -D switches), compiles
# the verifier, and checks the named LTL claim with pan. It then compares the
# outcome (HOLDS / VIOLATED) against what the paper expects and prints PASS/FAIL.
#
# Three kinds of expected outcome:
#   HOLDS               a safety property that must hold under the defense;
#   VIOLATED (control)  a NEGATIVE control: removing part of the defense must
#                       break the property (this is the point being made);
#   VIOLATED (witness)  a non-vacuity witness: the claim "nothing ever succeeds"
#                       is refuted, proving the legitimate run is reachable.
#
# A final pass re-verifies EVERY configuration of the table with its LTL claims
# stripped, so that pan checks for invalid end states (deadlock-freedom).
#
# Requires SPIN and a C compiler. Exit status is non-zero if any check fails.

set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

command -v spin >/dev/null 2>&1 || { echo "error: spin not found (install SPIN: https://spinroot.com/)"; exit 127; }
command -v cc   >/dev/null 2>&1 || { echo "error: no C compiler (cc) found"; exit 127; }

BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
cp ./*.pml "$BUILD/"

# model | -D switches | claim | expected | description
runs=(
  "model-legitimate.pml||p_auth|HOLDS|nominal ceremony: access granted implies the legitimate client requested it"

  "model-counter-measures.pml||p_auth|HOLDS|generative intruder, two sessions: no unenrolled client is ever served"
  "model-counter-measures.pml|-DNO_COUNTERMEASURE|p_auth|VIOLATED-control|baseline CTAP: the intruder is served"
  "model-counter-measures.pml|-DNO_FRESHNESS|p_auth|VIOLATED-control|reused session identifier (transcript hash): SPIN finds the cross-session replay itself"
  "model-counter-measures.pml||p_reachable|VIOLATED-witness|a legitimate authentication can still be granted (non-vacuity)"

  "model-enrollment.pml|-DCOMMITTED_CODE|p_binding|HOLDS|unbiasable code (SSP-style commitment): the intruder cannot make two pairings agree"
  "model-enrollment.pml|-DCOMMITTED_CODE -DGLOBAL_CLIENT_KEY|p_binding|HOLDS|an unbiasable code protects even a reused client key"
  "model-enrollment.pml||p_binding|VIOLATED-control|key-derived code: SPIN finds the cross-pairing mix-up even with per-authenticator keys"
  "model-enrollment.pml|-DGLOBAL_CLIENT_KEY|p_binding|VIOLATED-control|key-derived code plus a reused client key: no concurrent enrollment needed"
  "model-enrollment.pml|-DCOMMITTED_CODE -DNO_NUMERIC_COMPARISON|p_binding|VIOLATED-control|without the numeric comparison anything gets enrolled"
  "model-enrollment.pml|-DCOMMITTED_CODE|e_reachable|VIOLATED-witness|a legitimate enrollment can complete (non-vacuity)"
)

# model | -D switches  (deadlock / invalid-end-state checks)
safety=(
  "model-legitimate.pml|"
  "model-counter-measures.pml|"
  "model-counter-measures.pml|-DNO_COUNTERMEASURE"
  "model-counter-measures.pml|-DNO_FRESHNESS"
  "model-enrollment.pml|-DCOMMITTED_CODE"
  "model-enrollment.pml|-DCOMMITTED_CODE -DGLOBAL_CLIENT_KEY"
  "model-enrollment.pml|"
  "model-enrollment.pml|-DGLOBAL_CLIENT_KEY"
  "model-enrollment.pml|-DCOMMITTED_CODE -DNO_NUMERIC_COMPARISON"
)

pass=0
fail=0
printf '%-6s | %-46s | %-11s | %s\n' "RESULT" "MODEL / SWITCHES" "CLAIM" "OUTCOME"
printf -- '-------+------------------------------------------------+-------------+--------\n'

for r in "${runs[@]}"; do
  IFS='|' read -r model defs claim expect desc <<<"$r"

  ( cd "$BUILD" && spin -a $defs "$model" >/dev/null 2>&1 && cc -O2 -o pan pan.c 2>/dev/null )
  errs="$(cd "$BUILD" && ./pan -a -N "$claim" 2>&1 | grep -oE 'errors: [0-9]+' | awk '{print $2}')"

  if [ "${errs:-x}" = "0" ]; then actual="HOLDS"; else actual="VIOLATED"; fi

  # The expected field is HOLDS, or VIOLATED-control / VIOLATED-witness.
  case "$expect" in
    HOLDS)    want="HOLDS" ;;
    VIOLATED*) want="VIOLATED" ;;
  esac

  if [ "$actual" = "$want" ]; then res="PASS"; pass=$((pass+1)); else res="FAIL"; fail=$((fail+1)); fi

  label="${model%.pml} ${defs:-(nominal)}"
  printf '%-6s | %-46s | %-11s | %s\n' "$res" "$label" "$claim" "$actual — $desc"
done

# Deadlock-freedom: strip the ltl claims so pan checks invalid end states.
for r in "${safety[@]}"; do
  IFS='|' read -r model defs <<<"$r"
  stripped="noltl-${model}"
  ( cd "$BUILD" && perl -0pe 's/ltl \w+ \{[^}]*\}//g' "$model" > "$stripped" \
      && spin -a $defs "$stripped" >/dev/null 2>&1 && cc -O2 -o pan pan.c 2>/dev/null )
  errs="$(cd "$BUILD" && ./pan 2>&1 | grep -oE 'errors: [0-9]+' | awk '{print $2}')"

  if [ "${errs:-x}" = "0" ]; then res="PASS"; pass=$((pass+1)); else res="FAIL"; fail=$((fail+1)); fi
  label="${model%.pml} ${defs:-(nominal)}"
  printf '%-6s | %-46s | %-11s | %s\n' "$res" "$label" "end states" "${errs:-?} invalid end states — deadlock-freedom"
done

echo
echo "Summary: $pass passed, $fail failed."
[ "$fail" -eq 0 ]
