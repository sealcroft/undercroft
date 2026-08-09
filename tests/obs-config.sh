#!/usr/bin/env bash
# The observability CONFIG suite: the alert rules and the Alertmanager route
# are validated by the tools that will execute them, at the versions the
# stack deploys.
#
#   docker compose run --rm --build obs-config
#
# It exists because of a defect nothing in the repo could see. `alerts.yml`
# was valid, `alertmanager.yml` was valid, `cargo test` was green, and the
# inhibition rule silenced every warning in the fleet whenever one critical
# fired — because it scoped itself with `equal:` on a label no rule emitted,
# and Alertmanager treats a label absent from BOTH sides as equal. The
# failure mode was an alert that never arrived: nothing logs that.
#
# Four checks, each measuring something a different way of being wrong moves:
#   1. promtool check rules   — the rule files parse and the PromQL compiles
#   2. promtool test rules    — each rule fires when it should, does not when
#                               it should not, and emits the exact label set
#                               alerts_test.yml declares (real evaluation, so
#                               it cannot agree with the rules by construction)
#   3. amtool check-config    — the routing tree and receivers are valid
#   4. the join between them  — every label Alertmanager equals on is a label
#                               the tested alerts actually carry, and every
#                               rule has a test block
#
# Exit code is the verdict. No pipelines around the tools: a pipeline's
# status is its LAST command's, which is how `| grep` turns a failing check
# into a passing suite.
set -u

cd "$(dirname "$0")/.."

OBS=deploy/observability
RULES="$OBS/alerts.yml"
TESTS="$OBS/alerts_test.yml"
AM="$OBS/alertmanager/alertmanager.yml"

pass=0
fail=0
ok()   { pass=$((pass + 1)); echo "  ok    $1"; }
bad()  { fail=$((fail + 1)); echo "  FAIL  $1"; }
run()  { # run <description> <command...>
  local what="$1"; shift
  local out
  out=$("$@" 2>&1)
  local code=$?
  if [ "$code" -eq 0 ]; then
    ok "$what"
  else
    bad "$what (exit $code)"
    echo "$out" | sed 's/^/        /'
  fi
}

echo "═══ 1. promtool check rules ═══"
run "alerts.yml is a valid rule file" promtool check rules "$RULES"

echo "═══ 2. promtool test rules ═══"
# `promtool test rules` resolves `rule_files:` relative to the TEST file, so
# it has to run from that directory.
run "every alert fires, stays quiet, and carries the labels it claims" \
  sh -c "cd '$OBS' && promtool test rules '$(basename "$TESTS")'"

echo "═══ 3. amtool check-config ═══"
run "alertmanager.yml is a valid config" amtool check-config "$AM"

echo "═══ 4. the join: inhibition is scoped by a label every alert emits ═══"
# Alertmanager's `equal:` scopes an inhibition. A label that is absent from
# both the source and the target alert counts as EQUAL, so equalling on a
# label nothing emits does not narrow the rule — it widens it to everything.
# Check 2 has just proved that the label sets in alerts_test.yml are the ones
# the rules really emit; this requires the `equal:` labels to be present in
# every one of them, which closes the loop.
EQUAL_LABELS=$(awk '
  /^inhibit_rules:/      { in_inhibit = 1 }
  # Comments are not config. The first run of this check read the comment
  # ABOVE the rule — which quotes the old broken `equal:` line to explain
  # what went wrong — and reported the defect as still present. A checker
  # that cannot tell a config from a note about the config is measuring the
  # wrong bytes, which is the failure this whole suite exists to prevent.
  in_inhibit && /^[[:space:]]*#/ { next }
  in_inhibit && /equal:/ { line = $0
                           gsub(/.*equal: *\[/, "", line)
                           gsub(/\].*/, "", line)
                           gsub(/["'\'' ]/, "", line)
                           n = split(line, parts, ",")
                           for (i = 1; i <= n; i++) if (parts[i] != "") print parts[i] }
' "$AM")

if [ -z "$EQUAL_LABELS" ]; then
  bad "found no equal: labels in $AM — the extraction is broken, or an \
inhibit rule has no equal: at all (which inhibits globally)"
else
  for label in $EQUAL_LABELS; do
    # Every `exp_labels:` block in the test file must carry the label.
    missing=$(awk -v want="$label" '
      /exp_labels:/ { block = 1; has = 0; name = "?"; next }
      block && $1 == "alertname:" { name = $2 }
      block && $1 == want":"      { has = 1 }
      block && /exp_annotations:/ { if (!has) print name; block = 0 }
    ' "$TESTS" | sort -u)
    if [ -n "$missing" ]; then
      bad "alertmanager inhibits on '$label', which these alerts do not emit:"
      echo "$missing" | sed 's/^/        /'
      echo "        An alert missing the label is NOT excluded from the"
      echo "        inhibition — it is silenced unconditionally."
    else
      ok "every tested alert emits '$label'"
    fi
  done
fi

# And every rule must have a test block, or an untested rule could drop the
# label while check 4 still passes over the rules that kept it.
RULE_NAMES=$(grep -oE '^ *- alert: *[A-Za-z0-9_]+' "$RULES" | awk '{print $NF}' | sort -u)
for name in $RULE_NAMES; do
  if grep -q "alertname: *$name\$" "$TESTS"; then
    ok "$name has a test block"
  else
    bad "$name has no block in $TESTS — it is unverified, and the label check \
above cannot see it"
  fi
done

echo ""
echo "obs-config results: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
