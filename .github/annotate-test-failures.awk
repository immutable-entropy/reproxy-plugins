# Turns `reproxy plugins test` output into GitHub Actions error annotations,
# one per failed test, so a red run points straight at the failures instead
# of making you read the log. Driven by .github/workflows/ci.yml with:
#   awk -v dir=plugins/<name>/ -v plugin=<name> -v summary=$GITHUB_STEP_SUMMARY \
#       -f .github/annotate-test-failures.awk
#
# A failure prints as two lines:
#   --- FAIL: test/hooks.test.ts > group > the test (12ms)
#       the assertion message
# so a FAIL line is remembered and the next non-blank line is its message.

function esc(s) { gsub(/%/, "%25", s); gsub(/\r/, "%0D", s); gsub(/\n/, "%0A", s); return s }

/^--- FAIL: / {
  rest = substr($0, length("--- FAIL: ") + 1)
  file = rest; sub(/ .*/, "", file)                       # the test file: the first token
  name = rest; sub(/ \([0-9]+ms\)[[:space:]]*$/, "", name) # the test, without the timing
  curfile = dir file; curname = name; pending = 1
  next
}

pending && /[^[:space:]]/ {
  msg = $0; sub(/^[[:space:]]+/, "", msg)
  printf "::error file=%s,title=%s::%s\n", curfile, esc(plugin ": " curname), esc(curname " - " msg)
  if (summary != "") print "- **" plugin "** `" curname "` - " msg >> summary
  pending = 0
}
