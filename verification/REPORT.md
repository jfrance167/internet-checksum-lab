# Local verification — October 5, 2026

Approved stages1–4 and05:12 coordinator addendum implemented. WindowsCPython3.13.7
only; no new installation/repository. Exact schema,21full literal reports and5envelope
outcomes/status/invalid diagnostics were frozen before application code. Seven frozen
hashes unchanged; twelve current source/test/verifier/schema/oracle/fixture-authoring/
example files bound in receipt.json. Independent PowerShell reconciliation: zero
mismatches for both receipts. latest-run.json passed; failed/running means any prior
receipt is historical.

| Check | Actual outcome |
|---|---|
|`python -B -m unittest discover -s tests -v`|25passed; normal.log|
|`python -O -B -m unittest discover -s tests -v`|25passed; optimized.log|
|Full literal reports/envelopes|21reports/5envelopes matched including status/metadata/error LF|
|Independent one-byte/two-byte controls|256/65536passed|
|Independent column oracle|130lengths plus4096all-ones buffer passed|
|Anchored replacement oracle|562controls; both first/last offsets, all25boundary old/new pairs|
|Admission|strict types/BOM/-0/unknownversion/escaped duplicate keys/depth/strings/hex/closed fields/caps and late-invalid precedence passed|
|CLI|normal/-O modeled0/empty0/mixed3/invalid2/no stdout/help0/misuse2/unavailable2|
|Failure sinks|real normal/-O closed/both OS pipes and locally closed Python stdin/out/err preserve2|
|Count/short/flush seams|synthetic unit/actual normal/-O child controls on help/report/usage/error; floats/bools/None/exotic counts reject before equality hooks|
|Capability mocks|socket/DNS/process calls blocked on exercised API fixtures; no application imports/calls by source review|
|Odd-low-padding mutant|exit1,7assertion failures, intended padding assertion,0errors|
|Carry-dropped mutant|exit1,18assertion failures, intended carry assertion,0errors|
|Legacy-Eq2 mutant|exit1,6assertion failures, intended Eq3 assertion,0errors|
|Residual/equality mutant|exit1,3assertion failures, intended dual-zero assertion,0errors|
|Restoration|exact original bytes restored before final normal/O/compile/SAST|
|Compilation|exit0; compile.log|
|Bandit1.9.4|exit0;0findings/0errors/8narrow harness exclusions; bandit.json|

`python verification/verify.py` repeats fixed owned checks without network/install/
shell execution. Four mutants require intended FAIL names and reject ERROR failures.
Finally restores only own source and removes only three own source-cache paths.
Do not concurrently edit or forcibly terminate it. Receipt sourceSHA256:
`7180695ae63a355ad563cdbcea7adc1e8c4bfa1f20c0e98fdfea74b9b0deb715`.
No source/test/verifier changes after the final pass; completion documents followed.

## ECC actual-change self-review

Applied installed ecc-code-review/pinned reviewer checklist and ecc-verification-loop
to actual application, full admission/evaluation/serialization/CLI callers, tests,
verifier, original fixture-authoring script, frozen contract/oracles/examples and
docs. This is an implementation-agent self-review, not an independent audit. Full
native ECC runtime remains unavailable; installed narrow skill entry points were used.

Reviewed exact bytes identity before hooks, bounded UTF8/JSON grammar/duplicate keys,
common-before-math precedence, stricthex/types/caps, network-endian padding/carries,
zero representations, Eq3 masks/guard/Eq2 diagnosis and full recomputation, independent
oracle forms, bounded/no-hex scalar output, exact write counts/flush/detachment,
verifier restoration/unique targets/intended assertions and narrow subprocess scope.
The explicit selected CLI path is an authorized file read, not a server traversal
boundary. No upstream code execution/import or new dependency was introduced.

Confirmed LOW correctness issue during initial actual CLI test: Windows text newline
translation emitted CRLF instead of frozen LF for the invalid offset diagnostic.
test_actual_cli_examples_normal_optimized failed with actual
`checksum-lab: invalid replacement offset\r\n` versus expected ending`\n`.
Correction at checksum_lab.py native CLI entry point: configure stdout/stderr
`newline="\n"`. Byte-exact full CLI envelope tests pass normally/-O after correction.
This is a retained account of observed initial tool output, not a fabricated full
raw before-log. ValueError/OSError sink handling reused the reviewed owned pattern
and passed real local-close/broken-pipe controls; no additional app defect found.

Review also added coverage for actual report writes and locally closed report
streams, plus labeled count/short/flush report/error child seams and exercised
capability mocks. Final four mutations,25normal/Otests,compile/Bandit rerun after
test changes. Zero unresolved confirmed in-scope findings (critical/high/medium/low).
Local completion recommended; no publication/merge/deployment authorization implied.

Eight narrow Bandit exclusions: tests B404 plus five fixed B603 subprocess sites;
verifier B404 and one fixed B603 site. Application has no suppression. Scope is
installed Python/owned files and bounded child checks, no shell or foreign code.
Authored synthetic code/docs reviewed for private material; dedicated secret/history
scanner was not run. Raw upstream research text retains its notices/license separately.

## Output bounds and limits

output-stress.json records64rows,16384total decoded bytes,32-character IDs,40,409input
bytes and29,774output bytes under262,144. This largest admitted count/byte/label shape
is not an exact serialized maximum. Loose frozen scalar shape allowance
1600bytes/row +1024root =103424<262144; all IDs/strings bounded and fixed, no rawhex
echo, arithmetic values<=65535, offsets<=4094, counts<=4096. Fixed status/reason and
null/boolean spellings fit that allowance. Output cap still checked defensively;
one-byte output-cap test is an injected seam, not a claim of reachable valid overflow.

Limits are logical admission/output bounds, not hard RSS/time or host containment.
Capability mocks cover exercised paths; source review supports absence of network/
process features, not an isolation guarantee. Chosen blocking devices/pipes can block;
only ordinary bounded fixtures were used. Failing sinks may receive partial output.
No actual data transmission/protocol field validation/authentication/integrity claim.

Other Python/platforms, hostedCI/CodeQL, advisory/Scorecard/package execution,
independent review and dedicated secret/history scans NOT RUN. Original scanner live
Linux SYN remains unrun; prior labs/parent work/shared tools unchanged. No new
repository/install/real traffic/capture/device/upstream-code execution/spending.
