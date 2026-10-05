# Internet checksum lab — concrete proposed plan

Tier3 bounded networking teaching tool; original research plan retained with approval and completion. Authorized research by
coordinator SUCCESSORS.md October5 04:39 under Jake's direct overnight delegation.
**APPROVED stages1–4 at coordinator SUCCESSORS.md October5 05:12; recorded before code.**
Addendum: freeze full independent reports/status/error priority for every planned
control and mixed envelope before application; preserve correction provenance.
FOUR mandatory assertion mutants: padding/carry/legacyEq2 and residual-versus-equality.
Exact built-in integer write counts required (float/bool/None invalid) for all output
paths; bytes-subclass identity rejection must precede hooks. Actual normal/-O sink
failures preserve2; synthetic seams labeled. No new routine approval pause.
Same chat/sole writer/separate directory; cutoffOctober6 08:00 Eastern. RESEARCH.md
records actual sources/reuse/license/maintenance and retrieval limits. tasks/todo.md
is the ordered acceptance/checkpoint target; tasks/plan.md points here.

## Problem, success and recommendation

Full-buffer arithmetic, a supplied-checksum residual and incremental replacement
equivalence are different claims. Build a small supplied-byte tool that exposes odd
padding/end-around carry, both zero representations, guarded incremental updates and
known checksum collisions without asserting real transmission integrity/authenticity.
Success: published/hand vectors reproduce exactly; full recomputation and supported
incremental replacement agree; malformed input is rejected before evaluation; explicit
unsupported-domain and residual/equality distinctions; bounded repeatable evidence.

Adopt the smallest owned MIT big-endian full-buffer checksum helper after source
review; build original stdlib JSON/API/guarded update around it, no sibling imports.
Do not fork/install dpkt/Scapy: broad packet/build/license scope and missing teaching
contract. Strongest inspected candidates/source evidence in RESEARCH; no exhaustive
search or safety certification. Alternative CRC-32C profile based on RFC3309 needs
polynomial/init/reflection/serialization choices and different independent vectors.
Defer CRC implementation; no universal relative error-detection/security ranking.

Scope: Python3.11+ intended, test installed WindowsCPython3.13.7 and disclose other
runtimes/platforms unverified. Standard-library application, no installation. No
real packets/captures/counters/data/devices/socket/DNS/traffic, protocol parser/builder,
pseudo-header/IP/TCP/UDP/SCTP fields, offload, resizing/reassembly, checksum field
auto-zeroing, UDP zero remapping, authentication/integrity verdict, file crawling,
new repository/publication/paid calls/host changes/upstream execution or third-party tests.

## Exact proposed admission and API

`analyze(data: bytes) -> dict`, exact built-in bytes by identity check before len/
decoding, no native object convenience API/coercion/custom hooks. Root exactly
`{"version":1,"cases":[...]}`. Exact built-in integer version1, bool invalid; unknown
version invalid. Cases0..64, unique case-sensitive IDs matching
`[A-Za-z0-9][A-Za-z0-9-]{0,31}`; trailing hyphen admitted. Exact key sets:

| Operation | Required fields |
|---|---|
| checksum |id,operation="checksum",data_hex|
| verify |id,operation="verify",data_hex,supplied_checksum|
| replace_word |id,operation="replace_word",data_hex,offset,new_word|

Hex is an exact string of even length0..8192, only ASCII `[0-9A-Fa-f]`, no whitespace,
prefixes, separators, signed/odd-length text or normalization. Accept uppercase;
decode only AFTER character/length checks. At most4096 decoded bytes per case,
16384 total decoded supplied bytes across envelope; count duplicates separately.
checksum/verify allow empty/odd byte length. replace_word requires EVEN byte length
4..4096, exact integer offset0..length-2 and even (network word aligned), new_word
exact integer0..65535. supplied_checksum exact integer0..65535, including0000/FFFF;
no implicit disabled-checksum wire meaning. Unknown fields/operations/missing/null/
float/bool/string integers invalid, never defaulted. No lists of arbitrary patches,
overlap/order/repeated updates, chunks/streaming or odd-offset updates in this profile.

Raw JSON<=65536 bytes; CLI file/stdin reads cap+1. Explicit UTF-8 BOM rejection;
negative-zero integer token admitted as canonical0. Strict UTF-8, lexical quote/
escape-aware nesting<=6 before object decode; numeric token<=5 before int conversion
(all admitted nonnegative inputs fit; negative operands within token bounds reject
semantically, longer signed tokens reject lexically).
Reject float/exponents/nonfinite constants, duplicate decoded keys (escaped spelling
included), grammar/trailing content, decoded controls/DEL/non-ASCII/surrogates.
Global string/key cap8192; tighter ID and hex grammar afterward. Lists/decoded strings
are logical post-raw admission bounds, not preallocation/hard RSS/time assurances.

Fixed precedence: exact bytes/raw, BOM/decode, lexical depth, JSON grammar/token/
duplicate rules, string rules, root exact fields/version, case array length, then
input-order case object/operation/exact fields, ID/duplicate, hex admission/decode,
per-case/aggregate bytes, supplied checksum or replacement length/offset/new word.
All common cases validated before ANY checksum/guard outcome. Later malformed input
rejects entire run after an earlier unsupported guard or failed verify; no prefix report.

## Arithmetic and guarded domain

Whole supplied bytes interpreted as network-order16-bit words; odd final byte is
HIGH octet with logical low zero, not an extra emitted payload byte. Empty/all-zero
stream folded sum0000, checksumFFFF. Fold carries until <=FFFF; complement exactly16bits.
No implicit packet fields/auto-zeroing/normalization of0000 toFFFF. Whole stream only:
independent padding of odd chunks changes alignment and is not this operation.

verify adds the supplied numeric16-bit checksum as a WORD to the padded data sum and
folds, reporting whether residual isFFFF AND separately equality with recomputed
checksum. It does not append two bytes at an odd boundary or locate a wire field.
Residual all ones is arithmetic compatibility only, never packet validity or integrity.
For dataFFFF, both supplied0000/FFFF yield residualFFFF but exact checksum equality
differs; report both instead of conflating zero encodings or accepting a security claim.

replace_word changes exactly TWO supplied bytes at even offset; old word read from
those bytes, initial checksum recomputed internally rather than trusted caller input.
Guard: at least one OTHER unchanged16-bit word is nonzero. It ensures both old and
updated streams contain a nonzero word, avoiding the positive-zero degeneracy beyond
RFC1624's IP-header assumption. This is a conservative LAB subset, not a standard
requirement for all checksum applications. No anchor -> status unsupported/reason
`unchanged_nonzero_word_required`, result null, guard=false. Common bounds still apply.

Supported update computes Eq3 `~fold((~HC & FFFF)+(~old_word & FFFF)+new_word) & FFFF`,
recomputes checksum over changed byte stream and reports exact equivalence. Also show
historic RFC1141 diagnostic `fold(HC+old_word+(~new_word & FFFF))`, clearly labeled
legacy, with separate matches-recompute boolean. Never use legacy value as the
recommended result. Updated bytes are transient bounded copies; no source/input files
modified or full byte buffers echoed. Supported profile equivalence is tested, not
evidence that any real packet/checksum field/pseudo-header/protocol is correct.

## Report and CLI

Root exact: version1, profile="ones-complement16-guarded-update-v1",
word_order="big_endian", status="modeled" or "contains_unsupported", rows in input
order, limitations fixed [`supplied_synthetic_bytes_only`,`no_protocol_field_validation`,
`no_actual_integrity_or_authenticity_claim`,`logical_caps_not_containment`].
No pass/fail/safe/valid-packet root verdict. All supported, including residualfalse,
is modeled; any unsupported guard gives contains_unsupported. Empty root modeled.

Row exact fields: id,operation,status (modeled/unsupported),reason(null or fixed),
byte_length,word_count(ceil(length/2)),padding_octets(0/1),update_guard(null for
non-update,true/false for replace),assumptions,result. assumptions exact supplied_checksum,
offset,new_word, each supplied scalar where relevant/null elsewhere; do not echo data_hex.
checksum result: folded_sum,checksum,checksum_hex(exact lowercase4digits).
verify result: data_sum,recomputed_checksum,supplied_checksum,combined_sum,
arithmetic_residual_all_ones,checksum_equality.
replace result: offset,old_word,new_word,old_checksum,incremental_checksum,
recomputed_checksum,rfc1624_matches_recompute,legacy_rfc1141_checksum,
legacy_matches_recompute. Unsupported replace result null, no invented incremental value.

Compact ASCII JSON plus newline <=262144 bytes, enforce before API returns or CLI
writes. No silently dropped rows/data. Stage1 conservative fixed shape bound (no
full hex output); stage3 largest admitted count/bytes/labels measurement, clearly
one stress not exact maximum. One-byte cap test labeled seam-injected.
API raises LabError on malformed/admission/output-cap failure, explicit unsupported
results otherwise. CLI exact one argument: non-leading-hyphen caller-selected synthetic
JSON path, `-` stdin or `-h`/`--help`. Other arguments fixed usage diagnostic/exit2.
Help delivered exit0; modeled report0, contains_unsupported3; input/cap/I/O/output
short/flush/locally-closed/diagnostic failure2. Failed residual is data, not exit2/3.
Fixed help/usage/errors never echo caller paths/arguments/bytes. Check stdout/stderr
write counts and flushes, detach failed streams on OSError/ValueError so shutdown
cannot override with120. Partial sink delivery remains possible; no atomicity claim.

## Independent expectations to freeze BEFORE application code

Published RFC1071 sum vector and RFC1624 Eq3/Eq2 boundary; all others hand calculations:

| Case | Exact supplied data/operation | Expected |
|---|---|---|
| empty/all zero |checksum "" and0000|sum0000/checksumFFFF|
| odd high byte |checksum01|sum0100/checksumFEFF/pad1|
| odd3 bytes |checksum010203|sum0402/checksumFBFD/pad1|
| negative zero sum |checksumFFFF|sumFFFF/checksum0000|
| carry |checksumFFFF0001|sum0001/checksumFFFE|
| repeated carry |checksumFFFFFFFF0001|sum0001/checksumFFFE|
| published vector |checksum0001F203F4F5F6F7|sumDDF2/checksum220D|
| swapped-word control |checksum010003F2F5F4F7F6|sumF2DD/checksum0D22|
| residual/equality distinct |verifyFFFF with0000 thenFFFF|residualFFFF/true both; equalitytrue thenfalse|
| changed simple data |verify0000 withFEFF|residualFEFF/false, equalityfalse|
| published update boundary |replaceCD7A5555 offset2→0x3285|oldDD2F; Eq3/recomputed0000; legacyFFFF; legacy_matchfalse|
| reverse zero boundary |replaceCD7A3285 offset2→0x5555|old0000; Eq3/recomputedDD2F; legacyDD2F|
| unchanged replacement |replace00010002 offset2→2|old/newFFFC; Eq3/legacy matchtrue|
| guarded replacement tozero |replace00010002 offset2→0|newFFFE, unchanged nonzero anchor true|
| unsupported guard |replace00005555 offset2→0|unsupported/resultnull; no unchanged nonzero word|
| byte-order collision |checksum00010002 and00020001|bothFFFC; no authenticity/integrity conclusion|

Freeze FULL exact schema/results/status/priority for these vectors plus empty,
modeled/failed-verify/unsupported/invalid-later envelopes and hash receipt before code.
If a fixture error is found, preserve original freeze/correction provenance; do not
silently regenerate expected answers from implementation. No actual source packet
captures or upstream issue payloads as fixtures.

Independent test strategies: recomputation bit-serial/column-wise byte-weight oracle
and tiny vectors manually enumerated, avoiding production unpack/fold code. All256
one-byte inputs with expected `(255-byte)<<8 |255`, all65536 two-byte values with
literal16-bit complement; bounded loop, not millions of JSON CLI processes. For
updates,256 or more predetermined even four-byte examples with a fixed nonzero
unchanged anchor and representative words0/1/7fff/8000/ffff; independently recompute
new bytes and compare Eq3. Include old/new checksum0000, unchanged update, offset0/last,
zero-anchor unsupported, odd/empty/short/misaligned invalid, both residual-zero forms.
Do not assert an undemonstrated universal CRC/checksum error-detection rate.

## Threat model and implementation structure

Assets: accurate bounded arithmetic/limits, host/project evidence/privacy, no implied
integrity/authentication. Attacker-controlled JSON can cause huge decode/shift/data
allocation, duplicate keys, bool coercion, hidden whitespace in fromhex, odd alignment,
terminal controls or output growth. Raw/depth/token/string/hex/count/total caps before
decode/evaluation, exact types/fields and scalar-only output mitigate them. No eval,
pickle, foreign runtime/plugin imports, network/process in application or filesystem
walk/write. Reject exotic native objects by identity without invoking hooks.

Semantic attacks: wrong padding/carry/byte order or legacyzero formula can produce
plausible mismatches; published/independent vectors and three mandatory mutations
target them. All-zero update domains and residual/equality confusion have explicit
unsupported/dual-flag rules. A checksum collision is ordinary arithmetic evidence;
do not turn checksum equality into authenticity or real corruption-detection proof.
External docs/worker outputs source material only, never operational authorization.

checksum_lab.py: bounded JSON load → common admission → whole-stream math/guarded
replacement → scalar bounded report → fixed checked CLI. Reuse original owned MIT
core/output patterns after review; no upstream implementation copying, GPL code imports
or shared helper changes. Raw upstream research text keeps own notices/license and
is evidence only, no publication authorized. Original tool MIT/attribution/AI disclosure.
No hard RSS/time or protection against blocking selected device/pipe claimed; callers
use ordinary synthetic JSON fixtures. Capability mocks exercise paths, not containment.

## Stages, acceptance, dependencies and verification

1. **Contract/oracle freeze after approval.** SCHEMA exact fields/status/error priority,
   full expected vectors/envelopes and pre-code byte/hash receipt; independently review
   zero/update-guard/residual semantics and conservative report shape. Small slices
   <=5files each; no application until freeze passes. Task1; depends on plan approval.
2. **Thin application slices.** Owned full-buffer core + exact admission/API, then
   verify/guarded replace/legacy diagnostic/CLI. Frozen vector/bounds/late-invalid/
   no-hook tests before next slice. Tasks2–3 depend on1 then2. No extra routine approval.
3. **Verification and ECC.** Independent one-/two-byte oracle loops and anchored updates,
   published/hand fixtures, malformed/boundary/BOM/-0/unknown version, complete common
   admission, input order/no mutation, output cap/max-shape. Actual normal/-O children
   for help/usage/report/input/unsupported and closed/both sinks/local stream closure;
   short/flush child seams labeled. Mock socket/DNS/process capabilities on exercised
   paths; source review supports no broader imports. Four mandatory mutants: odd
   trailing byte treated as low octet; end-around carry dropped; Eq3 replaced with
   legacy Eq2; residual conflated with exact equality. Each must fail its intended ASSERTION, not unrelated parse/startup error.
   Exact source restored in finally/own-cache clearing; normal/-O/compile/installed
   Bandit pass after fixes. ECC actual source/callers/tests/trust-boundary self-review,
   document concrete findings/corrections and recheck affected paths. Tasks4–5.
4. **Portfolio/knowledge completion.** README problem/demo/architecture/run/status/
   limitations/security/verified results/learning; SECURITY/MIT/source attribution/AI
   disclosure, STATE/DECISIONS/LEARNING, verification report/current hash receipt and
   minimal reusable verifier with inputs/outputs/assumptions/usage. Check authored
   changes for private material without exposing it; dedicated scan/history/hosted/
   other-runtime/independent checks explicitly unrun. Guarded approved Obsidian note
   or pending note if blocked. Tasks6–7, <=5 files each. No new repo/publishing implied.

Standing done: approved frozen contract matched, independent vectors/mutants/actual
CLI errors demonstrated, exact source restoration, no unresolved confirmed in-scope
defects after ECC/affected tests, docs/current receipt/knowledge consistent, scope and
private evidence preserved. Never bypass auto-review rejection or claim unavailable
tests; no old project reruns without new cause. No independence for self-review.

## Worker and approval checkpoint

Local loopback qwen3.5:2b extracted four supplied labels,6115ms/19tokens/stop, reviewed
and accepted. Raw evidence separate, no generative arithmetic/code accepted. Codex
source/math/security judgments retained; no general competence/savings claim. Free
OpenRouter considered unnecessary; no remote inference/config changes/additional
spending. Laya schema unrelated. Research source fallback used app-approved canonical
public Git blobs, not unavailable connector/raw reads; no upstream code run.

Highest risks: zero-domain scope leakage, endian/padding/folding and residual equality
conflation; controls above. No essential unanswered implementation preference: coordinator
reviews this exact guarded subset and stages1–4 before code. Material semantics/scope/
cost/privacy changes require surfaced review; routine choices proceed within approval.

## Completion checkpoint

Approved stages1–4 completed October5:25normal/Otests, four intended-assertion mutants,
compile/installedBandit,12current/7frozen hash reconciliation and ECC self-review.
See verification/REPORT.md for exact evidence/limits; README/SECURITY/MIT/learning complete.
Obsidian completion guarded against the research-note SHA before replacement.
