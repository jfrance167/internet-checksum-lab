# Internet checksum research — October5,2026

RESEARCH/PLAN ONLY, coordinator SUCCESSORS.md04:39 under Jake's verified overnight
successor mandate. Separate directory/same chat/sole writer. No application code,
candidate execution, third-party tests, live packets/captures/devices or installation.

## Reuse and primary sources

Read applicable instructions/shared STARTUP/routing, vault Home/Integration and
scanner note. Targeted checksum/RFC1071/RFC1624/CRC note searches found scanner
verification and unrelated package/hash notes, no dedicated incremental-update lab.
Bounded search, not exhaustive assurance. Actual owned files inspected:
- zig-lab-scanner/src/packet.zig sum/fold/checksum: network-order16-bit words,
  odd byte shifted into high octet, repeated end-around fold then complement.
  Existing RFC1071/odd-length fixtures inspected, not rerun; Linux runtime gap retained.
- zig-lab-scanner/scripts/check_vectors.py: original struct-unpack big-endian sum,
  tail zero padding, repeated fold; RFC vector checksum220d plus packet-specific oracle.
- network-forensics-pcap-lab/generate_synthetic_pcap.py:checksum equivalent full-buffer
  routine. Read function only, not generator execution or capture processing.
Reuse smallest owned full-buffer arithmetic after review. New teaching admission,
zero/update/verification distinctions are separate; no sibling runtime imports or
packet-builder expansion. Existing serial fixed checked CLI/error pattern reusable.

[RFC1071](https://www.rfc-editor.org/rfc/rfc1071.html) sections1–3 reviewed: pair bytes
into16-bit words, end-around carry, complement; odd final byte logically padded.
Its numerical vector yields sumddf2, checksum220d. Byte-swapped words need consistent
final representation, and odd chunk boundaries cannot be independently padded then
naively added. Choose whole supplied byte stream, explicit big-endian interpretation.

[RFC1141](https://www.rfc-editor.org/rfc/rfc1141.html) and
[RFC1624](https://www.rfc-editor.org/rfc/rfc1624.html) sections2–5 read. Updated equation
complements the folded sum of complemented old checksum, complemented old word and
new word. Dual-zero boundary matters: published CD7A/5555→3285 example has oldDD2F,
new0000; historic formula givesFFFF. RFC1624's header argument assumes a nonzero
field exists. Lab inference: require an unchanged nonzero word for the supported
single-word replacement subset, rather than claim general arbitrary-buffer equivalence.
All-zero streams still have ordinary full checksums; outside guarded update scope
is explicitly unsupported. This conservative guard is a lab policy, not a new RFC rule.

[RFC3309](https://www.rfc-editor.org/rfc/rfc3309.html) checksum procedure reviewed as
CRC-32C alternative: polynomial/bit mapping, initialization/final complement and
transport serialization must be exact. It is a different profile; no universal
error-detection ranking or cryptographic authenticity follows. CRC implementation
deferred; no SCTP/protocol-engine conformance inferred. No standards-status/errata
certification or assurance from historical documents. PLAN fixes the chosen subset.

## Actual connected/public source assessment

Connected GitHub search `internet checksum incremental` returned no repositories.
Existing dpkt review and established Scapy utility provided relevant candidates.
Connected dpkt checksum excerpt and Scapy latest commit returned successfully. Later
connector transport failed; raw public browsing gave cache misses, shell raw-host
requests failed too. Those failures were not counted as inspection. App-approved
canonical api.github.com tree/blob reads then succeeded. Pinned public blobs independently
matched Git SHA1 identities (Git object identity, not a security endorsement), retained
with exact byte/SHA256 receipt. No upstream import/build/test or risky execution.

### dpkt

Pin [4f8958eb4b375b38d0ab6ffadf2da9b24395394d](https://github.com/kbandla/dpkt/tree/4f8958eb4b375b38d0ab6ffadf2da9b24395394d),
latest returned May5,2024 maintenance from prior verified source research.
Connected actual [dpkt/dpkt.py](https://github.com/kbandla/dpkt/blob/4f8958eb4b375b38d0ab6ffadf2da9b24395394d/dpkt/dpkt.py)
lines370–485, Git blob3d399109b722985064e49a01c47e29b74a3d61e1:
in_cksum_add unpacks little-endian words and adds odd last byte; in_cksum_done folds
and converts endian representation; in-file test_utils checks an odd15-byte vector
and endian-specific sum/checksum. Useful comparison, not a canonical per-chunk odd
alignment or RFC1624 incremental-update API; broad packet framework unnecessary.

Actual LICENSE (99d14371e1e1dc92c281081d590c0ac81e5ef04f), setup.py
(ece4577a27b2332f12e1f94f143e5d876fc62406), workflow
(d3f9b1a8f9c8bd19471884f11760ad8fa382e370) freshly read through canonical blobs.
BSD3 source/binary notices and no endorsement obligations, copyrightDugSong2004.
No declared runtime requirements, setuptools/distutils packaging that imports package
during setup; not executed. Actual CI pytest/coverage/lint matrix2.7/3.5–3.9/pypy3,
Ubuntu20.04, mutable action tags including develop. Prior relevant dpkt issue321 UDP
automatic length was inspected as reporter evidence, not reproduced or checksum proof.
No current compatibility/security/hosted/advisory assurance. No code adoption planned.

### Scapy

Pin [e2e35c07bce2f40e7513e1b29a6d300d5329dbc3](https://github.com/secdev/scapy/tree/e2e35c07bce2f40e7513e1b29a6d300d5329dbc3),
latest connected commit October2,2026, corrupted-gzip reader handling. Recursive tree
truncated=false. Actual scapy/utils.py checksum/endian-transform lines587–601:
odd-tail pad, native unsigned-H array sum, two carry reductions, complement and host
endian transform. Git blob4cfef59d438822b34c939059e386c79752a8e081, full bytes verified.
Not a bounded declaration/incremental teaching interface; importing broad utility
also brings packet/framework functionality that the lab does not need.

Read actual test/regression.uts utility tests and test/scapy/layers/inet.uts checksum
assertions lines471–549: fixed IP/TCP/UDP checksum examples depend on default fields,
including options/payload lengths. These are source evidence, not run passes or
independent lab vectors; no real/source packet payload copied into lab fixtures.
Inet test blob1032777c4ea87ac5cc437461bc51fcbf5487b5da. Utility regression file alone
did not supply direct Internet-checksum boundary controls; stronger inet test read
completed that assessment. None executed.

Actual GPL2-only SPDX source notice, project manifest and full LICENSE read. Source
copyrightPhilippeBiondi; copying/distributing derivatives would require preserving
notices/license and applicable GPL terms. No Scapy implementation code adopted.
Retained raw research text/license are upstream evidence, not original MIT source;
no publication authorized. pyproject.toml has setuptools>=62 build, Python>=3.7<4,
no declared mandatory runtime dependencies and optional ipython/pyx/cryptography/
matplotlib/docs extras. setup.py includes a compatibility patch for older setuptools
license metadata. Build/setup never executed. No dependency-count security inference.

Actual .github/workflows/unittests.yml (591293268294982e61bd761bed9f7b293f2d9ec7):
read permissions, commit/SPDX/health/docs/tests, Linux root/nonroot/macOS/Windows
matrix and Python3.7–3.14 paths, CodeQL security-events write. Mutable @v6/@v4/@v5
actions do not meet Jake's immutable-pin baseline; don't copy/run workflows. No hosted
pass established. Public issue4906 reports IPv6/VXLAN UDP payload-length/recomputed
checksum mismatch; body read, not parsed/run/reproduced. Issue4964 summary concerns
PPPoE send; not read as an arithmetic defect. Maintained broad scope does not certify
this profile. No advisory/Scorecard/package-artifact/security audit performed.

## Recommendation and worker

Reuse owned full-buffer checksum core and build original stdlib bounded teaching
wrapper/guarded update arithmetic after approval. Fork/adopt Scapy or dpkt adds broad
packet/build/license scope without the contract; neither inspected candidate unchanged
is the needed lab. Not an exhaustive search or blanket security verdict. CRC-32C is
an alternative future lab, not silently substituted/implemented alongside this one.
Source receipt binds12 upstream snapshots (including tree/excerpt); no application tests.

Installed loopback qwen3.5:2b once extracted four supplied labels correctly,6115ms,
19tokens/stop. Raw brief/draft/metadata separate; no generated code or mathematical
oracle accepted. Used app-approved loopback because prior sandbox access was denied
before inference. Explicitly considered free OpenRouter; unnecessary after suitable
local extraction. No remote inference/configuration/freshness probe/spending. Current
shared startup read only; readiness not inference/price/eligibility proof. Laya schema
unrelated. Codex retains source/security/math judgment; all actual testing awaits approval.
