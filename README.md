# Internet checksum lab

An offline teaching tool for Internet checksum arithmetic over supplied synthetic
bytes. It separates whole-buffer checksums, a supplied numeric checksum residual,
exact checksum equality, and a conservatively guarded aligned word replacement.
It sends no traffic and reads no captures or protocol fields.

## Run

No application dependencies or installation. Python3.11+ intended; Windows
CPython3.13.7 actually tested. From this directory:

```powershell
python checksum_lab.py --help
python checksum_lab.py examples/modeled.json
python checksum_lab.py examples/mixed.json
python checksum_lab.py examples/invalid-late.json
python -B -m unittest discover -s tests -v
python -O -B -m unittest discover -s tests -v
python verification/verify.py
```

`-` reads stdin; one explicitly selected ordinary JSON file is also accepted.
The reusable verifier needs the already installed Bandit1.9.4; it installs nothing,
runs only owned local code, temporarily edits this lab's source for four mutants,
restores exact bytes in finally and verifies frozen hashes. Do not edit source
concurrently or forcibly terminate it. Logs/current receipt are in `verification/`;
failed/running latest-run makes any older receipt historical.

## Example and learning

```json
{"version":1,"cases":[{"id":"zero","operation":"verify","data_hex":"FFFF","supplied_checksum":65535},{"id":"update","operation":"replace_word","data_hex":"CD7A5555","offset":2,"new_word":12933}]}
```

The first row has an all-ones arithmetic residual but **false exact equality**:
the recomputed checksum is0000 while the supplied checksum isFFFF. The second
reproduces RFC1624: Eq3 and full recomputation produce0000; the historic Eq2
diagnostic producesFFFF. These are mathematical distinctions, not a verdict about
actual transmission integrity or authenticity. `00010002` and `00020001` also
illustrate an ordinary checksum collision.

| Exit | Meaning |
|---|---|
|0|Delivered modeled report, including failed residuals; delivered help|
|3|Delivered report containing an unsupported replacement guard|
|2|Malformed/capped input, unavailable input/output, short/flush/closed sink or diagnostic failure|

Reports preserve case order and carry explicit assumptions. Full hex buffers and
input paths are not echoed. All common cases are admitted before any arithmetic:
an invalid later row rejects the entire envelope, even after an earlier unsupported
replacement or failed residual. Schema and errors were frozen before application code.

## Model and architecture

`checksum_lab.py`: exact-bytes UTF8/JSON admission → all-case validation → network
word arithmetic → scalar report/output cap → checked CLI writes. `analyze(data)`
accepts only exact built-in bytes, rejecting subclasses before hooks. See SCHEMA.md
for exact fields, types, caps and precedence. Inputs have version1 and up to64cases;
raw<=65536bytes, each buffer<=4096bytes, repeated buffers count toward16384total.
The final compact ASCII JSON/LF output cap is262144bytes.

Big-endian16-bit words use high-octet odd-tail padding and repeated end-around
carries. Empty/all-zero sum0000 givesFFFF; nonzero all-ones sumFFFF gives0000.
No zero remapping, pseudo-headers, automatic field zeroing, wire verification or
streaming/chunk padding. `verify` adds a supplied numeric word after logical padding.

Replacement requires an even buffer>=4bytes, one aligned offset and a16-bit new word.
At least one **other unchanged nonzero word** is required. This conservative lab
policy keeps the demonstrated update domain clear; it is not an additional RFC rule
or a claim that other domains are inherently invalid. A failed guard yields
unsupported/null arithmetic result. Supported Eq3 results are compared with full
updated-buffer recomputation; legacy Eq2 is only a named diagnostic.

## Verified evidence and limits

25 tests pass normally and with `-O`;21 full literal reports and5 envelope outcomes
match. All256one-byte and65536two-byte controls,130independent column oracles and
562anchored replacements pass. Four intended assertion mutants catch low-octet odd
padding, dropped carries, legacy Eq2 and residual/equality conflation. Real normal/-O
closed OS pipes and locally closed Python streams preserve2; synthetic short/count/
flush child seams are explicitly labeled in tests. Compile and installed Bandit
pass. See verification/REPORT.md and receipt.json for exact outcomes and current hashes.

The64row/16384decoded-byte/32-character-ID stress report is one measurement, not an
exact maximum proof. Logical caps are not hard RSS/time or host containment; selected
blocking devices/pipes are outside fixture use. A failing output sink can receive a
partial report. Other runtimes/platforms, hosted CI/CodeQL, independent audit,
dedicated secret/history scanning and real protocol validation are unrun. Original
scanner live Linux SYN remains unrun. Prior labs and parent work were preserved.

## Sources, license and assistance

Original wrapper/update model/tests; owned MIT full-buffer word/padding pattern reused
from `zig-lab-scanner/scripts/check_vectors.py` (Jake Franciosa2026). Verifier adapted
from the owned MIT serial lab. No sibling runtime imports or third-party implementation
adoption. Research-only snapshots retain their upstream notices; they are not covered
by a blanket new MIT grant. Original lab code/docs use LICENSE.

Primary arithmetic sources: [RFC1071](https://www.rfc-editor.org/rfc/rfc1071),
[RFC1141](https://www.rfc-editor.org/rfc/rfc1141),
[RFC1624](https://www.rfc-editor.org/rfc/rfc1624). RESEARCH.md records pinned dpkt/Scapy
source/license/metadata/CI/test inspection and retrieval limits; neither package or
upstream tests were installed or executed. CRC32C was researched as a deferred separate
profile, not implemented. Research is scoped, not exhaustive or safety certification.

AI assistance: Codex implemented/reviewed/tested this lab; local qwen3.5:2b extracted
four supplied labels only (raw evidence retained). Codex retained arithmetic/security
judgments. No remote drafting or additional spending; ECC review is a self-review.
Optional exercise: explain why the all-ones residual and exact equality disagree
for the first example, then identify which mandatory test would catch conflation.

## Publication status

See [publication review](PUBLICATION.md) for the October 5 source snapshot, fresh local checks, evidence boundaries and current hosted-check distinction.
