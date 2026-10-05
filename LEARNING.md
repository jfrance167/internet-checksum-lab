# Learning record

Internet checksum arithmetic has two zero representations. FFFF data recomputes0000,
yet suppliedFFFF also leaves an all-ones residual. Residual success does not imply
exact checksum equality, actual intact transmission or authentic input.

An odd final octet is the high byte of a logically padded network word. Padding each
odd chunk separately would change word alignment; this lab accepts whole buffers only.
End-around carry can recur. Independent high/low-column modulo65535 controls preserve
the zero distinction and avoid merely copying the implementation's fold loop.

RFC1624's published CD7A/5555→3285 example exposes Eq2's FFFF versus Eq3's0000.
The lab's unchanged-nonzero-word guard narrows its demonstrated domain. Unsupported
means outside the selected profile, not an assertion of general mathematical failure.

Verification found a real Windows text translation mismatch: the fixed LF diagnostic
was emitted as CRLF. Explicit native stream newline configuration fixed it; byte-exact
CLI envelope tests now agree. Locally closed streams raise ValueError while broken
pipes commonly raise OSError; both are exercised in real normal/-O children.

Tests deliberately inject four incorrect algorithms and require their intended
assertion names, not any crash. No mutation startup errors are accepted; exact source
bytes are restored in finally before final checks. Synthetic count/short/flush seams
are distinguished from actual OS pipe and local Python stream closure.

Compile/SAST and passing bounded controls are useful evidence, not protocol/runtime/
host containment or independent audit assurance. One largest-count stress shape is
not the exact serialized maximum. Shared tooling/raw research/prior lab gaps remain
separate from this lab's current result.
