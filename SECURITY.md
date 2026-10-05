# Security model

This is supplied-synthetic-byte arithmetic, not a network scanner or real integrity
checker. No sockets/DNS, packet parsing, captures, process launch or protocol field
validation in application code. No authenticity, confidentiality or collision
resistance claim. A checksum collision is an expected limitation.

Untrusted input boundaries: exact built-in bytes checked before hooks; raw UTF8/BOM,
lexical depth, duplicate JSON keys/numeric grammar, printable string bounds, closed
root/case schemas, exact integer ranges, strict hex/count bounds, whole-envelope
admission before math. Fixed diagnostic categories omit supplied data/paths.
Replacement is limited to the declared conservative unchanged-nonzero-word guard.
Unknown versions/fields and malformed late cases reject rather than partially report.

Output is capped before API return/write. Exact built-in integer write counts and
flush are checked on help/report/diagnostics; closed/failing sinks are detached to
retain controlled exit2. Partial delivery remains possible. CLI reads only the
explicit file or stdin with cap+1. Logical admission caps do not provide hard RSS/
time/host containment; use ordinary bounded synthetic fixture files, not device paths
or untrusted code. The filesystem sandbox is not malware isolation.

Only authored synthetic task files were checked for private-material leakage;
dedicated secret/history scanning, independent audit, hosted CodeQL and other runtime
checks were not performed. Raw research sources are evidence only and were not
executed. No repository/publication/merge/deployment is authorized by local completion.
Report an issue privately to the project owner with a minimal synthetic fixture;
omit credentials, employer/client data and real packet/capture material.
