# Frozen Internet checksum teaching profile v1

Approved PLAN/coordinator05:12 addendum, frozen before checksum_lab.py. Exact built-in
bytes by identity before len/hooks, JSON only. No native object API, protocol fields,
stream chunks or packet/capture/network/device operations. Whole supplied synthetic bytes.

Admission priority: exact bytes/raw<=65536; UTF8 BOM reject/decode; quote/escape-aware
lexical depth<=6; JSON grammar/duplicate decoded keys/token<=5/no floats/exponents/
constants; strings/keys<=8192 printableASCII; root exactversion/cases and integer1;
cases array<=64; input-order case object/operation/exact fields/ID/unique; even strict
hex0..8192; decode/per-case<=4096,total<=16384; suppliedchecksum or replacement length/
offset/newword. Entire common admission before math/guard. Unknownversion invalid;
-0 accepted/canonical integer0; longer signed tokens lexical-invalid. Bytes subclasses
and exotic objects rejected without equality/len/str/iteration/coercion hooks.

Root exactly version,cases. Cases exact shapes:
- checksum: id,operation="checksum",data_hex.
- verify: id,operation="verify",data_hex,supplied_checksum.
- replace_word: id,operation="replace_word",data_hex,offset,new_word.
ID `[A-Za-z0-9][A-Za-z0-9-]{0,31}` case-sensitive unique/trailinghyphenallowed.
Hex ASCII0-9a-fA-F only/even digits, whitespace/prefix forbidden. Empty/odd byte streams
accepted for checksum/verify. Replace requires even length4..4096, exact int even
offset0..length-2, exact int newword0..65535. Suppliedchecksum exactint0..65535.
Bool notint, null/unknown/missing/float/stringinteger invalid, no default/normalization.

Math: big-endian16-bit words; odd lastbyte highoctet, logical lowzero padding.
Fold repeated end-around carries to16bits; checksum=sum XOR FFFF. Empty/zeros sum0
checksumFFFF; FFFF sumFFFF checksum0. No protocol-zero remapping or implicit headers.
Verify fold(data_sum+suppliednumericword), residual_all_ones iffFFFF; separately
exact supplied==recomputed. Numericword added AFTER odd-tail logical padding, no wire
field/byteappend assertion. Checksum compatibility is not real integrity/authenticity.
Replace oldword read from exactoffset, initial checksum recomputed. Require unchanged
nonzero OTHER word; guardfalse unsupported/null result. Conservative labpolicy, not
RFCrule/general algorithm invalidity. Guardtrue Eq3 complementfold(~HC+~old+new),
each complement masked16bits; independently full updated-stream recomputation. Show
historic Eq2 fold(HC+old+~new) only as named legacydiagnostic, never recommended value.

Exact root report: version1,profile="ones-complement16-guarded-update-v1",
word_order="big_endian",status="modeled" or"contains_unsupported",rows inputorder,
limitations exactly["supplied_synthetic_bytes_only","no_protocol_field_validation",
"no_actual_integrity_or_authenticity_claim","logical_caps_not_containment"].
Rows exactly id,operation,status(modeled/unsupported),reason(null or
unchanged_nonzero_word_required),byte_length,word_count ceil(length/2),padding_octets0/1,
update_guard(null/non-update,true/false replace),assumptions,result.
assumptions exactly supplied_checksum,offset,new_word with relevant supplied scalar
and othersnull. No full datahex input/outputecho. Results exact byop:
- checksum: folded_sum,checksum,checksum_hex lowercase4digits.
- verify: data_sum,recomputed_checksum,supplied_checksum,combined_sum,
  arithmetic_residual_all_ones,checksum_equality (separate booleans).
- supported replace: offset,old_word,new_word,old_checksum,incremental_checksum,
  recomputed_checksum,rfc1624_matches_recompute,legacy_rfc1141_checksum,
  legacy_matches_recompute. Unsupported resultnull, metadata/assumptions remain known.
Failed residual remains modeled/rootmodeled/exit0. Any unsupported guard root3.
Empty report modeled. No valid/safe/authentication verdict or total detection-rate claim.

CLI one argument: synthetic non-leading-hyphen JSONfilepath,`-` stdin,`-h`/`--help`.
Fixed help/usage/diagnostics no paths/input echo. Admission error before report/stdout;
exit2. Modeled0,contains_unsupported3,help0 if delivered. Short/flush/closed/localclosed
or diagnostic failures2; actual normal/-O tested. EXACT built-in int writecounts must
equal requiredlength; float/bool/None/exoticcounts invalid. Failed stdout/stderr detached
on OSError/ValueError to avoid shutdown120. Partial failing sink may receive bytes.
FinalcompactASCIIJSON+newline<=262144 before APIreturn/write; LabError invalidinput/cap.

Conservative outputshape: <=1600bytes/row (ID32,scalar fields/masked16-bit values,
fixed strings,nohexbuffer) plus1024envelope;64*1600+1024=103424<262144. This is a loose
fixed-shape allowance, not measured exactmaximum. Measure largest admitted counts/
totalbytes/labels and label one-byte cap test as injected seam. Input/allocation caps
logical, not hard RSS/time/host containment/atomicity. No candidate execution/import.

Frozen errors used by invalid envelopes: `invalid replacement offset` (odd or out of
range), `invalid hexadecimal bytes` (character/length). Fixed error diagnostic prefix
`checksum-lab: ` plus categorical LabError and LF; usage separately fixed. Any earlier
lexical/type/root/count/common error wins before math; no prefix outcomes.
