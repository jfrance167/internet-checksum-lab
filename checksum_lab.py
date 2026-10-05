"""Bounded, offline Internet checksum teaching model. See SCHEMA.md."""
import json
import re
import struct
import sys

MAX_OUTPUT = 262144
LIMITATIONS = ["supplied_synthetic_bytes_only", "no_protocol_field_validation",
               "no_actual_integrity_or_authenticity_claim", "logical_caps_not_containment"]
HELP = "checksum-lab: supplied synthetic bytes only\nusage: checksum_lab.py JSONFILE | - | --help\n"
USAGE = "checksum-lab: usage: checksum_lab.py JSONFILE | - | --help\n"


class LabError(ValueError):
    """A fixed categorical admission error, never containing supplied data."""


def _fold(total):
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total


def _sum(data):
    # Owned scanner's network-order word/padding convention; see README attribution.
    padded = data + b"\0" if len(data) % 2 else data
    words = struct.unpack("!" + str(len(padded) // 2) + "H", padded)
    return _fold(sum(words))


def _checksum(data):
    return _sum(data) ^ 65535


def _integer(token):
    if len(token) > 5:
        raise LabError("invalid integer token")
    return int(token)


def _no_number(_):
    raise LabError("invalid numeric token")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LabError("duplicate object key")
        result[key] = value
    return result


def _strings(value):
    if type(value) is str:
        if len(value) > 8192 or any(ord(c) < 32 or ord(c) > 126 for c in value):
            raise LabError("invalid string")
    elif type(value) is dict:
        for key, child in value.items():
            _strings(key)
            _strings(child)
    elif type(value) is list:
        for child in value:
            _strings(child)


def _load(data):
    # Identity first: hostile bytes subclasses must not reach hooks.
    if type(data) is not bytes:
        raise LabError("input must be exact bytes")
    if len(data) > 65536:
        raise LabError("input byte cap exceeded")
    if data.startswith(b"\xef\xbb\xbf"):
        raise LabError("UTF8 BOM forbidden")
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        raise LabError("invalid UTF8") from None
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 6:
                raise LabError("JSON depth cap exceeded")
        elif char in "]}":
            depth -= 1
    try:
        value = json.loads(text, object_pairs_hook=_object, parse_int=_integer,
                           parse_float=_no_number, parse_constant=_no_number)
    except (json.JSONDecodeError, RecursionError):
        raise LabError("invalid JSON") from None
    _strings(value)
    return value


def _fields(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        raise LabError("invalid object fields")


def _word(value):
    return type(value) is int and 0 <= value <= 65535


def _admit(root):
    _fields(root, ("version", "cases"))
    if type(root["version"]) is not int or root["version"] != 1:
        raise LabError("invalid version")
    cases = root["cases"]
    if type(cases) is not list or len(cases) > 64:
        raise LabError("invalid case count")
    admitted, seen, total = [], set(), 0
    shapes = {"checksum": ("id", "operation", "data_hex"),
              "verify": ("id", "operation", "data_hex", "supplied_checksum"),
              "replace_word": ("id", "operation", "data_hex", "offset", "new_word")}
    for case in cases:
        if type(case) is not dict or type(case.get("operation")) is not str:
            raise LabError("invalid case operation")
        operation = case["operation"]
        if operation not in shapes:
            raise LabError("invalid case operation")
        _fields(case, shapes[operation])
        identifier = case["id"]
        if type(identifier) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,31}", identifier) is None or identifier in seen:
            raise LabError("invalid case ID")
        seen.add(identifier)
        encoded = case["data_hex"]
        if type(encoded) is not str or len(encoded) % 2 or re.fullmatch(r"[0-9a-fA-F]*", encoded) is None:
            raise LabError("invalid hexadecimal bytes")
        data = bytes.fromhex(encoded)
        total += len(data)
        if len(data) > 4096 or total > 16384:
            raise LabError("decoded byte cap exceeded")
        if operation == "verify" and not _word(case["supplied_checksum"]):
            raise LabError("invalid supplied checksum")
        if operation == "replace_word":
            if len(data) < 4 or len(data) % 2:
                raise LabError("invalid replacement length")
            offset = case["offset"]
            if type(offset) is not int or offset % 2 or not 0 <= offset <= len(data) - 2:
                raise LabError("invalid replacement offset")
            if not _word(case["new_word"]):
                raise LabError("invalid replacement word")
        admitted.append((case, data))
    return admitted


def _evaluate(case, data):
    operation = case["operation"]
    assumptions = {key: case.get(key) for key in ("supplied_checksum", "offset", "new_word")}
    row = dict(id=case["id"], operation=operation, status="modeled", reason=None,
               byte_length=len(data), word_count=(len(data) + 1) // 2,
               padding_octets=len(data) % 2, update_guard=None,
               assumptions=assumptions, result=None)
    if operation == "replace_word":
        offset, new = case["offset"], case["new_word"]
        guard = any(data[i:i + 2] != b"\0\0" for i in range(0, len(data), 2) if i != offset)
        row["update_guard"] = guard
        if not guard:
            row.update(status="unsupported", reason="unchanged_nonzero_word_required")
            return row
        old = int.from_bytes(data[offset:offset + 2], "big")
        hc = _checksum(data)
        incremental = _fold((hc ^ 65535) + (old ^ 65535) + new) ^ 65535
        updated = data[:offset] + new.to_bytes(2, "big") + data[offset + 2:]
        recomputed = _checksum(updated)
        legacy = _fold(hc + old + (new ^ 65535))
        row["result"] = dict(offset=offset, old_word=old, new_word=new,
                             old_checksum=hc, incremental_checksum=incremental,
                             recomputed_checksum=recomputed,
                             rfc1624_matches_recompute=incremental == recomputed,
                             legacy_rfc1141_checksum=legacy,
                             legacy_matches_recompute=legacy == recomputed)
    elif operation == "checksum":
        folded = _sum(data)
        checksum = folded ^ 65535
        row["result"] = dict(folded_sum=folded, checksum=checksum,
                             checksum_hex=f"{checksum:04x}")
    else:
        folded, supplied = _sum(data), case["supplied_checksum"]
        recomputed = folded ^ 65535
        combined = _fold(folded + supplied)
        row["result"] = dict(data_sum=folded, recomputed_checksum=recomputed,
                             supplied_checksum=supplied, combined_sum=combined,
                             arithmetic_residual_all_ones=combined == 65535,
                             checksum_equality=supplied == recomputed)
    return row


def _serialize(report):
    text = json.dumps(report, ensure_ascii=True, separators=(",", ":")) + "\n"
    if len(text.encode("ascii")) > MAX_OUTPUT:
        raise LabError("output byte cap exceeded")
    return text


def analyze(data):
    """Admit the entire exact-bytes JSON envelope, then return its bounded report."""
    admitted = _admit(_load(data))
    rows = [_evaluate(case, data) for case, data in admitted]
    report = dict(version=1, profile="ones-complement16-guarded-update-v1",
                  word_order="big_endian",
                  status="contains_unsupported" if any(row["status"] == "unsupported" for row in rows) else "modeled",
                  rows=rows, limitations=LIMITATIONS.copy())
    _serialize(report)
    return report


def _write(stream, text):
    count = stream.write(text)
    if type(count) is not int or count != len(text):
        raise OSError("failed write")
    stream.flush()


def _diagnostic(text):
    try:
        _write(sys.stderr, text)
    except (OSError, ValueError):
        sys.stderr = None
    return 2


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        return _diagnostic(USAGE)
    argument = argv[0]
    if argument in ("-h", "--help"):
        output, status = HELP, 0
    elif argument != "-" and argument.startswith("-"):
        return _diagnostic(USAGE)
    else:
        try:
            if argument == "-":
                data = sys.stdin.buffer.read(65537)
            else:
                with open(argument, "rb") as source:
                    data = source.read(65537)
            report = analyze(data)
            output = _serialize(report)
            status = 3 if report["status"] == "contains_unsupported" else 0
        except LabError as error:
            return _diagnostic("checksum-lab: " + str(error) + "\n")
        except (OSError, ValueError):
            return _diagnostic("checksum-lab: input unavailable\n")
    try:
        _write(sys.stdout, output)
    except (OSError, ValueError):
        sys.stdout = None
        return _diagnostic("checksum-lab: output unavailable\n")
    return status


if __name__ == "__main__":
    # Keep the frozen ASCII/LF CLI bytes identical on Windows and Unix.
    sys.stdout.reconfigure(newline="\n")
    sys.stderr.reconfigure(newline="\n")
    sys.exit(main())
