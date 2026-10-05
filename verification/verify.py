"""Repeat owned offline checks with installed Python/Bandit; no installation.

Run python verification/verify.py from any directory. Reads frozen schema/oracles/
examples and own source/tests; writes logs, stress, current receipt/latest-run.
Temporarily edits ONLY own source and restores exact bytes in finally. Do not edit
concurrently or forcibly terminate. Adapted from owned serial lab MIT verifier.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess  # nosec B404: fixed local checks of owned code only.
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "verification"
SOURCE = ROOT / "checksum_lab.py"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(name, args):
    child = subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True,
                           timeout=60)  # nosec B603: fixed installed Python/owned files, no shell.
    (OUT / (name + ".log")).write_bytes(child.stdout + child.stderr)
    return child


def clear_cache():
    for optimization in (None, "1", "2"):
        Path(importlib.util.cache_from_source(str(SOURCE), optimization=optimization)).unlink(missing_ok=True)


def verify():
    frozen = json.loads((OUT / "frozen-contract.json").read_text(encoding="utf-8-sig"))
    for name, expected in frozen["sha256"].items():
        if sha(ROOT / name) != expected:
            raise RuntimeError("frozen contract mismatch")
    original = SOURCE.read_bytes()
    results = {}
    tests = ["-B", "-m", "unittest", "discover", "-s", "tests", "-v"]
    mutations = (
        ("odd-low-padding", b'padded = data + b"\\0" if len(data) % 2 else data',
         b'padded = data[:-1] + b"\\0" + data[-1:] if len(data) % 2 else data', "test_mandatory_padding"),
        ("carry-dropped", b"return total\n", b"return total & 65535\n", "test_mandatory_carry"),
        ("legacy-eq2", b"incremental = _fold((hc ^ 65535) + (old ^ 65535) + new) ^ 65535",
         b"incremental = _fold(hc + old + (new ^ 65535))", "test_mandatory_eq3"),
        ("residual-equality-conflated", b"checksum_equality=supplied == recomputed",
         b"checksum_equality=combined == 65535", "test_mandatory_residual_equality"))
    try:
        for name, old, new, intended in mutations:
            if name == "carry-dropped":
                old = b"    while total >> 16:\n        total = (total & 65535) + (total >> 16)\n    return total"
                new = b"    return total & 65535"
            if original.count(old) != 1:
                raise RuntimeError("mutation target not unique")
            SOURCE.write_bytes(original.replace(old, new))
            clear_cache()
            child = run("mutation-" + name, tests)
            text = (child.stdout + child.stderr).decode("utf-8", errors="replace")
            failures = len(re.findall(r"^FAIL: ", text, re.MULTILINE))
            errors = len(re.findall(r"^ERROR: ", text, re.MULTILINE))
            intended_failed = bool(re.search(r"^FAIL: " + re.escape(intended) + r"\b", text, re.MULTILINE))
            results[name] = dict(exit=child.returncode, assertion_failures=failures,
                                 errors=errors, intended_assertion_failed=intended_failed)
            if child.returncode == 0 or not intended_failed or errors:
                raise RuntimeError("mutation did not fail intended assertion cleanly")
            SOURCE.write_bytes(original)
    finally:
        SOURCE.write_bytes(original)
        clear_cache()
    for name, args in (("normal", tests), ("optimized", ["-O", *tests]),
                       ("compile", ["-m", "compileall", "-q", "checksum_lab.py", "tests", "verification/verify.py"]),
                       ("bandit", ["-m", "bandit", "-q", "-r", "checksum_lab.py", "tests", "verification/verify.py",
                                   "-f", "json", "-o", str(OUT / "bandit.json")])):
        child = run(name, args)
        results[name] = {"exit": child.returncode}
        if child.returncode:
            raise RuntimeError(name + " failed")
    demos = {}
    for path in sorted((ROOT / "examples").glob("*.json")):
        expected = {"modeled": 0, "mixed": 3, "empty": 0,
                    "invalid-late": 2, "invalid-after-residual": 2}[path.stem]
        child = run("demo-" + path.stem, [str(SOURCE), str(path)])
        if child.returncode != expected or (expected == 2 and child.stdout):
            raise RuntimeError("demo mismatch")
        report = json.loads(child.stdout) if expected != 2 else None
        demos[path.name] = dict(exit=child.returncode, rows=len(report["rows"]) if report else None)
    sys.path.insert(0, str(ROOT))
    import checksum_lab
    cases = [{"id": "X" * 30 + f"{i:02}", "operation": "replace_word", "data_hex": "FFFF" * 128,
              "offset": 254, "new_word": 0} for i in range(64)]
    data = json.dumps({"version": 1, "cases": cases}).encode()
    output = checksum_lab._serialize(checksum_lab.analyze(data)).encode("ascii")
    stress = dict(input_bytes=len(data), output_bytes=len(output), rows=64, decoded_bytes=16384,
                  id_length=32, output_cap=262144, within_cap=len(output) <= 262144,
                  exact_maximum_claim=False)
    (OUT / "output-stress.json").write_text(json.dumps(stress, indent=2) + "\n", encoding="utf-8")
    paths = [SOURCE, ROOT / "tests/test_checksum_lab.py", Path(__file__).resolve(), ROOT / "SCHEMA.md",
             ROOT / "tests/hand-oracles.json", OUT / "frozen-contract.json", ROOT / "research/freeze-fixtures.ps1",
             *sorted((ROOT / "examples").glob("*.json"))]
    receipt = dict(python=sys.version, checks=results, demos=demos, stress=stress,
                   frozen_verified=True, source_restored=SOURCE.read_bytes() == original,
                   sha256={str(p.relative_to(ROOT)).replace("\\", "/"): sha(p) for p in paths})
    (OUT / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))


def main():
    status = OUT / "latest-run.json"
    status.write_text('{"status":"running"}\n', encoding="utf-8")
    try:
        verify()
    except Exception:
        status.write_text('{"status":"failed","prior_receipt_is_historical":true}\n', encoding="utf-8")
        raise
    status.write_text('{"status":"passed"}\n', encoding="utf-8")


if __name__ == "__main__":
    main()
