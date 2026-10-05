"""Independent literal/arithmetic and bounded IO controls; no network or foreign code."""
import io
import json
from pathlib import Path
import socket
import subprocess  # nosec B404: fixed local owned Python checks only.
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import checksum_lab as lab

FIXTURES = json.loads((ROOT / "tests/hand-oracles.json").read_text(encoding="utf-8-sig"))


def encoded(cases):
    return json.dumps({"version": 1, "cases": cases}).encode()


def case(data="", operation="checksum", **fields):
    return dict(id="x", operation=operation, data_hex=data, **fields)


def column_oracle(data):
    # Separate high/low columns and modulo65535; preserve the two zero sums.
    total = sum(data[::2]) * 256 + sum(data[1::2])
    remainder = total % 65535
    return 65535 - (remainder or (65535 if total else 0))


class Sink:
    def __init__(self, mode="ok"):
        self.mode, self.text = mode, ""

    def write(self, text):
        self.text += text
        if self.mode == "broken":
            raise BrokenPipeError()
        if self.mode == "closed":
            raise ValueError("closed")
        if self.mode == "short":
            return len(text) - 1
        if self.mode == "float":
            return float(len(text))
        if self.mode == "bool":
            return True
        if self.mode == "none":
            return None
        if self.mode == "exotic":
            class Count(int):
                def __eq__(self, other):
                    raise AssertionError("count hook called")
            return Count(len(text))
        return len(text)

    def flush(self):
        if self.mode == "flush":
            raise OSError("flush")


class Checks(unittest.TestCase):
    def test_full_frozen_reports(self):
        for vector in FIXTURES["vectors"]:
            with self.subTest(vector=vector["input"]):
                self.assertEqual(lab.analyze(json.dumps(vector["input"]).encode()), vector["expected"])

    def test_envelopes(self):
        for envelope in FIXTURES["envelopes"]:
            with self.subTest(envelope=envelope["name"]):
                data = json.dumps(envelope["input"]).encode()
                if envelope["exit"] == 2:
                    with self.assertRaises(lab.LabError) as caught:
                        lab.analyze(data)
                    self.assertEqual("checksum-lab: " + str(caught.exception) + "\n", envelope["diagnostic"])
                else:
                    self.assertEqual(lab.analyze(data), envelope["expected"])

    def test_all_one_byte(self):
        for value in range(256):
            self.assertEqual(lab._checksum(bytes([value])), ((255 - value) << 8) | 255)

    def test_all_two_byte(self):
        for value in range(65536):
            self.assertEqual(lab._checksum(value.to_bytes(2, "big")), value ^ 65535)

    def test_column_oracle(self):
        for length in range(130):
            data = bytes((i * 37 + length) % 256 for i in range(length))
            self.assertEqual(lab._checksum(data), column_oracle(data))
        self.assertEqual(lab._checksum(b"\xff" * 4096), 0)

    def test_mandatory_padding(self):
        self.assertEqual(lab._checksum(b"\x01"), 65279)

    def test_mandatory_carry(self):
        self.assertEqual(lab._checksum(bytes.fromhex("FFFFFFFF0001")), 65534)

    def test_mandatory_eq3(self):
        result = lab.analyze(encoded([case("CD7A5555", "replace_word", offset=2, new_word=12933)]))["rows"][0]["result"]
        self.assertEqual(result["incremental_checksum"], 0)
        self.assertEqual(result["legacy_rfc1141_checksum"], 65535)

    def test_mandatory_residual_equality(self):
        result = lab.analyze(encoded([case("FFFF", "verify", supplied_checksum=65535)]))["rows"][0]["result"]
        self.assertTrue(result["arithmetic_residual_all_ones"])
        self.assertFalse(result["checksum_equality"])

    def test_anchored_updates(self):
        controls = [(old, 255 - old) for old in range(256)]
        controls += [(old, new) for old in (0, 1, 32768, 65534, 65535)
                     for new in (0, 1, 32768, 65534, 65535)]
        for old, new in controls:
            for offset in (0, 2):
                data = old.to_bytes(2, "big") + b"\x00\x01" if offset == 0 else b"\x00\x01" + old.to_bytes(2, "big")
                changed = data[:offset] + new.to_bytes(2, "big") + data[offset + 2:]
                result = lab.analyze(encoded([case(data.hex(), "replace_word", offset=offset, new_word=new)]))["rows"][0]["result"]
                self.assertEqual(result["incremental_checksum"], column_oracle(changed))
                self.assertEqual(result["recomputed_checksum"], column_oracle(changed))
                self.assertTrue(result["rfc1624_matches_recompute"])

    def test_guard_and_collision(self):
        self.assertEqual(lab.analyze(encoded([case("00005555", "replace_word", offset=2, new_word=0)]))["status"], "contains_unsupported")
        self.assertTrue(lab.analyze(encoded([case("FFFF0000", "replace_word", offset=2, new_word=0)]))["rows"][0]["update_guard"])
        self.assertEqual(lab._checksum(bytes.fromhex("00010002")), lab._checksum(bytes.fromhex("00020001")))

    def test_identity_no_hooks(self):
        class Hostile(bytes):
            def __len__(self):
                raise AssertionError("len hook")
            def __str__(self):
                raise AssertionError("str hook")
            def __eq__(self, other):
                raise AssertionError("eq hook")
        for value in (Hostile(b"{}"), {}, bytearray(b"{}"), memoryview(b"{}"), None):
            with self.assertRaises(lab.LabError):
                lab.analyze(value)

    def test_admission_before_any_math(self):
        for envelope in FIXTURES["envelopes"]:
            if envelope["exit"] == 2:
                with patch.object(lab, "_evaluate", side_effect=AssertionError("evaluated prefix")):
                    with self.assertRaises(lab.LabError):
                        lab.analyze(json.dumps(envelope["input"]).encode())

    def test_json_and_string_controls(self):
        invalid = [b"\xef\xbb\xbf{}", b"\xff", b"{}{}", b'{"version":1,"version":1,"cases":[]}',
                   b'{"version":1,"\\u0076ersion":1,"cases":[]}', b'{"version":1.0,"cases":[]}',
                   b'{"version":1e0,"cases":[]}', b'{"version":NaN,"cases":[]}',
                   b'{"version":123456,"cases":[]}', b'{"version":-12345,"cases":[]}',
                   b'[[[[[[[]]]]]]]', b'{"version":true,"cases":[]}', b'{"version":2,"cases":[]}',
                   b'{"version":1,"cases":[],"unknown":0}']
        for identifier in ("a\n", "é", "\x7f", "\ud800", "a" * 33, "-x", ""):
            item = case()
            item["id"] = identifier
            invalid.append(encoded([item]))
        for data in invalid:
            with self.subTest(data=data[:80]), self.assertRaises(lab.LabError):
                lab.analyze(data)
        self.assertEqual(lab.analyze(b'{"version":1,"cases":[{"id":"x-","operation":"verify","data_hex":"","supplied_checksum":-0}]}')["rows"][0]["assumptions"]["supplied_checksum"], 0)

    def test_operation_types_and_fields(self):
        invalid = [case("0"), case("00 01"), case("0x00"), case("gg"), case(None),
                   case("", "unknown"), {"id": "x"}, [], case("", supplied_checksum=0)]
        for value in (True, None, "0", -1, 65536, 1.0):
            invalid.append(case("", "verify", supplied_checksum=value))
            invalid.append(case("00010002", "replace_word", offset=2, new_word=value))
        for offset in (True, None, "2", -2, 1, 4, 2.0):
            invalid.append(case("00010002", "replace_word", offset=offset, new_word=0))
        for data in ("", "0000", "000100"):
            invalid.append(case(data, "replace_word", offset=0, new_word=0))
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(lab.LabError):
                lab.analyze(encoded([item]))
        with self.assertRaises(lab.LabError):
            lab.analyze(encoded([case(), case()]))

    def test_caps(self):
        good = encoded([case("00" * 4096)])
        lab.analyze(good)
        for data in (b" " * 65537, encoded([case("00" * 4097)])):
            with self.assertRaises(lab.LabError):
                lab.analyze(data)
        lab.analyze(encoded([dict(case("00" * 4096), id=str(i)) for i in range(4)]))
        with self.assertRaises(lab.LabError):
            lab.analyze(encoded([dict(case("00" * 4096), id=str(i)) for i in range(5)]))
        lab.analyze(encoded([dict(case(), id=str(i)) for i in range(64)]))
        with self.assertRaises(lab.LabError):
            lab.analyze(encoded([dict(case(), id=str(i)) for i in range(65)]))
        with patch.object(lab, "MAX_OUTPUT", 1):
            with self.assertRaises(lab.LabError):
                lab.analyze(encoded([]))

    def test_quote_depth_and_exact_raw_boundary(self):
        item = case()
        item["id"] = "x"
        root = encoded([item])
        self.assertEqual(lab.analyze(root + b" " * (65536 - len(root)))["status"], "modeled")
        with self.assertRaises(lab.LabError):
            lab.analyze(encoded([case("[" * 20)]))

    def test_no_hex_echo_or_order_loss(self):
        items = [dict(case("ABCDEF"), id="z"), dict(case("1234"), id="a")]
        report = lab.analyze(encoded(items))
        self.assertEqual([row["id"] for row in report["rows"]], ["z", "a"])
        self.assertNotIn("ABCDEF", lab._serialize(report))

    def test_exercised_paths_no_network_or_process(self):
        with patch.object(socket, "socket", side_effect=AssertionError("socket")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
            for vector in FIXTURES["vectors"]:
                self.assertEqual(lab.analyze(json.dumps(vector["input"]).encode()), vector["expected"])

    def test_sink_counts_and_flush(self):
        for mode in ("short", "float", "bool", "none", "exotic", "broken", "closed", "flush"):
            with self.subTest(mode=mode):
                sink, diagnostic = Sink(mode), Sink()
                with patch.object(sys, "stdout", sink), patch.object(sys, "stderr", diagnostic):
                    self.assertEqual(lab.main(["--help"]), 2)
                with patch.object(sys, "stderr", Sink(mode)):
                    self.assertEqual(lab.main([]), 2)
                with patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(encoded([])))), \
                     patch.object(sys, "stdout", Sink(mode)), patch.object(sys, "stderr", Sink(mode)):
                    self.assertEqual(lab.main(["-"]), 2)

    def test_actual_cli_examples_normal_optimized(self):
        for optimized in ([], ["-O"]):
            for envelope in FIXTURES["envelopes"]:
                child = subprocess.run([sys.executable, *optimized, "-B", str(ROOT / "checksum_lab.py"), "-"],
                                       input=json.dumps(envelope["input"]).encode(), capture_output=True, timeout=10)  # nosec B603: installed Python, owned file, no shell.
                self.assertEqual(child.returncode, envelope["exit"])
                if envelope["exit"] == 2:
                    self.assertEqual(child.stdout, b"")
                    self.assertEqual(child.stderr.decode(), envelope["diagnostic"])
                else:
                    self.assertEqual(json.loads(child.stdout), envelope["expected"])

    def test_actual_help_usage_unavailable(self):
        for optimized in ([], ["-O"]):
            for args, status in ((["--help"], 0), ([], 2), (["--bad-secret-path"], 2), (["missing-secret-path"], 2)):
                child = subprocess.run([sys.executable, *optimized, "-B", str(ROOT / "checksum_lab.py"), *args],
                                       capture_output=True, timeout=10)  # nosec B603: fixed local owned Python invocation.
                self.assertEqual(child.returncode, status)
                self.assertNotIn(b"secret", child.stdout + child.stderr)

    def test_actual_locally_closed_streams(self):
        for optimized in ([], ["-O"]):
            for close, argv in (("stdout", ["--help"]), ("stderr", []), ("stdout,stderr", ["--help"]), ("stdin", ["-"]), ("stdout", ["-"]), ("stderr", ["--bad"]), ("stdout,stderr", ["-"])):
                code = "import io,sys,checksum_lab as m\nsys.stdin=io.TextIOWrapper(io.BytesIO(b'{\"version\":1,\"cases\":[]}'))\n"
                for name in close.split(","):
                    code += f"sys.{name}.close()\n"
                code += f"sys.exit(m.main({argv!r}))\n"
                child = subprocess.run([sys.executable, *optimized, "-B", "-c", code], cwd=ROOT,
                                       capture_output=True, timeout=10)  # nosec B603: fixed owned close-stream child seam, no shell.
                self.assertEqual(child.returncode, 2)

    def test_actual_closed_os_pipes(self):
        for optimized in ([], ["-O"]):
            for output, error, argv in ((True, False, ["--help"]), (False, True, []), (True, True, ["--help"]), (True, False, ["-"])):
                code = "import io,sys,checksum_lab as m\nsys.stdin.buffer.read(1)\n"
                code += "sys.stdin=io.TextIOWrapper(io.BytesIO(b'{\"version\":1,\"cases\":[]}'))\n"
                code += f"sys.exit(m.main({argv!r}))\n"
                child = subprocess.Popen([sys.executable, *optimized, "-B", "-c", code], cwd=ROOT,
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # nosec B603: fixed local barrier/owned child, no shell.
                try:
                    if output:
                        child.stdout.close()
                    if error:
                        child.stderr.close()
                    child.stdin.write(b"!")
                    child.stdin.close()
                    self.assertEqual(child.wait(timeout=10), 2)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=10)
                    for stream in (child.stdin, child.stdout, child.stderr):
                        if not stream.closed:
                            stream.close()

    def test_synthetic_child_write_seams(self):
        for optimized in ([], ["-O"]):
            for mode in ("short", "float", "bool", "none", "exotic", "flush"):
                for target, argv in (("stdout", ["--help"]), ("stderr", []), ("stdout", ["-"]), ("stderr", ["-"])):
                    payload = b'{"version":1,"cases":[]}' if target == "stdout" else b'{}'
                    code = "import io,sys\nsys.path.insert(0,'tests')\nfrom test_checksum_lab import Sink\nimport checksum_lab as m\n"
                    code += f"sys.stdin=io.TextIOWrapper(io.BytesIO({payload!r}))\n"
                    code += f"sys.{target}=Sink({mode!r})\nsys.exit(m.main({argv!r}))\n"
                    child = subprocess.run([sys.executable, *optimized, "-B", "-c", code], cwd=ROOT,
                                           capture_output=True, timeout=10)  # nosec B603: labeled fixed synthetic write-count/flush child seam.
                    self.assertEqual(child.returncode, 2)


if __name__ == "__main__":
    unittest.main()
