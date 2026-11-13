"""Garanties de performance sans chronomètre : lectures et choix de modules bornés, résultats inchangés."""

from __future__ import annotations

import glob
import os

import pytest

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.core.pipeline import AnalyzerRegistry, run_pipeline
from forensic_analyzer.models.finding import FindingModel


class _Counting(BaseAnalyzer):
    name = "compteur"
    supported_extensions = (".txt",)

    def __init__(self):
        self.checks: dict[str, int] = {}

    def can_handle(self, path: str) -> bool:
        self.checks[path] = self.checks.get(path, 0) + 1
        return path.endswith(".txt")

    def analyze(self, path: str) -> FindingModel:
        return FindingModel(type="test", file=path)


def test_each_module_examines_each_file_once(tmp_path):
    files = []
    for i in range(5):
        f = tmp_path / f"f{i}.txt"
        f.write_text("x")
        files.append(str(f))
    counter = _Counting()
    report = run_pipeline(files, AnalyzerRegistry().register(counter))
    assert report.total == 5
    assert set(counter.checks.values()) == {1}


def test_lite_operands_match_capstone_detail():
    """Les opérandes relus du texte (mode lite) valent ceux du mode détaillé de capstone."""
    capstone = pytest.importorskip("capstone")
    binaries = [p for p in sorted(glob.glob("/usr/bin/*"))[:80] if os.path.isfile(p) and not os.path.islink(p)][:5]
    if not binaries:
        pytest.skip("aucun binaire système disponible")
    checked = 0
    for mode, bits in ((capstone.CS_MODE_64, 64), (capstone.CS_MODE_32, 32)):
        md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        md.detail = True
        md.skipdata = True  # traverser en-têtes et données jusqu'au code
        checked += _compare_operands(md, binaries, bits)
    assert checked > 1000


def _compare_operands(md, binaries: list[str], bits: int) -> int:
    from capstone import x86_const

    from forensic_analyzer.utils import disasm

    checked = 0
    for path in binaries:
        with open(path, "rb") as fh:
            code = fh.read(200_000)
        for insn in md.disasm(code, 0x400000):
            if insn.id == 0:  # octets de données sautés (skipdata) : aucun opérande à comparer
                continue
            lite = disasm._Insn(insn.address, insn.size, insn.mnemonic, insn.op_str.split(", ") if insn.op_str else [], bits)
            for ours, ref in zip(lite.operands, insn.operands, strict=False):
                assert ours.type == ref.type, insn
                if ref.type == x86_const.X86_OP_IMM:
                    assert ours.imm == ref.imm, insn
                elif ref.type == x86_const.X86_OP_REG:
                    assert ours.reg == insn.reg_name(ref.reg), insn
                else:
                    assert disasm._operand_address(lite, ours) == disasm._operand_address(insn, ref), insn
            checked += 1
    return checked
