#!/usr/bin/env python3
"""
Ghidra PyGhidra Lua Feature Extractor - Final Stable Batch (원본 기반)
- with 블록 안에서 분석 + feature 추출 모두 완료
- nostrip만 처리
- 학습용 최소 필드만 유지
"""

import sys
import json
from pathlib import Path
from collections import Counter
from datetime import datetime
import pyghidra

pyghidra.start()

from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressFactory

# ====================== 설정 ======================
BASE_DIR = Path.cwd().absolute()
BINARIES_DIR = BASE_DIR / "binaries"
OUTPUT_BASE = BASE_DIR / "outputs"
PROJECT_BASE = BASE_DIR / "extractor" / "ghidra_projects"

# ====================== Helper ======================
def get_binary_info(binary_path: Path):
    if not binary_path.is_file() or binary_path.name.startswith('.'):
        return None, None, None
    parts = binary_path.parts
    try:
        lua_version = next(p for p in parts if p.startswith("Lua_"))
        arch_dir = next(p for p in parts if p in ("arm64", "aarch64", "x86_64"))
        arch = "arm64" if arch_dir in ("arm64", "aarch64") else "x86_64"
        opt_level = next((p for p in parts if p.startswith("O")), "O0")
        return lua_version, arch, opt_level
    except:
        return None, None, None


# ====================== Feature Extraction (원본 그대로) ======================
def extract_features_inside_program(currentProgram, lua_version, arch):
    results = []
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    ref_mgr = currentProgram.getReferenceManager()

    def get_pcode_opcode_histogram(function):
        histogram = Counter()
        total = 0
        for instr in listing.getInstructions(function.getBody(), True):
            for pcode in instr.getPcode():
                if pcode:
                    op = PcodeOp.getMnemonic(pcode.getOpcode())
                    histogram[op] += 1
                    total += 1
        ratio = {k: round(v/total, 4) for k,v in histogram.items()} if total else {}
        return dict(histogram), ratio, total

    def get_callees(function):
        callees = set()
        for instr in listing.getInstructions(function.getBody(), True):
            for pcode in instr.getPcode():
                if pcode is None or pcode.getOpcode() not in (PcodeOp.CALL, PcodeOp.CALLIND):
                    continue
                if pcode.getNumInputs() > 0:
                    target_vn = pcode.getInput(0)
                    if target_vn.isAddress():
                        addr_offset = target_vn.getOffset()
                        target_addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr_offset)
                        target_func = fm.getFunctionAt(target_addr)
                        if target_func and not target_func.isExternal():
                            callees.add(target_func.getName())
                        else:
                            callees.add(hex(addr_offset)[2:].upper().zfill(8))
        return sorted(list(callees))

    def get_callers(function):
        callers = set()
        entry_point = function.getEntryPoint()
        refs = ref_mgr.getReferencesTo(entry_point)
        for ref in refs:
            if ref.getReferenceType().isCall():
                from_addr = ref.getFromAddress()
                caller_func = fm.getFunctionContaining(from_addr)
                if caller_func and not caller_func.isExternal():
                    callers.add(caller_func.getName())
        return sorted(list(callers))

    def get_basic_blocks_info(function):
        bb_model = BasicBlockModel(currentProgram)
        monitor = ConsoleTaskMonitor()
        body = function.getBody()
        blocks = list(bb_model.getCodeBlocksContaining(body, monitor))
        bb_count = len(blocks)
        has_loop = False
        for block in blocks:
            dest_iter = block.getDestinations(monitor)
            destinations = []
            while dest_iter.hasNext():
                destinations.append(dest_iter.next())
            for succ in destinations:
                dest_block = succ.getDestinationBlock()
                if dest_block and dest_block.getFirstStartAddress() <= block.getFirstStartAddress():
                    has_loop = True
                    break
            if has_loop:
                break
        return bb_count, has_loop

    all_functions = list(fm.getFunctions(True))
    print(f"[+] Extracting features from {len(all_functions)} functions...")

    for func in all_functions:
        if func.isExternal() or func.isThunk():
            continue

        body = func.getBody()
        features = {
            "function_name": func.getName(),
            "entry_point": str(func.getEntryPoint()),
            "size_bytes": body.getNumAddresses(),
            "basic_block_count": 0,
            "has_loops": False,
            "pcode_opcode_histogram": {},
            "pcode_opcode_ratio": {},
            "pcode_instruction_count": 0,
            "numeric_constants": [],
            "struct_offsets": [],
            "strings": [],
            "callees": [],
            "callers": [],
            "data_xrefs_count": 0,
            "cyclomatic_complexity": 0,
            "lua_version": lua_version,
            "architecture": arch
        }

        # strings 강화
        strings = []
        for addr in body.getAddresses(True):
            data = listing.getDataAt(addr)
            if data and data.hasStringValue():
                str_value = str(data.getValue())
                if str_value:  # 빈 문자열 제외
                    strings.append(str_value)
        features["strings"] = list(set(strings))[:60]

        # struct_offsets 강화 (Lua 구조체는 종종 0x3000~0x5000대 오프셋도 나옴)
        offsets = []
        for instr in listing.getInstructions(body, True):
            for pcode in instr.getPcode():
                if pcode.getOpcode() in (PcodeOp.LOAD, PcodeOp.STORE):
                    for i in range(pcode.getNumInputs()):
                        vn = pcode.getInput(i)
                        if vn.isConstant():
                            off = vn.getOffset()
                            # 범위 크게 확대
                            if -0x2000 <= off <= 0x6000 and (off % 4 == 0 or off % 8 == 0):
                                offsets.append(off)
        features["struct_offsets"] = sorted(list(set(offsets)))[:100]

        features["callees"] = get_callees(func)
        features["callers"] = get_callers(func)

        hist, ratio, pcount = get_pcode_opcode_histogram(func)
        features["pcode_opcode_histogram"] = hist
        features["pcode_opcode_ratio"] = ratio
        features["pcode_instruction_count"] = pcount

        constants = []
        for instr in listing.getInstructions(body, True):
            for pcode in instr.getPcode():
                for i in range(pcode.getNumInputs()):
                    vn = pcode.getInput(i)
                    if vn.isConstant() and not vn.isAddress():
                        val = vn.getOffset()
                        if -0x100000000 < val < 0x100000000:
                            constants.append(val)
        features["numeric_constants"] = sorted(list(set(constants)))[:40]

        bb_count, has_loop = get_basic_blocks_info(func)
        features["basic_block_count"] = bb_count
        features["has_loops"] = has_loop
        features["cyclomatic_complexity"] = bb_count + 1

        xrefs = 0
        for addr in body.getAddresses(True):
            xrefs += len(list(ref_mgr.getReferencesFrom(addr)))
        features["data_xrefs_count"] = xrefs

        results.append(features)

    return results


# ====================== Main ======================
def main():
    print(f"[{datetime.now()}] Starting batch feature extraction...")

    for lua_dir in sorted(BINARIES_DIR.glob("Lua_*")):
        for arch_dir in sorted(lua_dir.glob("*")):
            for opt_dir in sorted(arch_dir.glob("O*")):
                for status_dir in sorted(opt_dir.glob("*")):
                    if status_dir.name != "nostrip":
                        continue
                    for binary in sorted(status_dir.glob("*")):
                        if not binary.is_file() or binary.name.startswith('.'):
                            continue

                        lua_version, arch, opt_level = get_binary_info(binary)
                        if not lua_version:
                            continue

                        print(f"\n[{datetime.now()}] Processing: {binary.name} | {lua_version} | {arch}")

                        # with 블록 안에서 모든 작업 완료
                        with pyghidra.open_program(
                            str(binary.absolute()),
                            project_location=str(PROJECT_BASE / lua_version / arch / opt_level / "nostrip"),
                            project_name=f"LuaAnalyzer_{lua_version}_{arch}_{opt_level}_{binary.stem}",
                            analyze=True
                        ) as flat_api:
                            currentProgram = flat_api.getCurrentProgram()

                            results = extract_features_inside_program(currentProgram, lua_version, arch)

                            output_dir = OUTPUT_BASE / lua_version / "feture_json"
                            output_dir.mkdir(parents=True, exist_ok=True)

                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            output_path = output_dir / f"{arch}_{opt_level}_nostrip_{binary.stem}_{timestamp}.json"

                            with open(output_path, "w", encoding="utf-8") as f:
                                json.dump(results, f, indent=2, ensure_ascii=False)

                            print(f"[+] Saved {len(results)} functions to {output_path}")

    print(f"\n[{datetime.now()}] All done.")

if __name__ == "__main__":
    main()