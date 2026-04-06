#!/usr/bin/env python3
"""
Ghidra PyGhidra Lua Feature Extractor - FINAL (HighFunction + Listing Hybrid)
- HighFunction: struct_offsets, read/write, compare, strings
- Listing: histogram, callgraph, bb, constants
"""

import sys
import json
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime
import itertools
import pyghidra
import gc
import time
import shutil   # ← 이 줄을 파일 상단 import 부분에 추가


pyghidra.start()

from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface

# ====================== 설정 ======================
BASE_DIR = Path.cwd().absolute()
BINARIES_DIR = BASE_DIR / "binaries"
OUTPUT_BASE = BASE_DIR / "outputs"
PROJECT_BASE = BASE_DIR / "extractor" / "ghidra_projects"

BATCH_SIZE = 1800

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

# ====================== Pointer Trace ======================
# ====================== Pointer Trace ======================
def trace_ptr(varnode, depth=0, visited=None, memo=None):
    if varnode is None:
        return None

    if visited is None:
        visited = set()

    if memo is None:
        memo = {}

    # 🔥 이미 계산된 경우 (성능 핵심)
    if varnode in memo:
        return memo[varnode]

    # 🔥 depth 제한
    if depth > 20:
        return None

    # 🔥 cycle 방지
    if varnode in visited:
        return None

    visited.add(varnode)

    # constant
    if varnode.isConstant():
        val = varnode.getOffset()
        memo[varnode] = val
        return val

    def_op = varnode.getDef()
    if def_op is None:
        memo[varnode] = None
        return None

    opcode = def_op.getOpcode()

    result = None

    # ADD / PTRSUB
    if opcode in (PcodeOp.INT_ADD, PcodeOp.PTRSUB):
        offset = 0
        for inp in def_op.getInputs():
            o = trace_ptr(inp, depth + 1, visited, memo)
            if o is not None:
                offset += o
        result = offset

    # MULT
    elif opcode == PcodeOp.INT_MULT:
        vals = []
        for inp in def_op.getInputs():
            o = trace_ptr(inp, depth + 1, visited, memo)
            if o is not None:
                vals.append(o)
        if len(vals) == 2:
            result = vals[0] * vals[1]

    else:
        # fallback
        for inp in def_op.getInputs():
            o = trace_ptr(inp, depth + 1, visited, memo)
            if o is not None:
                result = o
                break

    memo[varnode] = result
    return result
    
# 문자열 추출
# -----------------------------
def extract_strings(program, high_func):
    listing = program.getListing()
    addr_factory = program.getAddressFactory()
    strings = set()

    for op in high_func.getPcodeOps():
        for inp in op.getInputs():
            if inp.isConstant():
                try:
                    addr = addr_factory.getDefaultAddressSpace().getAddress(inp.getOffset())
                    data = listing.getDataAt(addr)

                    if data and data.hasStringValue():
                        s = str(data.getValue()).lower()

                        # 필터링
                        if len(s) >= 4 and not s.isdigit():
                            strings.add(s)

                except:
                    pass

    return list(strings)

import time

def extract_features_inside_program(currentProgram, lua_version, arch):
    results = []

    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    ref_mgr = currentProgram.getReferenceManager()

    iface = DecompInterface()
    iface.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()

    funcs = list(fm.getFunctions(True))
    total_funcs = len(funcs)

    print(f"[INFO] Total functions: {total_funcs}")

    def get_pcode_hist(function):
        hist = Counter()
        total = 0
        for instr in listing.getInstructions(function.getBody(), True):
            for p in instr.getPcode():
                if p:
                    op = PcodeOp.getMnemonic(p.getOpcode())
                    hist[op] += 1
                    total += 1
        ratio = {k: round(v/total, 4) for k,v in hist.items()} if total else {}
        return dict(hist), ratio, total

    def get_callees(function):
        callees = set()
        for instr in listing.getInstructions(function.getBody(), True):
            for p in instr.getPcode():
                if p.getOpcode() == PcodeOp.CALL:
                    vn = p.getInput(0)
                    if vn.isAddress():
                        addr = vn.getOffset()
                        f = fm.getFunctionAt(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr))
                        if f:
                            callees.add(f.getName())
        return list(callees)

    def get_callers(function):
        callers = set()
        for ref in ref_mgr.getReferencesTo(function.getEntryPoint()):
            if ref.getReferenceType().isCall():
                f = fm.getFunctionContaining(ref.getFromAddress())
                if f:
                    callers.add(f.getName())
        return list(callers)

    def get_bb(function):
        bb_model = BasicBlockModel(currentProgram)
        blocks = list(bb_model.getCodeBlocksContaining(function.getBody(), monitor))
        return len(blocks)

    for idx, func in enumerate(funcs):
        if func.isExternal() or func.isThunk():
            continue

        func_name = func.getName()
        entry = func.getEntryPoint()
        size = func.getBody().getNumAddresses()

        print(f"\n[FUNC {idx+1}/{total_funcs}] {func_name} @ {entry} size={size}")


        # -----------------------------
        # 🔥 Decompile timing
        # -----------------------------
        start_time = time.time()

        try:
            result = iface.decompileFunction(func, 0, monitor)

            elapsed = time.time() - start_time
            print(f"[DECOMP] done in {elapsed:.2f}s")

            if not result.decompileCompleted():
                print("[SKIP] decompile failed")
                continue

            high_func = result.getHighFunction()
            if high_func is None:
                print("[SKIP] high_func is None")
                continue

        except Exception as e:
            print(f"[ERROR] decompile crash: {e}")
            continue

        # -----------------------------
        # Feature Extraction
        # -----------------------------
        offsets = []
        read_count = defaultdict(int)
        write_count = defaultdict(int)
        compare_map = defaultdict(set)
        strings = set()

        try:
            count = 0
            for op in high_func.getPcodeOps():
                opcode = op.getOpcode()
                count += 1
                if count % 10 == 0:
                    print(f"[PCODE] {func_name} processed {count}")

                if opcode in (PcodeOp.LOAD, PcodeOp.STORE):
                    ptr = op.getInput(1)
                    offset = trace_ptr(ptr, 0, set(), {})

                    if offset is not None:
                        offset = int(offset)
                        offsets.append(offset)

                        if opcode == PcodeOp.LOAD:
                            read_count[offset] += 1
                        else:
                            write_count[offset] += 1

                if opcode in (
                    PcodeOp.INT_EQUAL,
                    PcodeOp.INT_NOTEQUAL,
                    PcodeOp.INT_LESS,
                    PcodeOp.INT_LESSEQUAL
                ):
                    const_val = None
                    ptr_node = None

                    for inp in op.getInputs():
                        if inp.isConstant():
                            const_val = inp.getOffset()
                        else:
                            ptr_node = inp

                    if const_val is not None and ptr_node is not None:
                        
                        offset = trace_ptr(ptr_node, 0, set(), {})
                        if offset is not None:
                            compare_map[int(offset)].add(int(const_val))

                for inp in op.getInputs():
                    if inp.isConstant():
                        try:
                            addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(inp.getOffset())
                            data = listing.getDataAt(addr)
                            if data and data.hasStringValue():
                                s = str(data.getValue()).lower()
                                if len(s) >= 4:
                                    strings.add(s)
                        except:
                            pass

        except Exception as e:
            print(f"[ERROR] feature extraction failed: {e}")
            continue

        unique_offsets = list(set(offsets))

        hist, ratio, pcount = get_pcode_hist(func)

        features = {
            "function_name": func_name,
            "entry_point": str(entry),
            "basic_block_count": get_bb(func),

            "pcode_opcode_histogram": hist,
            "pcode_opcode_ratio": ratio,
            "pcode_instruction_count": pcount,
            "callees": get_callees(func),
            "callers": get_callers(func),

            "struct_offsets": unique_offsets,
            "read_write": {
                str(off): {
                    "read": read_count[off],
                    "write": write_count[off]
                } for off in unique_offsets
            },
            "compare": {
                str(off): list(vals)
                for off, vals in compare_map.items()
            },
            "co_occurrence": list(itertools.combinations(unique_offsets, 2)),

            "strings": list(strings),

            "lua_version": lua_version,
            "architecture": arch
        }

        results.append(features)

    iface.dispose()
    return results


# ====================== MAIN ======================
# def main(binary_path):
#     with pyghidra.open_program(binary_path) as api:
#         program = api.getCurrentProgram()
#         results = extract_features_inside_program(program, "unknown", "unknown")

#     print(json.dumps(results, indent=2))

# BINARY_PATH = Path("/Volumes/DO/lua_custom_engine_binaries/03_Lua_Mapper/lua_extract_feature_ghidra/binaries/Lua_547/aarch64/O0/nostrip/lua_lua_547_0000")

# if __name__ == "__main__":
#     main(str(BINARY_PATH))

# ====================== Main ======================
# def main():
#     print(f"[{datetime.now()}] Starting batch feature extraction...")

#     for lua_dir in sorted(BINARIES_DIR.glob("Lua_*")):
#         for arch_dir in sorted(lua_dir.glob("*")):
#             for opt_dir in sorted(arch_dir.glob("O*")):
#                 for status_dir in sorted(opt_dir.glob("*")):
#                     if status_dir.name != "nostrip":
#                         continue
#                     for binary in sorted(status_dir.glob("*")):
#                         if not binary.is_file() or binary.name.startswith('.'):
#                             continue

#                         lua_version, arch, opt_level = get_binary_info(binary)
#                         if not lua_version:
#                             continue

#                         print(f"\n[{datetime.now()}] Processing: {binary.name} | {lua_version} | {arch}")

#                         # with 블록 안에서 모든 작업 완료
#                         with pyghidra.open_program(
#                             str(binary.absolute()),
#                             project_location=str(PROJECT_BASE / lua_version / arch / opt_level / "nostrip"),
#                             project_name=f"LuaAnalyzer_{lua_version}_{arch}_{opt_level}_{binary.stem}",
#                             analyze=True
#                         ) as flat_api:
#                             currentProgram = flat_api.getCurrentProgram()

#                             results = extract_features_inside_program(currentProgram, lua_version, arch)

#                             output_dir = OUTPUT_BASE / lua_version / "feture_json"
#                             output_dir.mkdir(parents=True, exist_ok=True)

#                             timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
#                             output_path = output_dir / f"{arch}_{opt_level}_nostrip_{binary.stem}_{timestamp}.json"

#                             with open(output_path, "w", encoding="utf-8") as f:
#                                 json.dump(results, f, indent=2, ensure_ascii=False)

#                             print(f"[+] Saved {len(results)} functions to {output_path}")

#     print(f"\n[{datetime.now()}] All done.")


# ====================== Main ======================
# ====================== Main ======================
# ====================== Main ======================
def main():
    print(f"[{datetime.now()}] LuaMapper Agent 배치 Feature 추출 시작 (BATCH_SIZE = 1000)")

    processed = 0
    batch_count = 0

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

                        print(f"\n[{datetime.now()}] [{processed+1}] Processing: {binary.name} | {lua_version} | {arch}")

                        try:
                            project_loc = PROJECT_BASE / lua_version / arch / opt_level / "nostrip"
                            project_name = f"LuaAnalyzer_{lua_version}_{arch}_{opt_level}_{binary.stem}"

                            # 프로젝트 폴더가 이미 있으면 미리 삭제 (안전하게)
                            if project_loc.exists():
                                shutil.rmtree(project_loc, ignore_errors=True)
                                time.sleep(1)

                            with pyghidra.open_program(
                                str(binary.absolute()),
                                project_location=str(project_loc),
                                project_name=project_name,
                                analyze=True
                            ) as flat_api:
                                currentProgram = flat_api.getCurrentProgram()

                                print("  → Waiting for analysis to complete...")
                                time.sleep(10)   # 분석 완료 대기

                                results = extract_features_inside_program(currentProgram, lua_version, arch)

                                # JSON 저장
                                output_dir = OUTPUT_BASE / lua_version / "feture_json"
                                output_dir.mkdir(parents=True, exist_ok=True)
                                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                output_path = output_dir / f"{arch}_{opt_level}_nostrip_{binary.stem}_{timestamp}.json"

                                with open(output_path, "w", encoding="utf-8") as f:
                                    json.dump(results, f, indent=2, ensure_ascii=False)

                                print(f"[+] Saved {len(results)} functions → {output_path.name}")

                            # with 블록 완전히 끝난 후 프로젝트 삭제
                            print("  → Deleting Ghidra project...")
                            if project_loc.exists():
                                shutil.rmtree(project_loc, ignore_errors=True)
                                print(f"  → Project deleted: {project_loc}")

                        except Exception as e:
                            print(f"[ERROR] {binary.name} - {e}")

                        processed += 1
                        batch_count += 1

                        # 1000개마다 메모리 정리
                        if batch_count >= BATCH_SIZE:
                            print(f"[MEMORY CLEAN] {processed}개 완료 → 메모리 정리")
                            gc.collect()
                            batch_count = 0
                            time.sleep(10)

    print(f"\n[{datetime.now()}] 전체 배치 완료! Total processed: {processed}")

if __name__ == "__main__":
    main()