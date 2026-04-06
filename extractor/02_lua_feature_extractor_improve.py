#!/usr/bin/env python3
"""
Ghidra 12.0.4 PyGhidra Lua Feature Extractor - IMPROVED
- struct_offsets 정확도 대폭 향상
- callees (호출하는 함수 entry point 목록) 추가 → agent propagation용
- call graph ready
"""

import sys
import json
import os
from collections import Counter, defaultdict
import pyghidra

pyghidra.start()

from ghidra.program.model.listing import FunctionIterator
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor

# ==================== 설정 ====================
PROJECT_DIR = "./ghidra_projects"
PROJECT_NAME = "LuaAnalyzer_arm64"
# ============================================

def load_current_program():
    project_dir_abs = os.path.abspath(PROJECT_DIR)
    project = pyghidra.open_project(project_dir_abs, PROJECT_NAME)
    root_folder = project.getProjectData().getRootFolder()
    domain_file = root_folder.getFiles()[0]          # 첫 번째 프로그램

    monitor = ConsoleTaskMonitor()
    program = domain_file.getReadOnlyDomainObject("lua_feature_extractor_improved", -1, monitor)
    print(f"[+] Loaded: {program.getName()} ({program.getLanguage().getLanguageID()})")
    return program

currentProgram = load_current_program()

def get_pcode_opcode_histogram(function):
    # (기존 코드 그대로 유지 - 생략)
    histogram = Counter()
    total = 0
    listing = currentProgram.getListing()
    for instr in listing.getInstructions(function.getBody(), True):
        for pcode in instr.getPcode():
            if pcode:
                op = PcodeOp.getMnemonic(pcode.getOpcode())
                histogram[op] += 1
                total += 1
    ratio = {k: round(v/total, 4) for k,v in histogram.items()} if total else {}
    return dict(histogram), ratio, total

def get_callees(function):
    """CALL/CALLIND pcode에서 callee entry point 수집"""
    callees = set()
    listing = currentProgram.getListing()
    for instr in listing.getInstructions(function.getBody(), True):
        for pcode in instr.getPcode():
            if pcode.getOpcode() in (PcodeOp.CALL, PcodeOp.CALLIND):
                for i in range(pcode.getNumInputs()):
                    vn = pcode.getInput(i)
                    if vn.isAddress():
                        addr = vn.getOffset()
                        if 0x100000 < addr < 0x2000000:  # 합리적인 코드 영역
                            callees.add(hex(addr)[2:].upper().zfill(8))
    return sorted(list(callees))

# extract_function_features() 함수의 해당 부분만 교체
def extract_function_features(func):
    if func.isExternal() or func.isThunk():
        return None

    features = {
        "function_name": func.getName(),          # training 때는 원본 이름, inference 때는 function_...
        "entry_point": str(func.getEntryPoint()),
        "size_bytes": func.getBody().getNumAddresses(),
        "basic_block_count": 0,
        "has_loops": False,
        "pcode_opcode_histogram": {},
        "pcode_opcode_ratio": {},
        "pcode_instruction_count": 0,
        "numeric_constants": [],
        "struct_offsets": [],                     # 개선됨
        "strings": [],
        "callees": [],                            # ★★★ agent propagation 핵심
        "data_xrefs_count": 0,
        "cyclomatic_complexity": 0
    }

    listing = currentProgram.getListing()
    body = func.getBody()

    # 1. Strings (기존)
    strings = []
    for addr in body.getAddresses(True):
        data = listing.getDataAt(addr)
        if data and data.hasStringValue():
            strings.append(str(data.getValue()))
    features["strings"] = list(set(strings))[:30]

# 2. Struct offsets - 개선 (0~0x1000 범위 + 8의 배수 필터링)
    offsets = []
    for instr in listing.getInstructions(body, True):
        for pcode in instr.getPcode():
            if pcode.getOpcode() in (PcodeOp.LOAD, PcodeOp.STORE):
                for i in range(pcode.getNumInputs()):
                    vn = pcode.getInput(i)
                    if vn.isConstant():
                        off = vn.getOffset()
                        if 0 <= off <= 0x1000 and off % 4 == 0:   # Lua struct field는 보통 8의 배수
                            offsets.append(off)
    features["struct_offsets"] = sorted(list(set(offsets)))[:50]
    # 3. Callees (agent용 핵심 feature)
    features["callees"] = get_callees(func)
    
    # 3,4. Basic Blocks & Loops - 그대로 유지 (이 부분은 이미 잘 동작함)
    bb_count, has_loop = get_basic_blocks_info(func)
    features["basic_block_count"] = bb_count
    features["has_loops"] = has_loop

    # 5. PCode histogram - 이 부분도 Instruction 순회 필요
    hist, hist_ratio, pcode_count = get_pcode_opcode_histogram(func)
    features["pcode_opcode_histogram"] = hist
    features["pcode_opcode_ratio"] = hist_ratio
    features["pcode_instruction_count"] = pcode_count

    # 6. Numeric constants - 마찬가지로 Instruction 순회 수정
    constants = []
    instr_iter = listing.getInstructions(func.getBody(), True)  # 다시 iterator
    for instr in instr_iter:
        for pcode in instr.getPcode():
            for i in range(pcode.getNumInputs()):
                vn = pcode.getInput(i)
                if vn.isConstant() and not vn.isAddress():
                    val = vn.getOffset()
                    if -0x100000000 < val < 0x100000000:
                        constants.append(val)
    features["numeric_constants"] = list(set(constants))[:40]

    # 7. Cyclomatic - 그대로
    features["cyclomatic_complexity"] = bb_count + 1

    # 8. Data xrefs - 그대로
    xrefs = 0
    ref_mgr = currentProgram.getReferenceManager()
    for addr in func.getBody().getAddresses(True):
        xrefs += len(list(ref_mgr.getReferencesFrom(addr)))
    features["data_xrefs_count"] = xrefs

    return features


def get_basic_blocks_info(function):
    bb_model = BasicBlockModel(currentProgram)
    monitor = ConsoleTaskMonitor()
    body = function.getBody()
    blocks = list(bb_model.getCodeBlocksContaining(body, monitor))

    bb_count = len(blocks)
    has_loop = False

    for block in blocks:
        dest_iter = block.getDestinations(monitor)
        
        # iterator를 직접 순회해서 리스트로 변환 (PyGhidra 안전 방식)
        destinations = []
        while dest_iter.hasNext():
            succ = dest_iter.next()
            destinations.append(succ)
        
        for succ in destinations:
            dest_block = succ.getDestinationBlock()
            if dest_block and dest_block.getFirstStartAddress() <= block.getFirstStartAddress():
                has_loop = True
                break
        if has_loop:
            break

    return bb_count, has_loop

def main():
    if len(sys.argv) < 2:
        print("Usage: python 01_lua_feature_extractor.py <output_json_path>")
        sys.exit(1)

    output_path = sys.argv[1]

    print(f"[+] Starting feature extraction on {currentProgram.getName()}")
    print(f"[+] Total functions: {currentProgram.getFunctionManager().getFunctionCount()}")

    results = []
    fm = currentProgram.getFunctionManager()

    # 모든 함수 리스트로 가져오기
    all_functions = list(fm.getFunctions(True))
    print(f"[+] Loaded {len(all_functions)} functions into list")

    monitor = ConsoleTaskMonitor()

    for func in all_functions:
        if func.isExternal() or func.isThunk():
            continue

        feats = extract_function_features(func)
        if feats:
            results.append(feats)
            if len(results) % 50 == 0:
                print(f"    Processed {len(results)} functions...")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"[+] Extraction completed! Saved {len(results)} functions to {output_path}")


if __name__ == "__main__":
    main()