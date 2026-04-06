#!/usr/bin/env python3
"""
Ghidra PyGhidra Lua Feature Extractor - Improved v2
- callees & callers를 함수 이름으로 저장 (nostrip 환경 우선)
- struct_offsets 필터링 강화
- get_callers() 에러 수정 (isCallOther 제거)
"""

import sys
import json
import os
from collections import Counter
import pyghidra

pyghidra.start()

from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressFactory

# ==================== 설정 ====================
PROJECT_DIR = "./ghidra_projects"
PROJECT_NAME = "LuaAnalyzer_arm64"
# ============================================

def load_current_program():
    project_dir_abs = os.path.abspath(PROJECT_DIR)
    project = pyghidra.open_project(project_dir_abs, PROJECT_NAME)
    root_folder = project.getProjectData().getRootFolder()
    domain_file = root_folder.getFiles()[0]  # 첫 번째 프로그램

    monitor = ConsoleTaskMonitor()
    program = domain_file.getReadOnlyDomainObject("lua_feature_extractor_v2", -1, monitor)
    print(f"[+] Loaded: {program.getName()} ({program.getLanguage().getLanguageID()})")
    return program

currentProgram = load_current_program()
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
    """이 함수가 호출하는 함수들 (이름 우선, fallback hex)"""
    callees = set()
    for instr in listing.getInstructions(function.getBody(), True):
        for pcode in instr.getPcode():
            if pcode is None:
                continue
            if pcode.getOpcode() not in (PcodeOp.CALL, PcodeOp.CALLIND):
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
    """이 함수를 호출하는 함수들 (이름 우선)"""
    callers = set()
    entry_point = function.getEntryPoint()

    # entry point로 들어오는 모든 reference
    refs = ref_mgr.getReferencesTo(entry_point)
    for ref in refs:
        # call 타입 reference만
        ref_type = ref.getReferenceType()
        if ref_type.isCall():  # isCallOther() 제거
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

def extract_function_features(func):
    if func.isExternal() or func.isThunk():
        return None

    features = {
        "function_name": func.getName(),
        "entry_point": str(func.getEntryPoint()),
        "size_bytes": func.getBody().getNumAddresses(),
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
        "cyclomatic_complexity": 0
    }

    body = func.getBody()

    # strings
    strings = []
    for addr in body.getAddresses(True):
        data = listing.getDataAt(addr)
        if data and data.hasStringValue():
            strings.append(str(data.getValue()))
    features["strings"] = list(set(strings))[:30]

    # struct_offsets - 강화 필터
    offsets = []
    for instr in listing.getInstructions(body, True):
        for pcode in instr.getPcode():
            if pcode.getOpcode() in (PcodeOp.LOAD, PcodeOp.STORE):
                for i in range(pcode.getNumInputs()):
                    vn = pcode.getInput(i)
                    if vn.isConstant():
                        off = vn.getOffset()
                        if 0 <= off <= 0x1000 and off % 4 == 0:
                            offsets.append(off)
    features["struct_offsets"] = sorted(list(set(offsets)))[:50]

    # callees & callers
    features["callees"] = get_callees(func)
    features["callers"] = get_callers(func)

    # pcode histogram
    hist, ratio, pcount = get_pcode_opcode_histogram(func)
    features["pcode_opcode_histogram"] = hist
    features["pcode_opcode_ratio"] = ratio
    features["pcode_instruction_count"] = pcount

    # numeric constants
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

    # basic blocks & loops
    bb_count, has_loop = get_basic_blocks_info(func)
    features["basic_block_count"] = bb_count
    features["has_loops"] = has_loop
    features["cyclomatic_complexity"] = bb_count + 1

    # data xrefs count
    xrefs = 0
    for addr in body.getAddresses(True):
        xrefs += len(list(ref_mgr.getReferencesFrom(addr)))
    features["data_xrefs_count"] = xrefs

    return features

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <output_json_path>")
        sys.exit(1)

    output_path = sys.argv[1]

    print(f"[+] Starting feature extraction on {currentProgram.getName()}")
    print(f"[+] Total functions: {currentProgram.getFunctionManager().getFunctionCount()}")

    results = []
    all_functions = list(currentProgram.getFunctionManager().getFunctions(True))
    print(f"[+] Loaded {len(all_functions)} functions into list")

    for func in all_functions:
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