#!/usr/bin/env python3
"""
Ghidra 12.0.4 PyGhidra Lua Feature Extractor - Headless Mode
- 프로젝트 및 프로그램 read-only 로드
- PCode 기반 feature 추출 (Lua 임베딩 함수 복원용)
"""

import sys
import json
import os
from collections import Counter
import pyghidra


pyghidra.start()

from ghidra.program.model.listing import FunctionIterator
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor

def load_current_program():
    project_relative = "./ghidra_projects"
    project_name = "LuaAnalyzer_arm64"

    project_dir_abs = os.path.abspath(project_relative)
    if not os.path.isdir(project_dir_abs):
        print(f"Error: Project directory not found: {project_dir_abs}")
        sys.exit(1)

    print(f"[*] Absolute project dir: {project_dir_abs}")

    try:
        project = pyghidra.open_project(project_dir_abs, project_name)
        print(f"[+] Project opened: {project.getName()}")

        root_folder = project.getProjectData().getRootFolder()
        domain_files = root_folder.getFiles()

        if not domain_files:
            print("Error: No programs found in project root folder!")
            sys.exit(1)

        print(f"[+] Found {len(domain_files)} programs")

        domain_file = domain_files[0]
        print(f"[+] Loading program: {domain_file.getName()}")

        monitor = ConsoleTaskMonitor()

        # ★ 핵심 수정: 3개 인자 맞춰서 호출
        # consumer = None (headless에서 허용됨)
        # version = -1 (DEFAULT_VERSION)
        dummy_consumer = "lua_feature_extractor"
        current_program = domain_file.getReadOnlyDomainObject(dummy_consumer, -1, monitor)

        if current_program is None:
            print("Error: Failed to load read-only program")
            sys.exit(1)

        print(f"[+] Loaded program (read-only): {current_program.getName()}")
        print(f"[+] Language: {current_program.getLanguage().getLanguageID()}")
        return current_program

    except Exception as e:
        print(f"Project/Program load error: {str(e)}")
        print(f"Exception type: {type(e).__name__}")
        sys.exit(1)

# 프로그램 로드 (스크립트 시작 시 한 번)
currentProgram = load_current_program()


def get_pcode_opcode_histogram(function):
    histogram = Counter()
    total_pcode = 0

    listing = currentProgram.getListing()
    instr_iter = listing.getInstructions(function.getBody(), True)

    for instr in instr_iter:
        for pcode in instr.getPcode():
            if pcode is None:
                continue
            opcode_name = PcodeOp.getMnemonic(pcode.getOpcode())
            histogram[opcode_name] += 1
            total_pcode += 1

    hist_dict = dict(histogram)
    if total_pcode > 0:
        hist_ratio = {k: round(v / total_pcode, 4) for k, v in histogram.items()}
        return hist_dict, hist_ratio, total_pcode
    return hist_dict, {}, 0


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

# extract_function_features() 함수의 해당 부분만 교체
def extract_function_features(func):
    if func.isExternal() or func.isThunk():
        return None

    features = {
        "function_name": func.getName(),
        "entry_point": str(func.getEntryPoint()),
        "size_bytes": func.getBody().getNumAddresses(),
    }

    listing = currentProgram.getListing()

    # 1. Strings - 개별 주소 순회
    strings = []
    addr_iter = func.getBody().getAddresses(True)  # forward iterator
    for addr in addr_iter:
        data = listing.getDataAt(addr)
        if data and data.hasStringValue():
            strings.append(str(data.getValue()))
    features["strings"] = list(set(strings))[:50]

    # 2. Struct offsets - Listing을 통해 Instruction 순회
    offsets = []
    instr_iter = listing.getInstructions(func.getBody(), True)  # ★ 핵심 수정 ★
    for instr in instr_iter:
        for pcode in instr.getPcode():
            if pcode.getOpcode() in (PcodeOp.LOAD, PcodeOp.STORE):
                for i in range(pcode.getNumInputs()):
                    vn = pcode.getInput(i)
                    if vn.isConstant():
                        offsets.append(vn.getOffset())
    features["struct_offsets"] = list(set(offsets))[:30]

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