# extractor/feature_extractor_post.py
"""
Ghidra analyzeHeadless Post Script - Lua Feature Extraction
- currentProgram을 명확하고 안전하게 사용
- 모든 변수 사전 선언
"""

import json
from collections import Counter
from datetime import datetime
import os

# ====================== Ghidra Import ======================
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor

# ====================== 환경 변수 ======================
output_base = os.getenv("FEATURE_OUTPUT_BASE", "/tmp/lua_features")
lua_version = os.getenv("LUA_VERSION", "unknown")
architecture = os.getenv("ARCH", "arm64")

# Ghidra가 자동으로 제공하는 전역 변수 (Post Script 환경)
# 안전하게 변수로 할당
current_program = currentProgram
binary_name = current_program.getName()

output_dir = os.path.join(output_base, lua_version, "feture_json")
os.makedirs(output_dir, exist_ok=True)

print(f"[PostScript] Starting → {binary_name} ({lua_version} | {architecture})")

# ====================== 객체 미리 선언 ======================
listing = current_program.getListing()
fm = current_program.getFunctionManager()
ref_mgr = current_program.getReferenceManager()

# ====================== Helper Functions ======================
def get_pcode_opcode_histogram(func):
    histogram = Counter()
    total = 0
    for instr in listing.getInstructions(func.getBody(), True):
        for pcode in instr.getPcode():
            if pcode:
                op = PcodeOp.getMnemonic(pcode.getOpcode())
                histogram[op] += 1
                total += 1
    ratio = {k: round(v / total, 4) for k, v in histogram.items()} if total else {}
    return dict(histogram), ratio, total


def get_callees(func):
    callees = set()
    for instr in listing.getInstructions(func.getBody(), True):
        for pcode in instr.getPcode():
            if pcode is None or pcode.getOpcode() not in (PcodeOp.CALL, PcodeOp.CALLIND):
                continue
            if pcode.getNumInputs() > 0:
                target_vn = pcode.getInput(0)
                if target_vn.isAddress():
                    addr_offset = target_vn.getOffset()
                    target_addr = current_program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_offset)
                    target_func = fm.getFunctionAt(target_addr)
                    if target_func and not target_func.isExternal():
                        callees.add(target_func.getName())
                    else:
                        callees.add(hex(addr_offset)[2:].upper().zfill(8))
    return sorted(list(callees))


def get_callers(func):
    callers = set()
    entry_point = func.getEntryPoint()
    for ref in ref_mgr.getReferencesTo(entry_point):
        if ref.getReferenceType().isCall():
            from_addr = ref.getFromAddress()
            caller_func = fm.getFunctionContaining(from_addr)
            if caller_func and not caller_func.isExternal():
                callers.add(caller_func.getName())
    return sorted(list(callers))


def get_basic_blocks_info(func):
    bb_model = BasicBlockModel(current_program)
    monitor = ConsoleTaskMonitor()
    body = func.getBody()
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


# ====================== 메인 추출 ======================
results = []

print(f"[PostScript] Total functions: {fm.getFunctionCount()}")

for func in fm.getFunctions(True):
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
        "architecture": architecture
    }

    # strings
    strings = []
    for addr in body.getAddresses(True):
        data = listing.getDataAt(addr)
        if data and data.hasStringValue():
            strings.append(str(data.getValue()))
    features["strings"] = list(set(strings))[:30]

    # struct_offsets
    offsets = []
    for instr in listing.getInstructions(body, True):
        for pcode in instr.getPcode():
            if pcode.getOpcode() in (PcodeOp.LOAD, PcodeOp.STORE):
                for i in range(pcode.getNumInputs()):
                    vn = pcode.getInput(i)
                    if vn.isConstant():
                        off = vn.getOffset()
                        if 0 <= off <= 0x2000 and off % 4 == 0:
                            offsets.append(off)
    features["struct_offsets"] = sorted(list(set(offsets)))[:50]

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

# ====================== 저장 ======================
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_path = os.path.join(output_dir, f"{architecture}_O0_nostrip_{binary_name}_{timestamp}.json")

with open(output_path, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(f"[PostScript] Completed → Saved {len(results)} functions to {output_path}")