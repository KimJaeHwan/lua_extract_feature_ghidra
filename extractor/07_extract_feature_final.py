#!/usr/bin/env python3
import sys
import json
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime
import itertools
import pyghidra

pyghidra.start()

from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
BINARY_PATH = Path("/Volumes/DO/lua_custom_engine_binaries/03_Lua_Mapper/lua_extract_feature_ghidra/binaries/Lua_547/aarch64/O0/nostrip/lua_lua_547_0000")

# ====================== Pointer Trace ======================
def trace_ptr(varnode, depth=0):
    if varnode is None or depth > 20:
        return None

    if varnode.isConstant():
        return varnode.getOffset()

    def_op = varnode.getDef()
    if not def_op:
        return None

    opcode = def_op.getOpcode()

    if opcode in (PcodeOp.INT_ADD, PcodeOp.PTRSUB):
        offset = 0
        for inp in def_op.getInputs():
            o = trace_ptr(inp, depth + 1)
            if o:
                offset += o
        return offset

    if opcode == PcodeOp.INT_MULT:
        vals = []
        for inp in def_op.getInputs():
            o = trace_ptr(inp, depth + 1)
            if o:
                vals.append(o)
        if len(vals) == 2:
            return vals[0] * vals[1]

    return None


# ====================== Feature Extraction ======================
def extract_features(program, func):
    listing = program.getListing()
    fm = program.getFunctionManager()
    ref_mgr = program.getReferenceManager()
    addr_factory = program.getAddressFactory()

    body = func.getBody()

    read_count = defaultdict(int)
    write_count = defaultdict(int)
    compare_map = defaultdict(set)
    stride_map = {}
    offsets = []
    strings = set()

    # ---------------- Pcode 분석 ----------------
    for instr in listing.getInstructions(body, True):
        for pcode in instr.getPcode():
            opcode = pcode.getOpcode()

            # LOAD / STORE → offset + RW
            if opcode in (PcodeOp.LOAD, PcodeOp.STORE):
                ptr = pcode.getInput(1)
                offset = trace_ptr(ptr)

                if offset is not None:
                    offset = int(offset)
                    offsets.append(offset)

                    if opcode == PcodeOp.LOAD:
                        read_count[offset] += 1
                    else:
                        write_count[offset] += 1

            # compare
            if opcode in (
                PcodeOp.INT_EQUAL,
                PcodeOp.INT_NOTEQUAL,
                PcodeOp.INT_LESS,
                PcodeOp.INT_LESSEQUAL
            ):
                const_val = None
                ptr_node = None

                for i in range(pcode.getNumInputs()):
                    vn = pcode.getInput(i)
                    if vn.isConstant():
                        const_val = vn.getOffset()
                    else:
                        ptr_node = vn

                if const_val is not None and ptr_node is not None:
                    offset = trace_ptr(ptr_node)
                    if offset is not None:
                        compare_map[int(offset)].add(int(const_val))

            # 문자열 추출
            for i in range(pcode.getNumInputs()):
                vn = pcode.getInput(i)
                if vn.isConstant():
                    try:
                        addr = addr_factory.getDefaultAddressSpace().getAddress(vn.getOffset())
                        data = listing.getDataAt(addr)
                        if data and data.hasStringValue():
                            s = str(data.getValue()).lower()
                            if len(s) >= 4:
                                strings.add(s)
                    except:
                        pass

    unique_offsets = list(set(offsets))

    # co-occurrence
    co_occurrence = list(itertools.combinations(unique_offsets, 2))

    # loop heuristic
    loop_map = {}
    for off in unique_offsets:
        total = read_count[off] + write_count[off]
        loop_map[off] = total > 3

    # ---------------- 기존 feature ----------------
    def get_pcode_hist():
        hist = Counter()
        total = 0
        for instr in listing.getInstructions(body, True):
            for p in instr.getPcode():
                if p:
                    op = PcodeOp.getMnemonic(p.getOpcode())
                    hist[op] += 1
                    total += 1
        ratio = {k: round(v/total, 4) for k,v in hist.items()} if total else {}
        return dict(hist), ratio, total

    def get_callees():
        callees = set()
        for instr in listing.getInstructions(body, True):
            for p in instr.getPcode():
                if p.getOpcode() == PcodeOp.CALL:
                    vn = p.getInput(0)
                    if vn.isAddress():
                        addr = vn.getOffset()
                        f = fm.getFunctionAt(program.getAddressFactory().getDefaultAddressSpace().getAddress(addr))
                        if f:
                            callees.add(f.getName())
        return list(callees)

    def get_callers():
        callers = set()
        for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
            if ref.getReferenceType().isCall():
                f = fm.getFunctionContaining(ref.getFromAddress())
                if f:
                    callers.add(f.getName())
        return list(callers)

    def get_bb():
        bb_model = BasicBlockModel(program)
        monitor = ConsoleTaskMonitor()
        blocks = list(bb_model.getCodeBlocksContaining(body, monitor))
        return len(blocks)

    hist, ratio, pcount = get_pcode_hist()

    # ---------------- 최종 ----------------
    return {
        "function_name": func.getName(),
        "entry_point": str(func.getEntryPoint()),

        # 기존
        "basic_block_count": get_bb(),
        "pcode_opcode_histogram": hist,
        "pcode_opcode_ratio": ratio,
        "pcode_instruction_count": pcount,
        "callees": get_callees(),
        "callers": get_callers(),

        # 🔥 구조 분석
        "struct_offsets": unique_offsets,
        "read_write": {
            str(k): {"read": read_count[k], "write": write_count[k]}
            for k in unique_offsets
        },
        "compare": {
            str(k): list(v) for k, v in compare_map.items()
        },
        "loop": {
            str(k): loop_map[k] for k in unique_offsets
        },
        "co_occurrence": co_occurrence,

        # 🔥 의미
        "strings": list(strings)[:50]
    }


# ====================== MAIN ======================
def main(binary_path):
    results = []

    with pyghidra.open_program(binary_path) as api:
        program = api.getCurrentProgram()
        fm = program.getFunctionManager()

        for func in fm.getFunctions(True):
            if func.isExternal() or func.isThunk():
                continue

            feat = extract_features(program, func)
            if feat:
                results.append(feat)

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main(str(BINARY_PATH))