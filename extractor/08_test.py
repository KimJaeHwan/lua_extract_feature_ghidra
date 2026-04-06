from pathlib import Path

BINARY_PATH = Path("/Volumes/DO/lua_custom_engine_binaries/03_Lua_Mapper/lua_extract_feature_ghidra/binaries/Lua_547/aarch64/O0/nostrip/lua_lua_547_0000")
import pyghidra
import json
import sys
import itertools
from collections import defaultdict

pyghidra.start()

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp


# -----------------------------
# pointer 추적 (base + offset)
# -----------------------------
def trace_ptr(varnode, depth=0):
    if varnode is None or depth > 20:
        return (None, None)

    if varnode.isConstant():
        return (None, varnode.getOffset())

    if varnode.isRegister():
        high = varnode.getHigh()
        if high:
            sym = high.getSymbol()
            if sym and sym.isParameter():
                return (f"arg{sym.getCategoryIndex()}", 0)

    def_op = varnode.getDef()
    if def_op is None:
        return (None, None)

    opcode = def_op.getOpcode()

    if opcode in (PcodeOp.INT_ADD, PcodeOp.PTRSUB):
        base = None
        offset = 0

        for inp in def_op.getInputs():
            b, o = trace_ptr(inp, depth + 1)
            if b:
                base = b
            if o:
                offset += o

        return (base, offset)

    if opcode == PcodeOp.INT_MULT:
        vals = []
        for inp in def_op.getInputs():
            _, o = trace_ptr(inp, depth + 1)
            if o:
                vals.append(o)
        if len(vals) == 2:
            return (None, vals[0] * vals[1])

    for inp in def_op.getInputs():
        b, o = trace_ptr(inp, depth + 1)
        if b or o:
            return (b, o)

    return (None, None)

def extract_strings(program, high_func):
    listing = program.getListing()
    strings = set()

    for op in high_func.getPcodeOps():
        for inp in op.getInputs():

            if inp.isConstant():
                try:
                    addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(inp.getOffset())
                    data = listing.getDataAt(addr)

                    if data and data.hasStringValue():
                        s = str(data.getValue())

                        if len(s) >= 4:
                            strings.add(s)

                except:
                    pass

    return list(strings)

# -----------------------------
# stride 탐지
# -----------------------------
def detect_stride(varnode):
    def_op = varnode.getDef()
    if not def_op:
        return None

    if def_op.getOpcode() == PcodeOp.INT_ADD:
        for inp in def_op.getInputs():
            sub = inp.getDef()
            if sub and sub.getOpcode() == PcodeOp.INT_MULT:
                for m in sub.getInputs():
                    if m.isConstant():
                        return m.getOffset()
    return None


# -----------------------------
# 함수 분석
# -----------------------------
def analyze_function(iface, func, monitor):
    result = iface.decompileFunction(func, 60, monitor)
    high_func = result.getHighFunction()

    if high_func is None:
        return None

    read_count = defaultdict(int)
    write_count = defaultdict(int)
    compare_map = defaultdict(set)
    stride_map = {}
    offsets = []

    for op in high_func.getPcodeOps():
        opcode = op.getOpcode()

        # LOAD / STORE
        if opcode in (PcodeOp.LOAD, PcodeOp.STORE):
            ptr = op.getInput(1)
            base, offset = trace_ptr(ptr)

            if offset is None:
                continue

            offset = int(offset)
            offsets.append(offset)

            if opcode == PcodeOp.LOAD:
                read_count[offset] += 1
            else:
                write_count[offset] += 1

            # stride 탐지
            stride = detect_stride(ptr)
            if stride:
                stride_map[offset] = int(stride)

        # 비교 연산
        if opcode in (
            PcodeOp.INT_EQUAL,
            PcodeOp.INT_NOTEQUAL,
            PcodeOp.INT_LESS,
            PcodeOp.INT_LESSEQUAL
        ):
            inputs = op.getInputs()

            const_val = None
            ptr_node = None

            for inp in inputs:
                if inp.isConstant():
                    const_val = inp.getOffset()
                else:
                    ptr_node = inp

            if const_val is not None and ptr_node is not None:
                _, offset = trace_ptr(ptr_node)
                if offset is not None:
                    compare_map[int(offset)].add(int(const_val))

    if not offsets:
        return None

    # co-occurrence
    unique_offsets = list(set(offsets))
    co_occurrence = list(itertools.combinations(unique_offsets, 2))

    # loop heuristic
    loop_map = {}
    for off in unique_offsets:
        total = read_count[off] + write_count[off]
        loop_map[off] = True if total > 3 else False

    strings = extract_strings(iface, high_func)
    
    # feature 구성
    feature = {
        "function": func.getName(),
        "features": {
            "offsets": unique_offsets,

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

            "loop": {
                str(off): loop_map[off]
                for off in unique_offsets
            },

            "stride": {
                str(off): stride_map[off]
                for off in stride_map
            },

            "co_occurrence": co_occurrence
        }
    }

    return feature


# -----------------------------
# main
# -----------------------------
def main(binary_path):
    results = []

    with pyghidra.open_program(binary_path) as api:
        program = api.getCurrentProgram()
        listing = program.getListing()
        monitor = api.getMonitor()

        iface = DecompInterface()
        iface.openProgram(program)

        for func in listing.getFunctions(True):
            res = analyze_function(iface, func, monitor)
            if res:
                results.append(res)

    print(json.dumps(results, indent=2))


# -----------------------------
# 실행
# -----------------------------
if __name__ == "__main__":
    main(str(BINARY_PATH))