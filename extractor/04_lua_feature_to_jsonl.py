#!/usr/bin/env python3
"""
nostrip json → jsonl 변환 스크립트 (Lua VM 함수 이름 매핑 학습용)
"""

import json
import sys
import os

def convert_to_jsonl(input_json_path, output_jsonl_path, filter_lua_only=True):
    """
    nostrip json을 jsonl로 변환
    - input: function_name을 unknown으로 바꿈
    - output: 실제 function_name (target_name)
    """
    with open(input_json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    print(f"[+] 입력 파일: {input_json_path}")
    print(f"[+] 총 함수 수: {len(data)}")

    count = 0
    lua_count = 0

    with open(output_jsonl_path, 'w', encoding='utf-8') as f:
        for item in data:
            func_name = item.get("function_name", "")

            # Lua VM 함수만 필터링 (필요 시 주석 해제)
            if filter_lua_only:
                if not (func_name.startswith("lua") or func_name.startswith("l_") or "lua" in func_name.lower()):
                    continue
                lua_count += 1

            # input 문자열 생성 (필요한 feature만 선택)
            input_lines = [
                f"function_name: unknown",
                f"entry_point: {item.get('entry_point', 'unknown')}",
                f"size_bytes: {item.get('size_bytes', 0)}",
                f"basic_block_count: {item.get('basic_block_count', 0)}",
                f"has_loops: {item.get('has_loops', False)}",
                f"pcode_instruction_count: {item.get('pcode_instruction_count', 0)}",
                f"cyclomatic_complexity: {item.get('cyclomatic_complexity', 0)}",
                f"callees: {json.dumps(item.get('callees', []))}",
                f"callers: {json.dumps(item.get('callers', []))}",
                f"pcode_opcode_ratio: {json.dumps(item.get('pcode_opcode_ratio', {}))}",
                f"numeric_constants: {json.dumps(item.get('numeric_constants', []))}",
                f"struct_offsets: {json.dumps(item.get('struct_offsets', []))}",
                # 필요하면 여기서 더 추가 (data_xrefs_count 등)
            ]

            entry = {
                "input": "\n".join(input_lines),
                "output": func_name
            }

            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
            count += 1

    print(f"[+] 변환 완료: {count}개 항목")
    if filter_lua_only:
        print(f"    → Lua 관련 함수만 필터링: {lua_count}개")
    print(f"    → 저장 위치: {output_jsonl_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("사용법: python convert_to_jsonl.py <input_json> <output_jsonl>")
        print("예시: python convert_to_jsonl.py lua_arm64_nostrip_improve_v2.json lua_mapper_train.jsonl")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    if not os.path.exists(input_path):
        print(f"파일이 없습니다: {input_path}")
        sys.exit(1)

    convert_to_jsonl(input_path, output_path, filter_lua_only=True)  # Lua만 필터링하고 싶으면 True