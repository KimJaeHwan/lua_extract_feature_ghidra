#!/usr/bin/env python3
"""
JSON 품질 검사 스크립트 - 개선 버전
- 평균이 아닌, '의미 있는 feature를 가진 함수 비율'로 판단
"""

import json
from pathlib import Path

def check_json_quality():
    base_dir = Path.cwd() / "outputs"
    if not base_dir.exists():
        print("outputs 폴더가 없습니다.")
        return

    total_files = 0
    total_functions = 0
    good_functions = 0
    bad_functions = 0

    print("JSON 품질 검사 시작 (개선 버전)...\n")

    for json_file in base_dir.rglob("*.json"):
        total_files += 1
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, list):
                continue

            for func in data:
                total_functions += 1

                strings_count = len(func.get("strings", []))
                offsets_count = len(func.get("struct_offsets", []))
                pcode_count = len(func.get("pcode_opcode_histogram", {}))
                callees_count = len(func.get("callees", []))

                # 의미 있는 함수 기준 (하나라도 충족하면 Good)
                if (strings_count >= 2 or 
                    offsets_count >= 5 or 
                    pcode_count >= 12 or 
                    callees_count >= 3):
                    good_functions += 1
                else:
                    bad_functions += 1

        except Exception:
            continue

    if total_functions == 0:
        print("검사할 함수가 없습니다.")
        return

    good_ratio = good_functions / total_functions * 100

    print("="*80)
    print("JSON 품질 검사 결과 (개선 기준)")
    print("="*80)
    print(f"총 JSON 파일 수     : {total_files}")
    print(f"총 함수 수          : {total_functions}")
    print(f"의미 있는 함수 수   : {good_functions} ({good_ratio:.1f}%)")
    print(f"저품질 함수 수      : {bad_functions} ({100-good_ratio:.1f}%)")
    print("="*80)

    if good_ratio >= 65:
        print("→ **양호합니다.** LoRA 학습에 사용할 수 있는 수준입니다.")
    elif good_ratio >= 45:
        print("→ 중간 수준입니다. struct_offsets와 strings를 조금 더 강화하면 좋습니다.")
    else:
        print("→ **저품질입니다.** 분석이 충분하지 않습니다. 분석을 더 강하게 해야 합니다.")

if __name__ == "__main__":
    check_json_quality()