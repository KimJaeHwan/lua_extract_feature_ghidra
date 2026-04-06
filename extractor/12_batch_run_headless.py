#!/usr/bin/env python3
"""
analyzeHeadless Batch Runner - shell=True 버전 (인자 문제 완전 해결)
"""

import subprocess
import os
from pathlib import Path
from datetime import datetime

# ====================== 설정 ======================
BASE_DIR = Path.cwd().absolute()
BINARIES_DIR = BASE_DIR / "binaries"
OUTPUT_BASE = BASE_DIR / "outputs"
PROJECT_BASE = BASE_DIR / "extractor" / "ghidra_projects"
POST_SCRIPT = BASE_DIR / "extractor" / "feature_extractor_post.py"

def get_binary_info(binary_path: Path):
    try:
        parts = binary_path.parts
        lua_version = next(p for p in parts if p.startswith("Lua_"))
        arch_dir = next(p for p in parts if p in ("arm64", "aarch64", "x86_64"))
        arch = "arm64" if arch_dir in ("arm64", "aarch64") else "x86_64"
        opt_level = next((p for p in parts if p.startswith("O")), "O0")
        return lua_version, arch, opt_level
    except:
        return None, None, None


def run_one(binary_path: Path):
    lua_version, arch, opt_level = get_binary_info(binary_path)
    if not lua_version:
        print(f"[SKIP] {binary_path.name}")
        return

    project_location = PROJECT_BASE / lua_version / arch / opt_level / "nostrip"
    project_name = f"LuaAnalyzer_{lua_version}_{arch}_{opt_level}_{binary_path.stem}"

    # shell=True로 문자열 명령어 전달 (인자 파싱 문제 해결)
    cmd = f'''analyzeHeadless \
"{project_location}" \
"{project_name}" \
-import "{binary_path}" \
-analysis on \
-postScript "{POST_SCRIPT}" \
-deleteProject'''

    env = os.environ.copy()
    env["FEATURE_OUTPUT_BASE"] = str(OUTPUT_BASE)
    env["LUA_VERSION"] = lua_version
    env["ARCH"] = arch

    print(f"[{datetime.now()}] Running: {binary_path.name} ({lua_version} | {arch})")

    try:
        result = subprocess.run(
            cmd,
            shell=True,           # ← 여기서 shell=True 사용
            env=env,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode == 0:
            print(f"[SUCCESS] {binary_path.name}")
        else:
            print(f"[FAILED] {binary_path.name} (code {result.returncode})")
            if result.stderr:
                print("--- Error Output ---")
                print(result.stderr.strip()[-800:])

    except subprocess.TimeoutExpired:
        print(f"[TIMEOUT] {binary_path.name}")
    except Exception as e:
        print(f"[ERROR] {binary_path.name} - {e}")


def main():
    print(f"[{datetime.now()}] Starting analyzeHeadless batch...")
    print(f"Project Base : {PROJECT_BASE}")
    print(f"Post Script  : {POST_SCRIPT}")
    print("=" * 100)

    count = 0
    for lua_dir in sorted(BINARIES_DIR.glob("Lua_*")):
        for arch_dir in sorted(lua_dir.glob("*")):
            for opt_dir in sorted(arch_dir.glob("O*")):
                nostrip_dir = opt_dir / "nostrip"
                if not nostrip_dir.exists():
                    continue
                for binary in sorted(nostrip_dir.glob("*")):
                    if binary.is_file() and not binary.name.startswith('.'):
                        count += 1
                        run_one(binary)

                        if count % 5 == 0:
                            print(f"--- Progress: {count} processed ---")

    print(f"\n[{datetime.now()}] Batch finished. Total processed: {count}")

if __name__ == "__main__":
    main()