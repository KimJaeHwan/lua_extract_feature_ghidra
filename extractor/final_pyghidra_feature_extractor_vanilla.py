#!/usr/bin/env python3
"""
PyGhidra feature extractor for vanilla Lua binaries.

This wrapper reuses the final feature extraction logic, but keeps vanilla build
artifacts in place and writes results to a separate outputs_vanilla directory.

Why this script exists:
- final_pyghidra_feature_extractor.py is tuned for the custom Lua binary corpus.
- It also moves processed binaries into processed_binaries/, which is not ideal
  for vanilla reference binaries that we want to keep as a stable baseline.
- This vanilla wrapper reads binaries_vanilla/ and writes outputs_vanilla/ so
  the reference corpus stays separated from custom extraction results.

Default input:
  ../lua_custom_engine_generator/binaries_vanilla

Default output:
  outputs_vanilla/

Useful commands from the lua_extract_feature_ghidra project root:

  # Check target binaries without starting Ghidra.
  ../lua_llm/bin/python extractor/final_pyghidra_feature_extractor_vanilla.py --list-only

  # Extract nostrip vanilla binaries only. Recommended first run on macOS.
  ../lua_llm/bin/python extractor/final_pyghidra_feature_extractor_vanilla.py --workers 1

  # Extract both nostrip and stripped binaries.
  ../lua_llm/bin/python extractor/final_pyghidra_feature_extractor_vanilla.py --workers 1 --include-stripped

  # Re-extract even when output JSON already exists.
  ../lua_llm/bin/python extractor/final_pyghidra_feature_extractor_vanilla.py --workers 1 --force
"""

import argparse
import importlib.util
import json
import os
import shutil
import sys
import time
from datetime import datetime
from multiprocessing import Pool
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
DEFAULT_INPUT_DIR = (BASE_DIR / ".." / "lua_custom_engine_generator" / "binaries_vanilla").resolve()
DEFAULT_OUTPUT_DIR = BASE_DIR / "outputs_vanilla"
DEFAULT_PROJECT_BASE = BASE_DIR / "extractor" / "ghidra_projects_vanilla"
DEFAULT_WORKERS = 2
DEFAULT_ANALYSIS_WAIT_SECONDS = 3


def load_base_extractor():
    """Load the existing feature extractor as a module without running its main()."""
    module_path = SCRIPT_DIR / "final_pyghidra_feature_extractor.py"
    spec = importlib.util.spec_from_file_location("lua_feature_base_extractor", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load base extractor: {module_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract Ghidra features from vanilla Lua binaries."
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help="vanilla binary root, e.g. ../lua_custom_engine_generator/binaries_vanilla",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="feature JSON output root",
    )
    parser.add_argument(
        "--project-dir",
        type=Path,
        default=DEFAULT_PROJECT_BASE,
        help="temporary Ghidra project root",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="number of parallel PyGhidra workers",
    )
    parser.add_argument(
        "--analysis-wait",
        type=int,
        default=DEFAULT_ANALYSIS_WAIT_SECONDS,
        help="seconds to wait after Ghidra analysis starts",
    )
    parser.add_argument(
        "--include-stripped",
        action="store_true",
        help="also process stripped binaries; default processes nostrip only",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="re-extract even when a matching output JSON already exists",
    )
    parser.add_argument(
        "--list-only",
        action="store_true",
        help="print target binaries without running PyGhidra",
    )
    return parser.parse_args()


def collect_binaries(input_dir, include_stripped):
    """Collect vanilla Lua binaries using the same Lua/version/arch/opt layout."""
    binaries = []
    allowed_modes = {"nostrip", "stripped"} if include_stripped else {"nostrip"}

    for lua_dir in sorted(input_dir.glob("Lua_*")):
        for arch_dir in sorted(lua_dir.glob("*")):
            if not arch_dir.is_dir():
                continue
            for opt_dir in sorted(arch_dir.glob("O*")):
                if not opt_dir.is_dir():
                    continue
                for strip_dir in sorted(opt_dir.glob("*")):
                    if not strip_dir.is_dir() or strip_dir.name not in allowed_modes:
                        continue
                    for binary in sorted(strip_dir.glob("*")):
                        if binary.is_file() and not binary.name.startswith("."):
                            binaries.append(binary)

    return binaries


def ensure_pyghidra_available():
    """Fail early with a clear message if the active Python lacks PyGhidra."""
    try:
        import pyghidra  # noqa: F401
    except ModuleNotFoundError:
        print("[ERROR] pyghidra is not installed in this Python environment.")
        print("        Try from the project root:")
        print("        ../lua_llm/bin/python extractor/final_pyghidra_feature_extractor_vanilla.py --workers 1")
        sys.exit(3)


def process_binary(task):
    """Run PyGhidra for one vanilla binary and write one feature JSON file."""
    binary_path, input_dir, output_dir, project_base, analysis_wait, force = task

    try:
        import pyghidra

        pyghidra.start()
        base_extractor = load_base_extractor()

        binary = Path(binary_path)
        input_dir = Path(input_dir)
        output_dir = Path(output_dir)
        project_base = Path(project_base)

        lua_version, arch, opt_level = base_extractor.get_binary_info(binary)
        if not lua_version:
            return f"[SKIP] invalid path: {binary}"

        relative = binary.relative_to(input_dir)
        parent_dir = relative.parent
        strip_mode = parent_dir.name
        # Keep the original directory layout so later call graph tools can infer
        # Lua version, architecture, optimization level, and strip mode by path.
        target_dir = output_dir / parent_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        output_pattern = f"{arch}_{opt_level}_{strip_mode}_{binary.stem}_*.json"
        if not force and list(target_dir.glob(output_pattern)):
            return f"[SKIP] already extracted: {relative}"

        project_loc = project_base / f"{binary.stem}_{arch}_{opt_level}_{strip_mode}_{os.getpid()}"
        project_name = f"VanillaLua_{binary.stem}_{arch}_{opt_level}_{strip_mode}"

        if project_loc.exists():
            shutil.rmtree(project_loc, ignore_errors=True)

        with pyghidra.open_program(
            str(binary.absolute()),
            project_location=str(project_loc),
            project_name=project_name,
            analyze=True,
        ) as flat_api:
            current_program = flat_api.getCurrentProgram()
            if analysis_wait > 0:
                time.sleep(analysis_wait)

            results = base_extractor.extract_features_inside_program(
                current_program,
                lua_version,
                arch,
            )

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = target_dir / f"{arch}_{opt_level}_{strip_mode}_{binary.stem}_{timestamp}.json"
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

        if project_loc.exists():
            shutil.rmtree(project_loc, ignore_errors=True)

        return f"[OK] {relative} -> {len(results)} funcs"

    except Exception as exc:
        return f"[ERROR] {binary_path} - {exc}"


def main():
    args = parse_args()
    input_dir = args.input_dir.resolve()
    output_dir = args.output_dir.resolve()
    project_dir = args.project_dir.resolve()

    if not input_dir.exists():
        print(f"[ERROR] input directory does not exist: {input_dir}")
        sys.exit(2)

    binaries = collect_binaries(input_dir, args.include_stripped)

    print(f"[{datetime.now()}] Vanilla feature extraction start")
    print(f"Input : {input_dir}")
    print(f"Output: {output_dir}")
    print(f"Mode  : {'nostrip+stripped' if args.include_stripped else 'nostrip only'}")
    print(f"Total binaries: {len(binaries)}")

    if args.list_only:
        for binary in binaries:
            print(binary.relative_to(input_dir))
        print("[DONE] Listed vanilla binaries only.")
        return

    if not binaries:
        print("[DONE] No vanilla binaries found.")
        sys.exit(10)

    ensure_pyghidra_available()

    tasks = [
        (
            str(binary),
            str(input_dir),
            str(output_dir),
            str(project_dir),
            args.analysis_wait,
            args.force,
        )
        for binary in binaries
    ]

    workers = max(1, args.workers)
    ok_count = 0
    error_count = 0
    skip_count = 0

    def print_and_count(result):
        nonlocal ok_count, error_count, skip_count
        print(result)
        if result.startswith("[OK]"):
            ok_count += 1
        elif result.startswith("[ERROR]"):
            error_count += 1
        elif result.startswith("[SKIP]"):
            skip_count += 1

    if workers == 1:
        for task in tasks:
            print_and_count(process_binary(task))
    else:
        with Pool(workers) as pool:
            for result in pool.imap_unordered(process_binary, tasks):
                print_and_count(result)

    print(f"Summary: ok={ok_count}, skipped={skip_count}, errors={error_count}")
    print(f"[{datetime.now()}] Vanilla feature extraction done.")
    if error_count:
        sys.exit(1)


if __name__ == "__main__":
    import multiprocessing

    multiprocessing.set_start_method("spawn", force=True)
    main()
