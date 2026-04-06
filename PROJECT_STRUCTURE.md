# 프로젝트 디렉토리 구조

이 문서는 `lua_extract_feature_ghidra` 저장소의 전체 구조를 빠르게 파악하기 위한 참고용 문서입니다.

## 요약 트리

```text
lua_extract_feature_ghidra/
├── .gitignore
├── README.md
├── PROJECT_STRUCTURE.md
├── FEATURE_SCHEMA.md
├── LuaMapper_Agent_전체흐름도.md
├── run_watchdog.sh
├── extractor/
│   ├── 01_lua_feature_extractor.py
│   ├── 02_lua_feature_extractor_improve.py
│   ├── 03_lua_feature_extractor_improve_v2.py
│   ├── 04_lua_feature_to_jsonl.py
│   ├── 05_RAG_build.py
│   ├── 06_RAG_dataset.py
│   ├── 07_extract_feature_final.py
│   ├── 08_test.py
│   ├── 09_test_string.py
│   ├── 10_lua_feature_extractor.py
│   ├── 11_feature_extractor_post.py
│   ├── 12_batch_run_headless.py
│   ├── check_list_json.py
│   ├── final_pyghidra_feature_extractor.py
│   ├── final_pyghidra_feature_extractor_origin.py
│   └── ghidra_headless_sh_test.sh
├── binaries/
│   └── Lua_547/
│       └── x86_64/
│           └── O0/
│               └── nostrip/
│                   └── .gitkeep
├── outputs/
│   └── Lua_547/
│       └── x86_64/
│           └── O0/
│               └── nostrip/
│                   └── x86_64_O0_nostrip_lua_lua_547_0000_20260405_100336.json
├── processed_binaries/
├── quarantine/
├── lua_rag_db/
└── samples/
```

## 디렉토리 역할

- `FEATURE_SCHEMA.md`
  - 추출되는 함수 feature JSON의 구조와 각 필드의 추출 근거를 설명하는 문서입니다.
- `extractor/`
  - Ghidra / PyGhidra 기반 feature 추출 스크립트가 모여 있는 핵심 코드 디렉토리입니다.
- `binaries/`
  - 분석 대상 Lua 바이너리를 두는 위치입니다.
  - 현재 저장소에는 디렉토리 구조 설명용으로 `.gitkeep`만 유지합니다.
- `outputs/`
  - 추출 결과 JSON이 저장되는 위치입니다.
  - 저장소에는 구조와 결과 형태 예시를 보여주기 위한 x86_64 샘플 JSON 1개만 포함합니다.
- `processed_binaries/`
  - 분석 완료 후 이동된 바이너리 보관 위치입니다.
- `quarantine/`
  - 타임아웃 또는 오류로 분리된 바이너리 보관 위치입니다.

## Git 포함 원칙

저장소에는 다음만 남깁니다.

- 실행/분석 로직을 담은 스크립트
- 프로젝트 설명 문서
- 디렉토리 구조를 이해하기 위한 최소 샘플

다음은 제외합니다.

- 대량 바이너리
- Ghidra 프로젝트 캐시
- 중간 산출물
- 로컬 DB
- 이전 실험용 샘플 폴더
