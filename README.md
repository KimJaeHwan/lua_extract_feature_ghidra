# Lua Feature Extractor with Ghidra

`lua_extract_feature_ghidra`는 커스텀 Lua 바이너리로부터 함수 단위 정적 feature를 추출하기 위한 Ghidra 기반 연구용 파이프라인입니다.

이 프로젝트는 앞 단계에서 생성된 다양한 Lua 엔진 바이너리를 입력으로 받아, Ghidra 및 PyGhidra를 이용해 함수 구조, 호출 관계, 상수, 문자열, P-code 통계 등의 정보를 추출하고, 이를 후속 분석에 활용할 수 있는 형태로 정리하는 것을 목표로 합니다. 전체적으로는 더 큰 LLM 기반 연구 흐름으로 이어지는 중간 단계의 feature 수집 시스템이라고 볼 수 있습니다. 현재 실험 및 추출 환경은 `Ghidra 12.0.4` 버전을 기준으로 구성되었습니다.

## 이 프로젝트가 하는 일

이 프로젝트는 다음 작업을 수행합니다.

- Lua 바이너리를 입력으로 수집
- Ghidra Headless 또는 PyGhidra 기반 분석 실행
- 함수 단위 feature 추출
- JSON 및 JSONL 형태로 결과 저장
- 대량 분석 중 메모리 초과나 비정상 종료를 감시하고 재시작
- 처리 완료 바이너리, 실패 바이너리, 중간 산출물을 분리 관리

즉, 단순 스크립트 모음이 아니라, 대량의 Lua 바이너리를 안정적으로 분석하기 위한 추출 파이프라인입니다.

## 왜 필요한가

동일한 계열의 바이너리라도 내부 구현, 최적화 옵션, 삽입된 코드 조합에 따라 함수 수준 특징이 달라질 수 있습니다. 이 프로젝트는 그런 차이를 정적 분석 기반 feature로 정리해, 바이너리 간의 구조적 유사성과 차이를 다룰 수 있는 형태로 바꾸는 데 목적이 있습니다.

이 프로젝트는 다음과 같은 상황에 유용합니다.

- 대량 바이너리의 함수 단위 특징 수집
- 정적 분석 기반 데이터셋 구축
- Lua VM 관련 함수 패턴 비교
- 후속 모델링 실험을 위한 기초 feature 축적

## 핵심 아이디어

이 프로젝트의 핵심은 Ghidra 기반의 하이브리드 feature 추출입니다.

스크립트들은 단순 문자열 추출만 하는 것이 아니라, Ghidra가 제공하는 Listing, Reference, Basic Block, P-code, Decompiler 정보를 조합해 함수별 feature를 구성합니다. 현재 코드상에서 다루는 feature 예시는 다음과 같습니다.

- 함수 이름 및 엔트리 포인트
- basic block 개수
- loop 존재 여부 추정
- P-code opcode histogram 및 비율
- 함수 간 caller / callee 관계
- numeric constants
- struct offsets
- strings
- data xref 개수
- cyclomatic complexity 근사값

즉, “한 번 디컴파일해서 결과를 덤프한다”가 아니라, 함수 의미와 구조를 동시에 반영하는 feature 세트를 만들려는 방향이 보입니다.

## 폴더 구조

전체 디렉토리 구조와 각 폴더의 역할은 [`PROJECT_STRUCTURE.md`](/Users/test2000/Desktop/01_project/01_AI_Project/03_Lua_Mapper/lua_extract_feature_ghidra/PROJECT_STRUCTURE.md)에서 따로 볼 수 있습니다.

```text
lua_extract_feature_ghidra/
├── run_watchdog.sh
├── extractor/
│   ├── 01_lua_feature_extractor.py
│   ├── ...
│   ├── 11_feature_extractor_post.py
│   ├── 12_batch_run_headless.py
│   ├── final_pyghidra_feature_extractor.py
│   └── ghidra_headless_sh_test.sh
├── binaries/
├── outputs/
├── outputs_lua_feature_jsonl/
├── processed_binaries/
├── quarantine/
├── lua_rag_db/
└── samples/
```

### 주요 디렉토리 설명

- `extractor/`: Ghidra 기반 feature 추출 및 후처리 스크립트 모음
- `binaries/`: 분석 대상 Lua 바이너리 입력 위치
- `outputs/`: 추출된 feature JSON 결과 저장 위치
- `outputs_lua_feature_jsonl/`: 후처리된 JSONL 결과 저장 위치
- `processed_binaries/`: 분석이 끝난 바이너리 이동 위치
- `quarantine/`: 타임아웃 또는 예외로 분리한 바이너리 저장 위치
- `lua_rag_db/`: 로컬 실험용 벡터 DB 및 관련 산출물
- `samples/`: 과거 실험용 샘플 입력 보관 위치

이 중 대부분의 `outputs`, `ghidra_projects`, `lua_rag_db`, `processed_binaries`, `quarantine`, `samples` 등은 실행 중 생성되거나 과거 실험에서 사용된 산출물이므로 일반적으로 Git에 포함하지 않습니다. 현재 저장소에는 구조 설명용으로 `outputs`의 x86_64 샘플 JSON 1개만 남기고, `binaries`는 `.gitkeep`으로 디렉토리 구조만 유지합니다.

## 주요 스크립트

- [`run_watchdog.sh`](/Users/test2000/Desktop/01_project/01_AI_Project/03_Lua_Mapper/lua_extract_feature_ghidra/run_watchdog.sh): 메모리 사용량을 감시하면서 메인 추출 스크립트를 재시작하는 watchdog
- [`final_pyghidra_feature_extractor.py`](/Users/test2000/Desktop/01_project/01_AI_Project/03_Lua_Mapper/lua_extract_feature_ghidra/extractor/final_pyghidra_feature_extractor.py): PyGhidra 기반 최종 feature 추출기
- [`11_feature_extractor_post.py`](/Users/test2000/Desktop/01_project/01_AI_Project/03_Lua_Mapper/lua_extract_feature_ghidra/extractor/11_feature_extractor_post.py): Ghidra Headless post script 형태의 feature 추출기
- [`12_batch_run_headless.py`](/Users/test2000/Desktop/01_project/01_AI_Project/03_Lua_Mapper/lua_extract_feature_ghidra/extractor/12_batch_run_headless.py): analyzeHeadless 기반 배치 실행기
- [`06_RAG_dataset.py`](/Users/test2000/Desktop/01_project/01_AI_Project/03_Lua_Mapper/lua_extract_feature_ghidra/extractor/06_RAG_dataset.py): 추출 결과를 기반으로 실험용 DB를 구성하는 스크립트

파일 번호가 붙은 여러 스크립트들은 실험과 개선 과정을 반영하는 버전 히스토리 성격도 함께 가지고 있습니다.

## 작업 흐름

현재 이 폴더의 전반적인 흐름은 다음과 같습니다.

1. `binaries/` 아래에 분석 대상 Lua 바이너리 배치
2. Ghidra Headless 또는 PyGhidra 기반 추출 스크립트 실행
3. 함수별 feature를 JSON 형태로 저장
4. 필요 시 JSONL 등 후처리 포맷으로 변환
5. 대량 실행 시 watchdog으로 메모리 사용량을 감시하며 안정성 확보

즉, 분석 정확도뿐 아니라 대량 실행의 운영 안정성까지 고려한 구성이 들어가 있습니다.

## 실행 환경

이 프로젝트는 다음과 같은 환경을 전제로 합니다.

- Ghidra 12.0.4 설치
- PyGhidra 사용 가능 환경
- Python 실행 환경
- 분석 대상 Lua 바이너리 준비

스크립트 일부는 현재 작업 디렉토리를 기준으로 경로를 계산하므로, 프로젝트 루트에서 실행하는 방식이 가장 자연스럽습니다.

버전 차이에 따라 Headless 실행 방식이나 PyGhidra 동작, 일부 API 사용 방식이 달라질 수 있으므로, 가능하면 `Ghidra 12.0.4` 기준으로 환경을 맞추는 것을 권장합니다.

## 빠른 시작 예시

### 1. 바이너리 준비

분석할 Lua 바이너리를 `binaries/` 아래 구조에 맞게 배치합니다.

### 2. PyGhidra 기반 추출 실행

```bash
python extractor/final_pyghidra_feature_extractor.py
```

### 3. watchdog 기반 장시간 실행

```bash
bash run_watchdog.sh
```

### 4. Headless 배치 실행

```bash
python extractor/12_batch_run_headless.py
```

## 현재 프로젝트 범위

현재 이 저장소는 다음 범위에 집중하고 있습니다.

- Lua 바이너리 대상 정적 feature 추출
- Ghidra / PyGhidra 기반 자동화
- 대량 실행을 위한 watchdog 및 배치 처리
- 결과 JSON 및 후처리용 데이터 정리

즉, 완성형 제품보다는 연구와 실험을 위한 분석 자동화 도구에 가깝습니다.

## Git 관리 방침

이 저장소에서는 다음 항목들을 Git에서 제외합니다.

- Ghidra 프로젝트 캐시
- 분석 결과 JSON / JSONL
- 중간 처리 디렉토리
- 로컬 실험용 DB
- 대용량 바이너리 및 압축 파일
- 과거 실험용 `samples/` 폴더

반대로, 추출 로직을 담은 스크립트와 실행 흐름을 설명하는 문서, 그리고 구조 설명용 최소 샘플은 저장소에 포함합니다.

## 참고

이 프로젝트는 앞 단계에서 생성된 Lua 엔진 변형들과 자연스럽게 연결되며, 전체적으로는 바이너리 수준 정보를 구조화된 feature로 바꾸는 중간 분석 단계 역할을 합니다.
