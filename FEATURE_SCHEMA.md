# Feature JSON 구조 설명

이 문서는 `lua_extract_feature_ghidra`에서 생성되는 함수 단위 feature JSON이 어떤 구조를 가지는지, 그리고 각 필드가 Ghidra 내부의 어떤 분석 과정에서 추출되는지를 설명합니다.

설명 기준은 현재 저장소의 주요 추출 스크립트인 다음 두 파일입니다.

- [`extractor/11_feature_extractor_post.py`](/Users/test2000/Desktop/01_project/01_AI_Project/03_Lua_Mapper/lua_extract_feature_ghidra/extractor/11_feature_extractor_post.py)
- [`extractor/final_pyghidra_feature_extractor.py`](/Users/test2000/Desktop/01_project/01_AI_Project/03_Lua_Mapper/lua_extract_feature_ghidra/extractor/final_pyghidra_feature_extractor.py)

두 스크립트는 추출 방식이 조금 다르지만, 공통적으로 함수 단위의 구조 정보, 호출 관계, 문자열, P-code 기반 통계, 오프셋 패턴 등을 수집합니다.

## 예시 구조

대표적인 feature JSON 예시는 아래와 같습니다.

```json
{
  "function_name": "luaV_execute",
  "entry_point": "00123456",
  "basic_block_count": 42,
  "pcode_opcode_histogram": {
    "LOAD": 120,
    "STORE": 35,
    "CALL": 12
  },
  "pcode_opcode_ratio": {
    "LOAD": 0.3412,
    "STORE": 0.0994,
    "CALL": 0.0341
  },
  "pcode_instruction_count": 352,
  "callees": ["luaD_call", "luaG_runerror"],
  "callers": ["lua_pcallk"],
  "struct_offsets": [16, 24, 40],
  "read_write": {
    "16": {"read": 10, "write": 2},
    "24": {"read": 6, "write": 0}
  },
  "compare": {
    "16": [0, 1],
    "40": [5]
  },
  "co_occurrence": [[16, 24], [16, 40], [24, 40]],
  "strings": ["error", "function"],
  "numeric_constants": [0, 1, 2, 16],
  "has_loops": true,
  "data_xrefs_count": 48,
  "cyclomatic_complexity": 43,
  "lua_version": "Lua_547",
  "architecture": "x86_64"
}
```

실제 필드는 추출 스크립트 종류에 따라 조금 다를 수 있습니다. 예를 들어 `final_pyghidra_feature_extractor.py` 쪽은 `read_write`, `compare`, `co_occurrence` 같은 구조 추적 정보가 더 적극적으로 들어가고, `11_feature_extractor_post.py` 쪽은 `numeric_constants`, `has_loops`, `data_xrefs_count`, `cyclomatic_complexity` 같은 필드가 더 명확하게 포함됩니다.

## 필드별 설명

### `function_name`

- 의미
  - Ghidra가 인식한 함수 이름입니다.
- 추출 위치
  - `func.getName()`
- 해석 포인트
  - 사람이 읽기 쉬운 식별자입니다.
  - 다만 검색/학습 단계에서는 label leakage를 피하기 위해 직접 feature로 사용하지 않을 수 있습니다.

### `entry_point`

- 의미
  - 함수 시작 주소입니다.
- 추출 위치
  - `func.getEntryPoint()`
- 해석 포인트
  - 바이너리 내부에서 함수를 구분하는 식별자 역할을 합니다.

### `size_bytes`

- 의미
  - 함수 바디가 차지하는 주소 수 기반 크기입니다.
- 추출 위치
  - `body.getNumAddresses()`
- 추출 스크립트
  - 주로 `11_feature_extractor_post.py`
- 해석 포인트
  - 함수 규모를 보는 보조 지표입니다.

### `basic_block_count`

- 의미
  - 함수 내부 basic block 개수입니다.
- 추출 위치
  - `BasicBlockModel(...).getCodeBlocksContaining(...)`
- 해석 포인트
  - 제어 흐름 복잡도를 반영하는 대표적인 구조 feature입니다.
  - block 수가 많을수록 분기와 흐름이 복잡할 가능성이 높습니다.

### `has_loops`

- 의미
  - basic block 간 흐름을 보고 loop가 존재하는지 휴리스틱하게 추정한 값입니다.
- 추출 위치
  - basic block destination을 순회하면서 역방향 edge 여부 확인
- 추출 스크립트
  - `11_feature_extractor_post.py`
- 해석 포인트
  - 반복 실행 구조가 있는 함수인지 간단히 판단할 때 씁니다.

### `cyclomatic_complexity`

- 의미
  - 현재 구현에서는 `basic_block_count + 1` 형태의 근사값입니다.
- 추출 스크립트
  - `11_feature_extractor_post.py`
- 해석 포인트
  - 정확한 정식 계산이라기보다 함수 복잡도에 대한 빠른 근사 지표입니다.

### `pcode_opcode_histogram`

- 의미
  - 함수에서 생성된 P-code opcode의 raw count입니다.
- 추출 위치
  - `listing.getInstructions(...).getPcode()` 순회
- 해석 포인트
  - 함수가 LOAD/STORE/CALL/COMPARE 중심인지 같은 동작 패턴을 봅니다.
  - 함수 크기에 크게 영향받기 때문에 단독 사용보다는 ratio와 함께 보는 편이 좋습니다.

### `pcode_opcode_ratio`

- 의미
  - 전체 P-code 대비 opcode별 비율입니다.
- 추출 위치
  - histogram을 total로 나누어 계산
- 해석 포인트
  - 함수 규모 영향을 줄이고 동작 패턴 자체를 비교하기 쉽게 만든 feature입니다.
  - retrieval이나 clustering에서 상대적으로 유용합니다.

### `pcode_instruction_count`

- 의미
  - 함수에서 생성된 전체 P-code 수입니다.
- 추출 위치
  - histogram 계산 시 total count
- 해석 포인트
  - 함수 크기와 복잡도를 반영하는 기본 scalar feature입니다.

### `callees`

- 의미
  - 현재 함수가 호출하는 함수 목록입니다.
- 추출 위치
  - `CALL`, `CALLIND` P-code 또는 reference 기반 호출 분석
- 해석 포인트
  - 함수 역할을 추론할 때 매우 중요한 단서입니다.
  - 예를 들어 error 처리 함수, loader 함수, VM dispatch 함수 등은 부르는 함수 집합이 다르게 나타납니다.

### `callers`

- 의미
  - 현재 함수를 호출하는 함수 목록입니다.
- 추출 위치
  - `ReferenceManager.getReferencesTo(...)`
- 해석 포인트
  - 이 함수가 어떤 맥락에서 사용되는지 보여줍니다.
  - entry 성격인지, helper 성격인지 구분할 때 유용합니다.

### `strings`

- 의미
  - 함수 내부에서 접근하는 문자열 리터럴입니다.
- 추출 위치
  - constant 주소를 string data로 해석하거나, 함수 바디의 data를 직접 확인
- 해석 포인트
  - 의미 추론에 매우 강한 단서입니다.
  - 예외 메시지, 타입 이름, 로그 문자열 등이 함수 역할을 직접 드러낼 수 있습니다.

### `numeric_constants`

- 의미
  - 함수에서 사용되는 상수값 목록입니다.
- 추출 위치
  - P-code input 중 constant 값을 수집
- 추출 스크립트
  - `11_feature_extractor_post.py`
- 해석 포인트
  - 상태 코드, 크기 값, 루프 한계값, opcode 관련 상수 등 구조를 드러내는 힌트가 됩니다.

### `struct_offsets`

- 의미
  - 함수가 구조체 또는 메모리 레이아웃 상에서 접근하는 오프셋 후보입니다.
- 추출 위치
  - `LOAD`/`STORE` 분석 중 constant offset 수집
  - 또는 HighFunction 기반 pointer trace 결과
- 해석 포인트
  - Lua 내부 상태 구조체, VM 관련 데이터 구조 접근 패턴을 보여주는 핵심 feature입니다.
  - 단순 opcode 분포보다 더 구조적인 유사도를 제공할 수 있습니다.

### `read_write`

- 의미
  - 각 offset에 대해 read와 write가 몇 번 발생했는지 기록한 맵입니다.
- 추출 위치
  - HighFunction P-code에서 `LOAD`와 `STORE`를 분리 집계
- 추출 스크립트
  - 주로 `final_pyghidra_feature_extractor.py`
- 해석 포인트
  - 특정 필드를 읽기만 하는지, 갱신도 하는지 구분할 수 있습니다.
  - 상태 검사 함수와 상태 변경 함수의 차이를 보는 데 도움됩니다.

### `compare`

- 의미
  - 특정 offset 값이 어떤 상수와 비교되는지 기록한 맵입니다.
- 추출 위치
  - `INT_EQUAL`, `INT_NOTEQUAL`, `INT_LESS`, `INT_LESSEQUAL` 등 비교 opcode 분석
- 추출 스크립트
  - 주로 `final_pyghidra_feature_extractor.py`
- 해석 포인트
  - 상태 값 분기, opcode dispatch, 플래그 검사 같은 패턴을 잡는 데 중요합니다.

### `co_occurrence`

- 의미
  - 같은 함수 안에서 함께 등장한 offset 조합입니다.
- 추출 위치
  - 추출된 unique offset들의 조합 생성
- 추출 스크립트
  - 주로 `final_pyghidra_feature_extractor.py`
- 해석 포인트
  - 어떤 필드들이 함께 사용되는지 보는 보조 구조 feature입니다.
  - 차원이 쉽게 커질 수 있어서 후속 단계에서는 선택적으로 사용할 수 있습니다.

### `data_xrefs_count`

- 의미
  - 함수 내부 주소들에서 발생하는 reference 수 총합입니다.
- 추출 위치
  - `ReferenceManager.getReferencesFrom(...)`
- 추출 스크립트
  - `11_feature_extractor_post.py`
- 해석 포인트
  - 함수가 외부 데이터/코드와 얼마나 많이 연결되는지 보는 보조 지표입니다.

### `lua_version`

- 의미
  - 이 feature가 어떤 Lua 버전 계열에서 나왔는지 나타냅니다.
- 추출 위치
  - 바이너리 경로 또는 실행 시 환경 변수
- 해석 포인트
  - retrieval/filtering 시 같은 버전끼리 비교하거나 교차 버전 비교를 할 때 사용합니다.

### `architecture`

- 의미
  - 바이너리 아키텍처 정보입니다.
- 추출 위치
  - 바이너리 경로 또는 실행 시 환경 변수
- 해석 포인트
  - x86_64, arm64 등 아키텍처 차이로 인한 feature 변형을 구분할 때 필요합니다.

## 추출 방식 차이

### `11_feature_extractor_post.py`

이 스크립트는 Ghidra Headless post script 방식으로 동작하며, 비교적 안정적인 기본 feature 세트를 생성합니다.

강한 항목:

- basic block
- histogram / ratio
- callers / callees
- numeric constants
- strings
- has_loops
- data_xrefs_count

### `final_pyghidra_feature_extractor.py`

이 스크립트는 PyGhidra + Decompiler + HighFunction 기반으로 더 구조적인 feature를 적극적으로 추출합니다.

강한 항목:

- struct_offsets
- read_write
- compare
- co_occurrence
- pointer trace 기반 offset 해석

즉, 전자는 비교적 넓고 안정적인 feature 수집, 후자는 더 깊은 구조 분석에 가깝습니다.

## 후속 단계에서의 활용

현재 다른 저장소에서는 이 feature들을 다음과 같이 활용합니다.

- `strings`, `callees`, `callers`, `compare`
  - symbolic / semantic retrieval 단서
- `pcode_opcode_ratio`, `basic_block_count`, `pcode_instruction_count`
  - numeric similarity 계산
- `struct_offsets`, `read_write`
  - 구조 유사도 및 VM 내부 패턴 비교
- `lua_version`, `architecture`
  - metadata filtering

즉, 이 feature JSON은 단순 덤프 파일이 아니라, 이후 retrieval/embedding/LLM 실험으로 이어지는 핵심 중간 표현입니다.
