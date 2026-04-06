LuaMapper Agent 전체 흐름도 (Final Architecture)
text[입력] Strip된 타겟 바이너리
       ↓
[Step 0] Ghidra Feature Extraction
       ↓
[전체 함수 리스트] (이름 없음 + feature 포함)
       ↓
       ┌──────────────────────────────┐
       │         Agent Main Loop      │
       └──────────────────────────────┘
                    ↓
       [Step 1] LoRA 1차 예측 (Batch 처리)
                    ↓
       모든 unnamed 함수에 대해 LoRA가 예측
       → {entry_point: "0014754c", 
          candidates: ["luaD_pcall(0.87)", "luaD_call(0.65)", ...],
          confidence: 0.87}
                    ↓
       [Step 2] High Confidence 함수 확정 (Threshold 적용)
                    ↓
       Confidence ≥ 0.85 → 함수 이름 확정 + Call Graph DB에 기록
                    ↓
       [Step 3] Propagation (Call Graph 확장)
                    ↓
       ┌─────────────────────────────────────────────────────┐
       │  현재 확정된 함수의 callees와 callers를 Call Graph DB에서 조회   │
       │  → 다음으로 분석할 후보 함수 리스트 생성 (depth +1)            │
       └─────────────────────────────────────────────────────┘
                    ↓
       [Step 4] Inlining Detection & Depth 조정
                    ↓
       if (함수 크기가 작고 callees가 적고 pcode가 복잡하면)
           → "인라인 의심" 플래그 ON + depth +1 강제 확장
                    ↓
       [Step 5] LLM Reasoning (가장 중요한 단계)
                    ↓
       LLM에게 아래 정보를 모두 주고 추론 요청:
       - LoRA 1차 예측 결과
       - Call Graph DB에서 가져온 callees / callers
       - (선택) Ghidra decompiled 코드 일부
       - 지금까지 확정된 주변 함수 정보

       LLM 출력 형식 (강제):
       {
         "final_name": "luaD_pcall",
         "confidence": 0.93,
         "reasoning": "LoRA 예측이 0.87이었고, callees에 luaD_throw와 luaD_call이 있으며 callers에 lua_pcallk가 존재하므로...",
         "next_priority": ["luaD_protectedparser", "luaD_rawrunprotected"]
       }
                    ↓
       [Step 6] 최종 판단 및 기록
                    ↓
       Confidence ≥ Threshold → 함수 이름 확정 + Call Graph DB 업데이트
       ↓
       아직 미확정 함수가 있고, propagation queue가 비어있지 않으면 → Step 3으로 돌아감
                    ↓
[종료] 모든 함수 이름 매핑 완료 + 보고서 생성

Agent 흐름도 주요 특징

LoRA는 빠른 1차 예측 역할
Call Graph DB는 정확한 그래프 탐색 역할
LLM Reasoning은 가장 중요한 판단 단계 (단순 매칭이 아닌 추론)
Inlining Detection은 별도 모듈로 처리
Propagation은 depth를 동적으로 조정 (최대 5)
Threshold는 나중에 튜닝 가능 (초기값 0.85 추천)