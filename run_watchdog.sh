#!/bin/bash

# ======================
# 설정
# ======================
SCRIPT="extractor/final_pyghidra_feature_extractor.py"
MEM_LIMIT_MB=30000   # 필요하면 20000~30000 추천
CHECK_INTERVAL=5

MAIN_PID=0

# ======================
# Ctrl+C / 종료 처리
# ======================
cleanup() {
    echo ""
    echo "[CTRL+C] 종료 요청 감지 → 전체 프로세스 정리"

    if [ "$MAIN_PID" -ne 0 ]; then
        pkill -P $MAIN_PID 2>/dev/null
        kill -9 $MAIN_PID 2>/dev/null
    fi

    # ghidra 잔존 제거
    pkill -9 -f ghidra 2>/dev/null
    pkill -9 -f decompile 2>/dev/null

    echo "[EXIT] watchdog 종료"
    exit 0
}

trap cleanup SIGINT SIGTERM

# ======================
# 재귀 자식 PID 수집
# ======================
get_descendants() {
    local parent=$1
    local children=$(pgrep -P $parent)

    for child in $children; do
        echo $child
        get_descendants $child
    done
}

# ======================
# 전체 메모리 합산 (MB)
# ======================
get_total_mem() {
    local pids="$1"
    local total=0

    for pid in $pids; do
        if ps -p $pid > /dev/null 2>&1; then
            rss=$(ps -o rss= -p $pid 2>/dev/null)
            total=$((total + rss))
        fi
    done

    echo $((total / 1024))
}

# ======================
# 프로세스 트리 kill
# ======================
kill_tree() {
    local root=$1
    local all_pids="$root $(get_descendants $root)"

    echo "[KILL TREE] $all_pids"

    for pid in $all_pids; do
        kill -9 $pid 2>/dev/null
    done

    # ghidra 잔존 제거
    pkill -9 -f ghidra 2>/dev/null
    pkill -9 -f decompile 2>/dev/null
}

# ======================
# 메인 루프
# ======================
while true; do
    echo "======================================"
    echo "[START] $(date)"
    echo "======================================"

    python "$SCRIPT" &
    MAIN_PID=$!

    echo "[RUNNING] PID=$MAIN_PID"

    KILLED=0

    while kill -0 $MAIN_PID 2>/dev/null; do

        ALL_PIDS="$MAIN_PID $(get_descendants $MAIN_PID)"
        TOTAL_MB=$(get_total_mem "$ALL_PIDS")

        echo "[MONITOR] ${TOTAL_MB} MB"

        if [ "$TOTAL_MB" -gt "$MEM_LIMIT_MB" ]; then
            echo "[MEMORY EXCEEDED] ${TOTAL_MB} MB → KILL"

            kill_tree $MAIN_PID
            KILLED=1
            break
        fi

        sleep $CHECK_INTERVAL
    done

    wait $MAIN_PID
    EXIT_CODE=$?

    echo "[EXIT CODE] $EXIT_CODE"

    # ======================
    # 종료 조건
    # ======================

    # 🔥 완전 종료 (binaries 없음)
    if [ "$EXIT_CODE" -eq 10 ]; then
        echo "[DONE] No binaries left → watchdog 종료"
        break
    fi

    # 🔥 정상 완료
    if [ "$KILLED" -eq 0 ] && [ "$EXIT_CODE" -eq 0 ]; then
        echo "[DONE] 정상 완료 → watchdog 종료"
        break
    fi

    echo "[RESTART] $(date)"
    sleep 3
done

echo "[EXIT] watchdog finished"