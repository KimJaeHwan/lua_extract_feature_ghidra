#!/usr/bin/env python3
"""
RAG DB 구축 스크립트 - Lua VM call graph용 (ChromaDB)
수정 완료: embeddings 리스트 제대로 생성
"""

import json
import chromadb
from sentence_transformers import SentenceTransformer
import os
from tqdm import tqdm

# ==================== 설정 ====================
INPUT_JSON = "./outputs/lua_arm64_nostrip_improve_v2.json"   # ← 너의 nostrip json 경로
COLLECTION_NAME = "lua_vm_callgraph"
PERSIST_DIR = "./lua_rag_db"                        # DB가 저장될 폴더
# ============================================

# 1. Embedding 모델 로드 (bge-m3 추천)
print("[+] Embedding 모델 로드 중... (bge-m3)")
embedder = SentenceTransformer('BAAI/bge-m3')
print("[+] 모델 로드 완료\n")

# 2. ChromaDB Persistent Client 생성
client = chromadb.PersistentClient(path=PERSIST_DIR)

# 기존 컬렉션 삭제 후 새로 생성
try:
    client.delete_collection(COLLECTION_NAME)
    print(f"[+] 기존 컬렉션 삭제 완료: {COLLECTION_NAME}")
except:
    pass

collection = client.create_collection(
    name=COLLECTION_NAME,
    metadata={"hnsw:space": "cosine"}
)

# 3. JSON 파일 로드
with open(INPUT_JSON, 'r', encoding='utf-8') as f:
    data = json.load(f)

print(f"[+] 총 {len(data)}개 함수 로드됨\n")

# 4. 데이터 준비
documents = []
metadatas = []
ids = []
embeddings = []          # ← 여기서 embeddings 리스트를 제대로 만듦

print("[+] Embedding 생성 및 DB 삽입 시작...")

for idx, func in enumerate(tqdm(data)):
    func_name = func.get("function_name", "unknown")

    # Lua VM 관련 함수만 필터링 (lua로 시작하거나 lua 포함)
    if not (func_name.startswith("lua") or "lua" in func_name.lower()):
        continue

    # embedding할 텍스트 구성
    callees_str = ", ".join(func.get("callees", []))
    callers_str = ", ".join(func.get("callers", []))

    text = f"Function: {func_name}\nCalls: {callees_str}\nCalled_by: {callers_str}"

    # embedding 생성
    embedding = embedder.encode(text).tolist()

    # 메타데이터
    metadata = {
        "function_name": func_name,
        "entry_point": func.get("entry_point", ""),
        "size_bytes": func.get("size_bytes", 0),
        "callees_count": len(func.get("callees", [])),
        "callers_count": len(func.get("callers", []))
    }

    documents.append(text)
    embeddings.append(embedding)      # ← 리스트에 제대로 추가
    metadatas.append(metadata)
    ids.append(f"lua_func_{idx}")

# 5. ChromaDB에 한 번에 추가
if documents:
    collection.add(
        documents=documents,
        embeddings=embeddings,        # ← 이제 길이가 맞음
        metadatas=metadatas,
        ids=ids
    )
    print(f"\n[+] RAG DB 구축 완료!")
    print(f"    → 총 {collection.count()}개 함수 벡터 저장됨")
    print(f"    → 저장 경로: {PERSIST_DIR}")
else:
    print("저장할 데이터가 없습니다.")

# 위 코드 끝에 붙여서 테스트
query_text = "Function: luaD_pcall\nCalls: lua_gettop, luaD_throw, luaD_call\nCalled by: lua_pcallk, lua_cpcall"
query_embedding = embedder.encode(query_text).tolist()

results = collection.query(
    query_embeddings=[query_embedding],
    n_results=5,
    include=["documents", "metadatas", "distances"]
)

print("\n검색 결과 Top 5:")
for i, (doc, meta, dist) in enumerate(zip(results['documents'][0], results['metadatas'][0], results['distances'][0])):
    print(f"{i+1}. {meta['function_name']} (distance: {dist:.4f})")
    print(f"   → {doc[:200]}...\n")