#!/usr/bin/env python3
"""
RAG DB 구축 스크립트 - v3 (검색 품질 개선 버전)
"""

import json
import chromadb
from sentence_transformers import SentenceTransformer
from tqdm import tqdm

INPUT_JSON = "./outputs/lua_arm64_nostrip_improve_v2.json"
COLLECTION_NAME = "lua_vm_callgraph"
PERSIST_DIR = "./lua_rag_db"
LUA_VERSION = "5.4"

print("[+] RAG DB v3 구축 시작...")

embedder = SentenceTransformer('BAAI/bge-m3')

client = chromadb.PersistentClient(path=PERSIST_DIR)
try:
    client.delete_collection(COLLECTION_NAME)
except:
    pass

collection = client.create_collection(name=COLLECTION_NAME, metadata={"hnsw:space": "cosine"})

with open(INPUT_JSON, 'r', encoding='utf-8') as f:
    data = json.load(f)

documents = []
embeddings = []
metadatas = []
ids = []

for idx, func in enumerate(tqdm(data)):
    func_name = func.get("function_name", "unknown")
    if not (func_name.startswith("lua") or "lua" in func_name.lower()):
        continue

    callees_str = " ".join(func.get("callees", []))
    callers_str = " ".join(func.get("callers", []))

    # 개선된 간결한 embedding text
    text = f"Version: {LUA_VERSION}\n" \
           f"Function: {func_name}\n" \
           f"Calls: {callees_str}\n" \
           f"Called_by: {callers_str}"

    embedding = embedder.encode(text).tolist()

    metadata = {
        "function_name": func_name,
        "lua_version": LUA_VERSION,
        "callees_count": len(func.get("callees", [])),
        "callers_count": len(func.get("callers", []))
    }

    documents.append(text)
    embeddings.append(embedding)
    metadatas.append(metadata)
    ids.append(f"lua_{LUA_VERSION}_{idx}")

collection.add(
    documents=documents,
    embeddings=embeddings,
    metadatas=metadatas,
    ids=ids
)

print(f"\n[+] RAG DB v3 구축 완료!")
print(f"    → 총 {collection.count()}개 함수 저장됨")