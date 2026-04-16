import os
import ssl
import json
import math
import mysql.connector
from mysql.connector import Error
import chromadb
from chromadb.utils import embedding_functions
from sentence_transformers import SentenceTransformer
from config import DB_CONFIG, TABLE_NAME, CHROMA_PATH, COLLECTION_NAME

def build_vector_db(limit: int = 100):
    try:
        # 1. 连接MySQL，加载样本
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        query = f"""
            SELECT 
                vul_description_textual AS description,
                cvsss3_attack_vector AS AV,
                cvsss3_attack_complexity AS AC,
                cvsss3_privilege_require AS PR,
                cvsss3_user_inactive AS UI,
                cvsss3_scope AS S,
                cvsss3_security AS C,
                cvsss3_integrality AS I,
                cvsss3_utilizability AS A
            FROM `{TABLE_NAME}`
            WHERE 
                vul_description_textual IS NOT NULL 
                AND cvsss3_attack_vector IS NOT NULL 
                AND cvsss3_attack_complexity IS NOT NULL 
                AND cvsss3_privilege_require IS NOT NULL 
                AND cvsss3_user_inactive IS NOT NULL 
                AND cvsss3_scope IS NOT NULL 
                AND cvsss3_security IS NOT NULL 
                AND cvsss3_integrality IS NOT NULL 
                AND cvsss3_utilizability IS NOT NULL 
            LIMIT {limit}
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        print(f"✅ 从MySQL加载 {len(rows)} 条样本")

        # 2. 初始化Chroma（用DefaultEmbeddingFunction避免模型下载）
        client = chromadb.PersistentClient(path=CHROMA_PATH)
        embedding_func = embedding_functions.DefaultEmbeddingFunction()  # 轻量嵌入，无需模型
        collection = client.get_or_create_collection(
            name=COLLECTION_NAME,
            embedding_function=embedding_func
        )

        # 3. 插入数据（分批插入，避免超时）
        ids = [str(i) for i in range(len(rows))]
        documents = [row["description"] for row in rows]
        metadatas = [{
            "AV": row["AV"], "AC": row["AC"], "PR": row["PR"],
            "UI": row["UI"], "S": row["S"], "C": row["C"],
            "I": row["I"], "A": row["A"]
        } for row in rows]

        batch_size = 50  # 减小批次（原1000条易超时）
        for i in range(0, len(ids), batch_size):
            collection.add(
                ids=ids[i:i+batch_size],
                documents=documents[i:i+batch_size],
                metadatas=metadatas[i:i+batch_size]
            )
            print(f"✅ 已插入 {min(i+batch_size, len(ids))}/{len(ids)} 条样本")

        print(f"✅ 向量库构建完成，存储路径：{CHROMA_PATH}")
        cursor.close()
        conn.close()
    except Error as e:
        print(f"❌ 数据库错误：{e}")
    except Exception as e:
        print(f"❌ 构建向量库失败：{e}")

if __name__ == "__main__":
    build_vector_db(limit=100)  # 先测试100条，成功后可改回10000