import chromadb
from chromadb.utils import embedding_functions
from sentence_transformers import SentenceTransformer
from config import CHROMA_PATH, COLLECTION_NAME

def retrieve_similar_samples(new_desc: str, top_k: int = 5):
    # 1. 连接向量库
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    collection = client.get_collection(name=COLLECTION_NAME)

    # 2. 检索相似样本（用向量相似度计算）
    results = collection.query(
        query_texts=[new_desc],  # 新描述文本
        n_results=top_k,  # 返回Top 5相似样本
        include=["documents", "metadatas"]  # 返回描述和指标
    )

    # 3. 格式化结果
    samples = []
    for doc, meta in zip(results["documents"][0], results["metadatas"][0]):
        samples.append({
            "description": doc,
            "metrics": meta  # 包含AV/AC/PR等8个指标
        })
    return samples

if __name__ == "__main__":
    # 测试：输入一条新漏洞描述
    test_desc = "某CMS系统存在SQL注入漏洞，攻击者通过URL参数注入恶意代码，无需登录即可读取数据库用户表。"
    similar_samples = retrieve_similar_samples(test_desc, top_k=5)

    # 打印检索结果
    print("🔍 检索到的相似样本：")
    for i, sample in enumerate(similar_samples, 1):
        print(f"\n--- 样本{i} ---")
        print(f"描述：{sample['description'][:50]}...")  # 只显示前50字
        print(f"指标：{sample['metrics']}")