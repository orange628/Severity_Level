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
    return results 
if __name__ == "__main__":
    # 示例新描述
    new_description = "This is a sample vulnerability description for testing."
    
    # 获取相似样本
    similar_samples = retrieve_similar_samples(new_description)
    
    # 打印结果
    print(similar_samples)
