import os
from dotenv import load_dotenv

load_dotenv()  # 加载.env文件




TABLE_NAME = "data"  # 已精简的表名，包含15个字段（描述+8指标）

# Chroma向量库配置（本地存储路径）
CHROMA_PATH = "./chroma_db"  # 向量库存到当前文件夹的chroma_db目录
COLLECTION_NAME = "knowledge_base"  # 集合名（自定义，如cvss_data）

# DeepSeek API配置
