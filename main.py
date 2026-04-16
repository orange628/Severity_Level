import requests
import json
import math
from config import DEEPSEEK_API_KEY, API_URL, MODEL_NAME, CHROMA_PATH, COLLECTION_NAME
from retrieve_samples import retrieve_similar_samples  # 导入第4步的检索函数

# ---------------------- 大模型提取指标（用检索到的样本） ----------------------
def extract_metrics(new_desc: str) -> dict:
    # 1. 检索相似样本（Top 5）
    similar_samples = retrieve_similar_samples(new_desc, top_k=5)

    # 2. 构造Prompt（给大模型看相似样本+规则）
    prompt = f"""
你是网络安全专家，需从漏洞描述中提取CVSS 3.1的8个指标（AV/AC/PR/UI/S/C/I/A）。  
### 规则：远程→AV:N，低复杂度→AC:L，无权限→PR:N，无交互→UI:N，影响不变→S:U，高机密性→C:H，高完整性→I:H，高可用性→A:H。  
### 相似案例（参考提取逻辑）：{json.dumps(similar_samples, ensure_ascii=False)}  
### 新描述：{new_desc}，返回JSON格式（键名：AV/AC/PR/UI/S/C/I/A）。
    """

    # 3. 调用DeepSeek API
    headers = {
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": MODEL_NAME,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,  # 低温度=更稳定
        "response_format": {"type": "json_object"}
    }
    try:
        response = requests.post(API_URL, headers=headers, json=payload, timeout=30)
        result = response.json()["choices"][0]["message"]["content"]
        return json.loads(result)  # 返回提取的8个指标
    except Exception as e:
        print(f"❌ 提取指标失败：{e}")
        return {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "N"}  # 默认值

# ---------------------- CVSS 3.1分数计算（官方公式） ----------------------
def calculate_cvss(metrics: dict) -> tuple:
    # 指标映射表（CVSS 3.1官方）
    av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_map = {"L": 0.77, "H": 0.44}
    pr_map = {"N": 0.85, "L": 0.62, "H": 0.27}
    ui_map = {"N": 0.85, "R": 0.62}
    impact_map = {"H": 0.56, "L": 0.22, "N": 0.0}
    const = {"iss": 6.42, "ess": 8.22, "scope_factor": 3.25}

    # 提取指标（转大写，避免大小写问题）
    av, ac, pr, ui, s = metrics["AV"].upper(), metrics["AC"].upper(), metrics["PR"].upper(), metrics["UI"].upper(), metrics["S"].upper()
    c, i, a = metrics["C"].upper(), metrics["I"].upper(), metrics["A"].upper()

    # 计算影响子分数（ISS）
    impact = 1 - (1-impact_map[c])*(1-impact_map[i])*(1-impact_map[a])
    iss = const["iss"] * impact if s == "U" else 7.52*(impact-0.029) - const["scope_factor"]*((impact-0.02)**15)

    # 计算可利用性子分数（ESS）
    ess = const["ess"] * av_map[av] * ac_map[ac] * pr_map[pr] * ui_map[ui]

    # 基础分数（范围变更时×1.08）
    base_score = min(iss + ess, 10) if s == "U" else min(1.08*(iss+ess), 10)
    base_score = round(base_score, 1)  # 保留1位小数

    # 危害等级
    severity = "Critical" if base_score >=9 else "High" if base_score>=7 else "Medium" if base_score>=4 else "Low"

    # CVSS向量
    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    return base_score, severity, vector

# ---------------------- 主函数（输入描述→输出结果） ----------------------
def main(new_desc: str):
    print(f"输入描述：{new_desc}")
    metrics = extract_metrics(new_desc)  # Step1：提取指标
    score, severity, vector = calculate_cvss(metrics)  # Step2：计算分数
    print(f"📤 输出结果：\n评分={score}，等级={severity}，向量={vector}\n指标={metrics}")
    return {"score": score, "severity": severity, "vector": vector, "metrics": metrics}

if __name__ == "__main__":
    # 测试：输入一条新漏洞描述
    test_desc = "某OA系统文件上传漏洞，攻击者构造恶意文件无需权限上传webshell，控制服务器。"
    main(test_desc)