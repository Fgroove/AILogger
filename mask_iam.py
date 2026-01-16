import pandas as pd
import hashlib
import re

# 盐值：必须与 SIP 脱敏脚本保持完全一致，才能实现跨设备关联！
SALT = "Sec_AnHui_2024"


def get_hash(value):
    """生成唯一哈希ID，用于Agent关联分析"""
    if pd.isna(value) or value == "": return "N/A"
    # 清理空格和可能存在的括号备注
    clean_val = str(value).split('(')[0].strip().lower()
    return hashlib.sha256((clean_val + SALT).encode()).hexdigest()[:12].upper()


def mask_text_content(text):
    """
    使用正则表达式提取并替换文本中的 IP 和 MAC 地址
    """
    if pd.isna(text): return text

    # 1. 匹配并替换 IP 地址 (如 192.168.1.1)
    def replace_ip(match):
        return get_hash(match.group(0))

    text = re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', replace_ip, text)

    # 2. 匹配并替换 MAC 地址 (支持 00:00:00... 或 00-00-00... 格式)
    def replace_mac(match):
        return f"MAC_{get_hash(match.group(0))}"

    text = re.sub(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', replace_mac, text)

    return text


def process_iam(input_file):
    print(f"开始脱敏 IAM 日志: {input_file}")
    # 读取 Excel
    try:
        df = pd.read_excel(input_file)
    except Exception as e:
        print(f"读取失败，请确保文件名为 {input_file} 且格式正确。错误: {e}")
        return

    # 1. 处理显性字段：用户名、源IP、目标IP
    # 脱敏后：删除原始列，增加 _ID 列（用于关联）和 _展示 列（用于汇报）
    mapping_cols = {
        '用户名': '用户',
        '源IP': '源地址',
        '目标IP': '目的地址'
    }

    for col, label in mapping_cols.items():
        if col in df.columns:
            print(f"正在处理字段: {col}")
            df[f'{label}_ID'] = df[col].apply(get_hash)
            # 展示列：隐藏末尾，保留特征
            if 'IP' in col:
                df[f'{label}_展示'] = df[col].apply(lambda x: ".".join(str(x).split('.')[:3]) + ".*")
            else:
                df[f'{label}_展示'] = df[col].apply(lambda x: str(x)[0] + "***" if len(str(x)) > 1 else "匿名")
            df.drop(columns=[col], inplace=True)

    # 2. 深度处理“详情”字段中的 MAC 地址和嵌套 IP
    if '详情' in df.columns:
        print("正在解析详情字段中的 MAC 地址与嵌套数据...")
        df['详情'] = df['详情'].apply(mask_text_content)

    output = "iam_masked_final.xlsx"
    df.to_excel(output, index=False)
    print(f"IAM 脱敏完成！已生成：{output}")


if __name__ == "__main__":
    process_iam("iam.xlsx")