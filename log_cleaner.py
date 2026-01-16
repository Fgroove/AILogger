import pandas as pd


def clean_logs(sip_masked_path, iam_masked_path):
    print("=== 执行高效降噪流程 ===")

    # 加载已脱敏的数据
    df_sip = pd.read_excel(sip_masked_path)
    df_iam = pd.read_excel(iam_masked_path)

    # --- 1. 静态降噪：风险评级过滤 ---
    # 仅保留 中危 和 高危
    if '日志级别' in df_sip.columns:
        df_sip = df_sip[df_sip['日志级别'].isin(['中危', '高危'])]

    # --- 2. 统计降噪：频率聚合 ---
    # 定义聚合维度：谁在什么时间对谁做了什么
    # 我们把重复的攻击行为合并，统计次数
    group_cols = ['源地址_ID', '目的地址_ID', '目的端口', '日志名称']
    if '原始日志' in df_sip.columns:
        # 尝试从原始日志提取更具体的攻击名称
        df_sip['具体威胁'] = df_sip['原始日志'].str.extract(r'evt_name="([^"]+)"')
        group_cols.append('具体威胁')

    # 执行聚合
    df_agg = df_sip.groupby(group_cols).size().reset_index(name='攻击次数')

    # --- 3. 业务降噪：身份关联加权 ---
    # 将 SIP 的攻击 IP 与 IAM 的用户身份进行关联
    # 关键：如果能关联上用户名，说明是内网实名攻击，优先级调至最高
    df_final = pd.merge(df_agg, df_iam[['源地址_ID', '用户_ID', '用户_展示']].drop_duplicates(),
                        on='源地址_ID', how='left')

    # 打分逻辑：有实名身份的攻击加星标
    df_final['优先级'] = df_final['用户_ID'].apply(lambda x: "★★★ (内网实名)" if pd.notna(x) else "★ (外部IP)")

    # --- 4. 准备发给 AI 的数据 ---
    # 按照次数和优先级排序，只选前 20 条最值得关注的
    df_final = df_final.sort_values(by=['攻击次数'], ascending=False).head(20)

    # 转化为精简的文本列表
    ai_ready_list = df_final.to_dict(orient='records')

    print(f"降噪完成！原始日志已压缩，精选出 {len(ai_ready_list)} 条高价值威胁线索。")
    return ai_ready_list


if __name__ == "__main__":
    # 独立运行测试
    sample_data = clean_logs("sip_masked_final.xlsx", "iam_masked_final.xlsx")
    for item in sample_data:
        print(item)