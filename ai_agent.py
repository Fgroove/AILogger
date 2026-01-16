import dashscope
from dashscope import Generation
from datetime import datetime
import json

# 导入之前的模块
import mask_sip
import mask_iam
import log_cleaner

# ================= 配置区 =================
dashscope.api_key = "sk-xxxxxxxxxxxxxxx"  # 替换为你的真实API-KEY
MODEL_NAME = "qwen-plus"  # 推荐使用 plus 模型进行深度研判


# ==========================================

class SecurityAgent:
    def __init__(self):
        self.report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate_expert_prompt(self, cleaned_logs):
        """
        构建符合世校赛标准的专业级提示词
        """
        # 将日志转换为更易读的字符串格式
        logs_str = json.dumps(cleaned_logs, ensure_ascii=False, indent=2)

        prompt = f"""
你是一名资深的校园网安全运营专家（SOC Analyst），擅长结合 ATT&CK 攻击框架进行威胁研判。
现在为你提供经过【脱敏】和【前置降噪】处理后的校园网多源异构日志（来自深信服 SIP 态势感知与 IAM 上网行为管理）。

### 待分析日志数据：
{logs_str}

### 任务要求：
请根据上述数据，生成一份结构化、专业性强的《网络安全事件研判报告》。报告必须包含以下模块：

1. **执行摘要 (Executive Summary)**：用一句话概括当前校园网面临的核心风险。
2. **风险事件研判 (Incident Analysis)**：
   - 识别出哪些是真实威胁（True Positive），哪些可能是业务误报。
   - 重点分析具有【★★★ (内网实名)】标签的事件，结合 '用户_展示' 字段进行画像。
   - 尝试识别攻击者的意图（如：内部失控设备扫描、校外暴力破解、敏感目录探测等）。
3. **技术溯源 (Technical Attribution)**：
   - 利用日志中的 '源地址_ID' 和 '用户_ID' 阐述攻击路径。
   - 映射至 ATT&CK 攻击阶段（如：侦察、漏洞利用、横向移动）。
4. **处置建议 (Remediation)**：
   - 给出立即执行的动作（如：一键封禁、断网取证）。
   - 给出长期的加固建议（如：修改口令、补丁升级）。
5. **AI 判研信心指数 (Confidence Score)**：0-100% 并给出理由。

### 注意事项：
- 报告语言应专业、客观。
- 严禁出现真实 IP 和用户名，必须使用日志中的 ID 字段。
- 报告采用 Markdown 格式输出。
"""
        return prompt

    def get_ai_report(self, prompt):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 正在调动通义千问专家模型进行深度研判...")
        response = Generation.call(
            model=MODEL_NAME,
            prompt=prompt,
            result_format='message'
        )
        if response.status_code == 200:
            return response.output.choices[0].message.content
        else:
            return f"AI 研判失败，错误码：{response.status_code}, 消息：{response.message}"

    def run_pipeline(self):
        print(">>> “智御”安全智能体（Agent）自动化流水线启动 <<<\n")

        # 1. 自动化脱敏
        mask_sip.process_sip("sip.xls")
        mask_iam.process_iam("iam.xlsx")

        # 2. 自动化降噪与关联
        cleaned_data = log_cleaner.clean_logs("sip_masked_final.xlsx", "iam_masked_final.xlsx")

        if not cleaned_data:
            print("结果：当前网络环境未发现高风险威胁。")
            return

        # 3. AI 专家研判
        prompt = self.generate_expert_prompt(cleaned_data)
        report_content = self.get_ai_report(prompt)

        # 4. 输出专业报告文件
        report_filename = f"Security_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.md"
        with open(report_filename, "w", encoding="utf-8") as f:
            f.write(f"# “智御”校园网安全态势研判报告\n")
            f.write(f"> **报告时间**：{self.report_time}  \n")
            f.write(f"> **分析引擎**：Aliyun Qwen-Plus (Security Agent Mode)  \n\n")
            f.write(report_content)

        print(f"\n[√] 自动化流程圆满完成！")
        print(f"报告已生成至：{report_filename}")
        print("-" * 50)
        print("报告预览（摘要）：")
        print(report_content[:300] + "...")


if __name__ == "__main__":
    agent = SecurityAgent()

    agent.run_pipeline()
