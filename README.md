# 智御 (SmartGuard) - 校园网安全态势研判智能体

**“智御”** 是一款专为校园网设计的安全日志自动化分析 Agent。它能够接入深信服 SIP（态势感知）与 IAM（上网行为管理）导出的海量日志，通过高效的降噪算法与加盐脱敏技术，结合通义千问（Qwen-Plus）大模型，实现分钟级的自动化威胁研判与实名溯源。

## ✨ 核心特性

* **🔒 隐私合规（Privacy-First）**：内置加盐哈希（Salted Hash）脱敏引擎，确保在 AI 分析全流程中不涉及任何学生与教工的明文敏感信息（IP、MAC、姓名）。
* **🌪️ 高效降噪（Intelligent Noise Reduction）**：采用“三级过滤漏斗”，通过规则过滤、统计聚合与业务关联，将万量级原始日志压缩至百量级核心线索，节省 90% 以上的 AI Token 消耗。
* **🧠 深度研判（AI-Driven Insights）**：集成通义千问专家级 Prompt 模板，自动映射 ATT&CK 攻击框架，生成包含风险定性、溯源链条与处置建议的专业报告。
* **🔗 实名联动（Real-name Attribution）**：打通 SIP 威胁数据与 IAM 身份数据，实现从“虚拟 IP”到“实名用户”的精准画像，助力校园网安全闭环。

## 🛠️ 技术架构

项目遵循模块化设计，确保高内聚低耦合：

1. **`log_cleaner.py` (数据降噪)**：先执行逻辑聚合，提升 80% 以上的处理效率。
2. **`mask_sip.py / mask_iam.py` (数据脱敏)**：对聚合后的关键实体执行单向一致性哈希。
3. **`ai_agent.py` (智能体大脑)**：负责工作流调度、LLM 接口调用及 MD 报告生成。
4. **`reid_tool.py` (身份溯源)**：管理员专用，用于将 AI 识别出的异常 ID 碰撞还原。

## 🚀 快速开始

### 1. 环境准备

```bash
git clone https://github.com/YourUsername/SmartGuard.git
cd SmartGuard
pip install pandas openpyxl dashscope

```

### 2. 配置 API Key

在 `ai_agent.py` 中填入你的通义千问 API Key：

```python
dashscope.api_key = "sk-xxxxxxxxxxxx"

```

### 3. 运行自动化流水线

将 SIP 和 IAM 的导出文件放在根目录，执行：

```bash
python ai_agent.py

```

## 📊 研判报告示例

系统将自动生成名为 `Security_Report_YYYYMMDD.md` 的报告：

> **执行摘要**：识别到一起针对教务系统的内网扫描行为，风险等级：**高**。
> **溯源路径**：`用户_ID: 8FE3...` (对应实名: ***) -> 尝试 SQL 注入 -> 目标 `教务服务器_ID: D7F2...`。
> **处置建议**：防火墙一键封禁源 IP 2 小时，并进行线下安全合规谈话。

## 🛡️ 合规说明

本项严格遵守以下安全标准：

* **《中华人民共和国数据安全法》**：坚持“去标识化”原则。
* **《个人信息保护法》**：在数据离开内网域前完成隐私遮蔽。

## 👥 贡献与支持
@
该项目最初为 **2025年安徽省职业院校技能大赛（信息安全管理与评估）** 设计。欢迎通过 Issue 提交反馈或参与功能优化。
