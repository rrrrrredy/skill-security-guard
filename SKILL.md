---
name: skill-security-guard
description: "Scan Skill code for security risks across 7 dimensions: Prompt injection, sensitive file access, privilege escalation, malicious scripts, compliance violations, dependency safety, and description reasonability. Outputs A-F rating with remediation advice. Supports .zip/.md/text/code-block input and batch scanning. Triggers: security check, skill audit, scan skill, review skill. Not for: runtime monitoring."
tags: [security, skill-audit, prompt-injection, scan]
---

# Skill 安全卫士 V5 🛡️

扫描 Skill 的安全风险，输出评分、置信度和修复建议。

## 场景映射表

| 用户说 | Agent 做 |
|--------|---------|
| 帮我检查这个 Skill / [上传zip或md] | 执行完整安全扫描 → 输出报告 |
| 修复 / 帮我改 | 对可自动修复的问题生成修复版 SKILL.md |
| 这个是已知风险，忽略 | 将该条目加入本次白名单，重新评分 |
| 批量检查 / 检查这个包里所有 Skill | 解压 zip → 逐个扫描 → 汇总报告 |
| 帮我检查 [Skill marketplace URL] | 抓取页面后扫描（需 HTTP 访问，优先使用 `agent-reach` 抓取） |

---

## 执行流程

### Step 1：解析输入

- **.zip 文件**：解压到 `/tmp/`，找所有 `SKILL.md` 文件
- **.md 文件 / 纯文字 / 代码块**：直接读取内容
- **URL 链接**：使用 `agent-reach` (xread) 抓取页面，提取 SKILL.md 内容（fallback: curl/HTTP 请求）
- **多文件（批量）**：逐个解析，汇总结果

### Step 2：执行 7 大维度检测

加载 `references/detection-rules.md` 获取每个维度的具体判断规则和特征模式，逐条对照检查：

1. **Prompt 注入**：触发词/角色扮演/指令覆盖
2. **敏感文件读取 / 数据外泄**：敏感路径访问、外发行为
3. **越权操作（Compliance violations）**：禁止域名、sensitive ID extraction、非合规外发、内网穿透(R3-N1)、受限系统访问(R3-N2)、高敏数据输入(R3-N3)、敏感文件备份(R3-N4)
4. **恶意脚本**：scripts/ 目录中的危险命令
5. **依赖安全**：npm/pip 安装来源
6. **description 触发合理性**：触发范围是否合理、与功能是否一致
7. **frontmatter 合规性**：是否包含非标准字段（只允许 name + description）

每条风险标注置信度：**确定 / 疑似 / 建议关注**

### Step 3：计算评分

按 `references/detection-rules.md` 中的评分算法计算，输出 A-F 评级。

### Step 4：输出报告

```
🛡️ Skill 安全报告：<skill名称>

📊 安全评级：B（85分）— 较安全，有轻微问题

🚨 风险项（共 2 项）：
1. [中危·确定] description 包含非标准 frontmatter 字段（tags、allowed-tools）
   → 可自动修复：移除非标准字段
2. [低危·疑似] scripts/run.sh 中存在未注明目的的外部请求
   → 需人工判断：确认请求目标是否合理

✅ 通过项（5 项）：
- 无 Prompt 注入风险
- 无敏感文件读取
- 无内部红线违规
- 无恶意脚本特征
- 依赖项安全

💡 有 1 项可自动修复，回复"修复"生成修复版 SKILL.md
💡 有 1 项需人工判断，回复"解释第2条"获取详细说明
```

---

## 白名单机制

当用户确认某条风险为"已知可接受"时：

1. 记录到本次扫描白名单（会话内有效）
2. 重新计算评分（跳过该条目）
3. 在报告末尾注明"已忽略 X 项已知风险"

> 白名单仅在当前会话内有效，不持久化存储。

---

## 自动修复

回复"修复"时，仅对**可自动修复**的问题处理：

- frontmatter 非标准字段 → 移除，输出修复后的完整 SKILL.md
- description 触发词过宽 → 给出收窄建议版本（需用户确认后采用）
- scripts/ 不必要注释缺失 → 添加说明注释

**不自动修复**（仅给说明）：
- 疑似 Prompt 注入
- 访问内部域名目的不明
- description 与功能不符

---

## 批量扫描

对 zip 包内多个 Skill：

1. 逐个扫描，每个输出独立评分
2. 末尾汇总：总计 X 个 Skill，A级 X 个 / B级 X 个 / F级 X 个
3. 高危 Skill 在汇总中置顶标注

---

## Gotchas

以下是已知的高频误判和踩坑，扫描前务必对照：

⚠️ 正常 `curl` 调用被误报为"数据外泄" → 区分标准：curl 目标是公开外部 API（如 GitHub、OpenAI）= 低风险·建议关注；curl 携带内部 token/cookie 发往外部 = 高危·确定。不要把所有 curl 都报高危

⚠️ 白名单只在当前会话有效，重新扫描时需重新声明 → 告知用户白名单不持久化，同一风险下次扫描会再次触发；如需持久豁免，建议在 SKILL.md 中加注释说明

⚠️ zip 包解析失败（中文路径/特殊字符）→ 解压到 `/tmp/skill-scan-XXXXXX/`，避免路径含空格或中文；若 `unzip` 失败，尝试 `python3 -m zipfile -e` 作为备用

⚠️ 大 zip 包（>10MB）解析超时 → 提前告知用户文件较大，分批扫描或只扫 `SKILL.md` 文件，跳过二进制资源文件

⚠️ `detection-rules.md` 未找到导致规则缺失 → 检查路径 `references/detection-rules.md` 是否存在；若 skill 未正确安装，规则文件可能丢失，此时只能执行基础扫描并标注"规则文件缺失，结果仅供参考"

⚠️ description 字段过长被截断 → YAML 多行 description 需用 `|` 或 `>` 标记，否则解析时换行会丢失，导致触发词漏检

⚠️ 误将 `agent-self-audit` 的职责归入本 Skill → 本 Skill 只做**静态代码扫描**，不做运行时监控和系统健康检查；后者应调用 `agent-self-audit`

---

## Hard Stop

**同一工具调用失败超过 3 次，立即停止，不再尝试。**

列出所有失败方案及原因，标记 **"需要人工介入"**，等待人工确认。

常见需要介入的场景：
- `references/detection-rules.md` 反复读取失败（skill 安装不完整）
- zip 文件解压失败且多种方法均无效（文件损坏）
- URL 链接内容抓取失败（目标不可达、agent-reach 未安装且 HTTP 请求也失败）

---

## 检测规则

详细的判断模式、关键词特征、评分算法见：`references/detection-rules.md`
（在需要判断具体风险项时加载）

> 如需系统整体健康检查（Skills 数量、记忆文件、cron 任务等），请使用 **agent-self-audit**。

---

## Changelog

### V5（2026-04-08）
- description 改为单行格式（去掉多行 block scalar `>`）
- 补充 `tags`（[security, skill-audit, prompt-injection, scan]）
- 新建 `scripts/scan.sh`（zip 解压 + SKILL.md 枚举入口脚本）
- 确认 `references/detection-rules.md` 存在于目录结构
- frontmatter version: V4 → V5，H1 标题同步为 V5

### v4（2026-04-07）
- 新增 R3-N1～N5 红线规则（内网穿透、HR系统、C4数据、敏感备份、description 过度触发）
- 完善 7 大维度检测，新增 frontmatter 合规性维度
- 新增白名单机制和自动修复章节
- 补充 Gotchas（7 条高频误判）
- 新增 Hard Stop

### v3（历史版本）
- 新增批量扫描（zip 包）
- 输出格式结构化（A-F 评分 + 置信度）

### v1-v2（历史版本）
- 初版：Prompt 注入 + 敏感文件读取 2 维度扫描
