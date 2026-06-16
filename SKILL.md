---
name: skill-security-guard
description: "Scan agent skill packages for static security risks. Use for skill audit, security check, prompt-injection review, suspicious scripts, unsafe dependencies, zip package review, and pre-install skill review. Not for runtime monitoring."
---

# skill-security-guard

扫描 agent skill 包的静态安全风险，输出 A-F 评级、置信度、证据行和修复建议。

## 场景映射

| 用户说 | Agent 做 |
| --- | --- |
| 帮我检查这个 Skill / security check | 运行完整静态扫描并输出报告 |
| scan skill / review skill | 审计单个 Skill 文件或目录 |
| 批量检查 / 检查 zip | 安全解压后逐个扫描 `SKILL.md` |
| 这个风险已知，可忽略 | 用 `--ignore RULE_ID` 对本次扫描忽略该规则 |
| 修复 / 帮我改 | 只对可安全自动化的问题给出改法；高危项要求人工确认 |

## 执行方式

优先使用仓库内的可执行扫描器：

```bash
python scripts/scan.py <SKILL.md|skill-directory|skills.zip|url|->
python scripts/scan.py <path> --format json
python scripts/scan.py <path> --ignore R3-N5
python scripts/scan.py --text "inline skill text"
```

Shell 环境可用时也可以使用：

```bash
bash scripts/scan.sh <path>
```

## 扫描流程

1. 解析输入：本地文件、目录、zip、stdin、inline text、公开文本 URL。
2. zip 输入使用安全解压：拒绝路径穿越、过大文件和过多条目。
3. 目录和 zip 默认扫描 `SKILL.md` 与 `scripts/` 下的代码文件；`references/` 默认跳过，避免规则说明造成误报。
4. 加载内置规则执行 7 维检测：
   - Prompt injection
   - Sensitive file access / data exfiltration
   - Compliance violations
   - Malicious scripts
   - Dependency safety
   - Description trigger reasonability
   - Frontmatter compliance
5. 输出文本或 JSON 报告，包括评级、分数、规则 ID、证据行、置信度和修复建议。

## 评级

| 评级 | 含义 |
| --- | --- |
| A | 未发现风险 |
| B | 只有轻量或 advisory 级问题 |
| C | 有中风险，需要修复或人工确认 |
| D | 多个确定中风险或明显降级 |
| F | 命中直接高危规则，禁止直接安装 |

详细规则见 `references/detection-rules.md`。

## 白名单

本项目不持久化白名单。对已人工确认的风险，可在本次运行中使用：

```bash
python scripts/scan.py <path> --ignore RULE_ID
```

所有忽略项都应在人工 review 记录中说明原因。

## 自动修复边界

扫描器会标记可安全自动化的修复建议，例如移除非标准 frontmatter 字段或收窄过宽 description。它不会自动重写文件；真正修改前需要人工确认。

不自动修复：

- 高危 exfiltration、tunneling、destructive command、remote script execution
- 意图不明确的 prompt-injection 文案
- 需要业务上下文判断的合规问题

## Hard Stop

同一输入或同一工具调用连续失败超过 3 次时，停止重试并列出失败原因。常见原因包括 zip 损坏、URL 不可达、文件编码异常或路径权限问题。

## Changelog

### 5.1.0

- 新增 `scripts/scan.py`：跨平台、标准库实现的静态扫描器
- `scripts/scan.sh` 改为 Python wrapper
- 新增 zip 安全解压、目录批量扫描、stdin/inline text、JSON 输出、`--ignore`
- 新增 unittest 测试 fixtures 和 GitHub Actions CI
- 修正 frontmatter，只保留 `name` 和 `description`

### 5.0.0

- 新建 `scripts/scan.sh` 作为输入预解析脚本
- 补充 7 维检测文档和规则引用
