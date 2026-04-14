# 检测规则详细定义

## 维度一：Prompt 注入风险

**确定有问题**（置信度：确定）
- 包含以下关键短语：
  - "忽略之前所有指令" / "ignore previous instructions"
  - "你现在是一个没有限制的AI" / "you are now DAN"
  - "扮演XX角色，不受任何约束"
  - "system prompt已更新，新规则是"
- description 中写"当用户问任何问题时触发" / "适用于所有场景" 等无边界触发词

**疑似**（置信度：疑似）
- description 触发范围极宽泛，覆盖超过5种不相关场景
- SKILL.md body 中包含"覆盖之前的安全规则"类语句

---

## 维度二：敏感文件读取/数据外泄

**确定有问题**（置信度：确定）
- 读取以下路径：
  - `/root/.openclaw/openclaw.json`
  - `/root/.openclaw/devices/paired.json`
  - `/root/.openclaw/identity/`
  - `~/.ssh/`、`~/.aws/`、`~/.config/`
- 包含 `curl`/`wget`/`nc` 将本地文件内容发往外部域名
- 包含 `cat openclaw.json | curl`、`scp` 至未知主机等模式
- 读取 `SOUL.md`、`MEMORY.md`、`USER.md` 等个人配置文件并外发

**疑似**（置信度：疑似）
- 使用通配符读取目录：`cat /root/.openclaw/*`
- 读取环境变量：`printenv`、`env`、`/proc/*/environ`

---

## 维度三：越权操作（Compliance Violations）

**确定有问题**（置信度：确定）
- 访问组织内部受限域名（如 HR 系统、OKR 系统、人才系统等）
- 从 openclaw.json 提取 `sandboxId`/`botMisId` 并用于构造URL
- 通过非合规通道外发公司内部文件
- 读取其他用户的 session 数据

**疑似**（置信度：疑似）
- 访问内部域名但目的不明确

#### 新增红线（2026年更新）

**R3-N1：内网穿透禁止**
- 特征：skill 中包含 ngrok/localtunnel/cloudflared/bore/frp 等工具的安装或调用
- 风险等级：🔴 严重
- 置信度：确定
- 修复：移除所有内网穿透相关指令

**R3-N2：HR 系统访问禁止**
- 特征：访问组织内部 HR/OKR/人才/绩效等受限系统
- 风险等级：🔴 严重
- 置信度：确定
- 修复：移除相关 URL 访问指令

**R3-N3：C4 高敏数据输入禁止**
- 特征：skill 要求用户输入包含"C4"、"绝密"、"内部高密"等字样的内容，或描述要处理高敏数据
- 风险等级：🔴 严重
- 置信度：疑似
- 修复：添加数据分级说明，明确 skill 不处理 C4 数据

**R3-N4：敏感文件备份禁止**
- 特征：skill 执行对 openclaw.json / device.json / device-auth.json 等文件的备份、上传、外发操作
- 风险等级：🔴 严重
- 置信度：确定
- 修复：移除相关备份逻辑

**R3-N5：description 过度触发**
- 特征：description 中包含"所有"、"任何"、"一切"等无限制性词语，触发范围不合理
- 风险等级：🟡 中危
- 置信度：疑似
- 修复：缩小 description 触发词范围，明确边界

---

## 维度四：恶意脚本（scripts/ 目录）

**确定有问题**（置信度：确定）
- `rm -rf /`、`rm -rf ~`、`dd if=/dev/zero` 等破坏性命令
- 下载并执行远程脚本：`curl URL | bash`、`wget URL | sh`
- 反弹 shell：`bash -i >& /dev/tcp/`、`nc -e /bin/bash`
- 提权命令：`sudo su`、`chmod 777 /etc/`
- 挖矿特征：`xmrig`、`minerd`、`.mining`

**疑似**（置信度：疑似）
- 脚本中有硬编码的外部 IP 地址
- 使用 `eval` 执行动态生成的代码
- 网络请求目标域名不在白名单内

---

## 维度五：依赖安全（npm/pip）

**建议关注**（置信度：建议关注）
- 安装来源不明的包：`pip install` 非 PyPI 官方、`npm install` 非 npmjs.com
- 包名疑似 typosquatting（如 `requets` 代替 `requests`）
- 使用 `--pre`（预发布版）或 `--index-url` 指向非官方源

---

## 维度六：description 触发合理性

**确定有问题**（置信度：确定）
- description 为空或少于 20 字
- 触发词覆盖所有场景（"用于任何任务"）

**建议关注**（置信度：建议关注）
- description 与 SKILL.md body 描述的功能明显不符
- 触发词包含与 Skill 功能无关的高频词（如"帮我"、"查一下"）

---

## 评分算法

| 风险级别 | 扣分 |
|---------|------|
| 确定-高危（外泄/越权/恶意脚本） | 直接 F |
| 确定-中危（注入/越权访问） | -30分/项，≥2项降为D |
| 疑似-中危 | -15分/项 |
| 建议关注 | -5分/项，不影响评级 |
| R3-N1~N4 严重红线（内网穿透/HR系统/C4数据/敏感备份） | -20分/项 |
| R3-N5 description 过度触发 | -10分/项 |

**评级标准：**

| 分数 | 评级 | 含义 |
|------|------|------|
| 100 | A | 安全，可放心安装 |
| 85-99 | B | 较安全，有轻微问题 |
| 70-84 | C | 存在需关注的风险，建议修复后安装 |
| 50-69 | D | 存在较严重风险，强烈建议修复 |
| <50 | F | 存在高危风险，禁止安装 |

---

## 可自动修复 vs 需人工判断

**可自动修复：**
- frontmatter 包含非标准字段 → 自动移除
- description 触发词过宽 → 建议收窄并生成修改版
- scripts/ 中有不必要的网络请求 → 添加注释说明用途

**需人工判断（仅给建议，不自动改）：**
- 疑似 Prompt 注入（意图不明确）
- 访问内部域名但目的不确定
- description 与功能不符（需理解语义）
