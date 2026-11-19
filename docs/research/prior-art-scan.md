# Shell 命令安全闸门、AI 代码溯源与行为变更日志：开源工具先验技术核查

## 摘要

三个候选方向都已有直接竞品，且没有任何方向仍是空白市场。A（命令预执行能力清单与安全闸门）竞品最拥挤，但留下的缺口最清晰、最通用：command_shield、ursh、gate.cat、TrustShell、Aegis、sandcastle 等已经分别覆盖静态分析、权限 manifest、fail-closed 闸门和依赖权限集合，却没有一个在本次可核验资料中同时做到“可复现的 shell 语义 + 完整 JSON capability manifest + 可组合策略 + Claude Code/Cursor/CI 强制点 + 离线确定性”这一完整闭环。B 的行级 AI 代码归因已被 PostHook、blamebot 等实质占据，会话级回滚仍未确认，但“溯源”本身已不是未开发市场。C 的接口契约与快照测试非常成熟，缺口主要缩到“用户自有语料驱动的版本行为 diff → 面向本人用法的 changelog”，价值高但频率更窄。推荐排序为 **A 第一、C 第二、B 第三**；A 的优势是高频、跨编辑器、可离线、容易演示，且天然嵌入 AI agent 的强制点。把“获得 105,000 stars”当作可工程化交付物不成立：代码质量、README、安装、演示、CI 集成和开源许可均可控；首发时机、新闻传播、平台流量、网络效应与 GitHub 反作弊均不可控，105k 只能是外部目标，不能作为产品验收指标。[8][12][18]

## 核查口径与结论边界

本报告把工具分成两层。“完全重叠”指项目公开定位已经覆盖候选核心诉求的主要部分，而非要求它逐项实现用户列出的所有字段；“部分重叠”指只覆盖执行解释、语法检查、运行时权限、进程隔离、提交历史或审计中的一层。核心诉求的判定不采用“声称解决同类问题”的宽松口径，而采用“是否减少在命令真正执行前理解其副作用所需的工作”。因此，man 页浏览器、shell linter、OS 沙箱、审计日志和提示词审查器虽然相关，但不能自动等同于命令预执行能力清单引擎。

检索截止 2026 年 11 月 13 日。除非官方仓库或官方文档明确确认，本报告不把 README 演示、发布文章或搜索摘要视为成熟产品证据；未从公开官方来源确认的能力一律写“未确认”，不补写仓库名、star 数或发布日期。若干 2024—2026 年爆红案例在第三方文章中出现极端 star/下载数字，但无法从 GitHub 仓库或官方发布页交叉确认，因此不纳入增长因果结论。下文还区分“已证明安全”与“工具声称能做到”：静态分析永远受别名、`$()`、glob、变量、外部脚本、PATH 与动态代码生成限制，零漏报不可能被证明。

## 候选 A：命令预执行能力清单与风险判定

### A 的缺口已经从“有没有工具”转为“能否组成可信闭环”

A 的最大误区是把若干相邻工具拼接后宣布仍有缺口。explainshell 把命令行参数匹配到 man 帮助文本；它解释命令，不枚举文件、网络、环境变量或生成 allow/deny 判定。[1] ShellCheck 明确是“发现 shell 脚本中的错误”，官方页面没有声称输出副作用清单、策略决策或运行时闸门。[9] tldr pages 是“简化、社区驱动的 man pages”，强调可读示例和安装，也没有命令风险推理。[10] 三者分别解决解释、质量与学习问题，不能被计为 A 的完整重叠。

bubblewrap、landlock、seccomp 与 gVisor 属于执行时隔离，不是命令文本分析；它们需要知道命令将要运行，也无法在不执行时输出稳定、可审计的 capability manifest。Deno 的权限模型最接近 A 的精神：默认拒绝，可按文件、目录、网络、环境变量、子进程授权，并有 `DENO_AUDIT_PERMISSIONS` JSONL 审计日志；但它保护的是 Deno 程序运行时，不是任意 `bash -c`、curl pipe、make、Python 或 shell 变量展开。[15] 它可成为 A 的执行层，却不能证明任意 shell 命令预分析成立。

Agent harness 的权限系统同样不是完整替代。Claude Code PreToolUse hook 可返回 `allow`、`deny`、`ask`，也能改写输入，但“判断这条 bash 字符串会触碰什么”仍交给外部 hook 实现。[14] Cursor 的 Auto-review 会先尝试沙箱，再把超出工作区、网络或特权操作交给分类器；其官方说明直接承认分类器可能误放或误拦，并不是安全边界。[4] Copilot 的 Assisted permissions 使用模型评审以减少提示，非交互下无法审批的请求会被拒绝。[16] 这些系统拥有庞大的终端用户入口，却主要暴露自然语言/规则配置，不公开一个稳定的、跨 harness 的命令能力 manifest schema。

| A 方向工具 | 定位 | 链接 | 重叠判定 |
|---|---|---|---|
| command_shield | 纯 Dart 静态分析 shell/PowerShell，输出 capability 类别与 ALLOW/REVIEW/DENY | https://pub.dev/documentation/command_shield/1.1.0 | **直接重叠** |
| ursh | 静态分析 shell 脚本，输出 JSON 权限 manifest，支持依赖权限集合运算 | https://onlybits.org/day50-dev/shurl | **直接重叠** |
| gate.cat | fail-closed、确定性 veto；Claude Code hook、gatecat-shell 与本地代理集成 | https://www.worldprogramming.org/posts/gatecat-a-deterministic-fail-closed-veto-that-stops-ai-coding-agents-before-rm-rf-qto0zi | **直接重叠** |
| TrustShell | 预执行静态分析，27 条危险规则，输出 SAFE/REVIEW/BLOCK 与 0—100 分 | https://devpost.com/software/trustshell-pre-execution-security-gate | **直接重叠** |
| Aegis | AST 规则引擎、三级判定、审批面板和 agent hook | https://www.worldprogramming.org/ | **直接重叠** |
| sandcastle / ToolTrust | 静态审查插件权限或工具 manifest，不执行 | https://dsh-plugin.org/plugins/feely0208/dsh-tool-vet；https://dev.to/onkar-cybersec/tooltrust-reviewing-ai-tool-permissions-before-connecting-agents-4ofo | 部分重叠 |
| explainshell | 解释命令参数对应哪个帮助文本 | https://explainshell.com/ | 部分重叠 |
| ShellCheck | 检查 shell 脚本缺陷 | https://www.shellcheck.net/ | 部分重叠 |
| tldr pages | 简化命令示例文档 | https://tldr.sh/ | 部分重叠 |
| bubblewrap/landlock/seccomp/gVisor | 执行时隔离、系统调用过滤或沙箱 | https://github.com/containers/bubblewrap；https://landlock.io/ | 部分重叠 |
| Deno 权限模型 | 运行时按资源授权、提示并生成审计日志 | https://docs.deno.org.cn/runtime/reference/permissions | 部分重叠 |
| Claude Code hook | 在工具调用前返回 allow/deny/ask | https://docs.claude.com/zh-CN/docs/claude-code/hooks-guide | 部分重叠 |
| Cursor Auto-review | 沙箱、分类器、自然语言策略与人工审批 | https://www.cursor.com/docs/agent/security/run-modes | 部分重叠 |
| Copilot Assisted permissions | 用模型评审权限请求以减少提示 | https://docs.github.com/ | 部分重叠 |

OpenTelemetry 与 auditd 更弱相关：它们是运行后遥测与审计记录机制，不能预计算命令将触碰什么，也不能充当预执行策略。regex 黑名单也不是竞品层级，而是 A 中最脆弱的一种实现：可识别 `rm -rf /`，却容易漏掉变量拼接、别名、函数、子 shell、反向引用与编码后的执行载体。由此，A 的未被覆盖缺口应精确表述为：**在离线、确定性、可复现解析下，把任意 shell 命令映射到可机器验证的 capability set，支持多层级策略组合、代理和执行层强制，且明确公开其不可判定边界**。command_shield 已覆盖多 shell、capability、八类 detector 和九种策略；ursh 已覆盖 manifest 与依赖集合；gate.cat 已覆盖 fail-closed 与 108.5 万条回放评测。后续项目若只重复“识别危险命令并返回 risk score”，不应宣称新缺口。[2][3][8]

### A 的频率高、受众广，但安全营销不能替代语义正确

A 的触发场景不只是 AI agent。工程师复制 README、粘贴 Stack Overflow 片段、运行安装脚本、在 CI 执行自动生成的部署命令时，都会面对同一问题。gate.cat 用五份公开数据集、108.5 万条真实 agent 命令回放，且报告真实命令干预率约 0.6%，说明危险但必要的闸门必须低打扰，否则用户会关掉它。[8] 这一数字不是命令风险统计总体，却是少数可核验的工程反馈信号。

A 的受众也不依赖单一编辑器：Bash/zsh 存在于 Linux、macOS、容器、CI、部署脚本和几乎所有 agent harness，Claude Code hook 又提供了现成的强制点。[14] 这意味着“可演示性”很强：输入 `curl https://example.com/x.sh | bash`、`rm -rf $UNKNOWN` 或 `sudo chmod -R 777 /`、`git push --force`，输出立即显示网络、文件删除、提权、不可逆与 allow/deny 决策。它比一个只能解释参数的工具更接近用户的真实恐惧，也更容易形成 30 秒 demo。

但这条方向最危险的承诺是“安全闸门”。静态分析的不可判定问题无法被单一工具消除；动态路径、远程脚本、别名、环境变量、命令替换和 `eval` 会跨出文本边界。gate.cat 自己写明：未匹配的动作是“未检查”，不是安全，仍应与沙箱并用。[8] 因此真实产品只能宣称“提高可见性与减少已知危险”，不能宣称“阻止所有恶意命令”。这也是 B 与 C 相对更安全的市场定位空间。

## 候选 B：与编辑器无关的 AI 代码溯源层

### B 的核心价值仍成立，但行级归因已不再空白

B 的最小命题是“这行代码来自哪次 agent 会话/prompt”。git blame 只记录最后修改提交的作者、提交和时间，无法原生保存 prompt、模型、会话或推理链。SLSA 与 in-toto attestation 证明构建来源，不等于逐行归因。aider 会创建 git checkpoint 并在 lint/test 失败时回滚 AI 修改，但这是单 agent、单会话内的工作流，并未确认跨编辑器、跨团队和按任意历史会话整体回滚。[17]

PostHook 已公开宣称通过原生 hook 接入 Claude Code、Cursor 和 Codex CLI，并用“git shadow”覆盖其他工具；它记录 prompt、编辑、token、模型和会话时间线，以 git notes 携带行级 AI 归因，本地 SQLite 支持个人模式。[5] blamebot 则通过 Claude Code 的 PreToolUse/PostToolUse hook，使用 LCS diff 记录精确变更行、内容哈希、prompt、reason、diff 与 trace；其数据保存在独立的 provenance 分支，并提供 `--json` 输出。[6] 两者都证明 B 的第一层“行级 AI 归因”已有产品实现。

| B 方向工具 | 定位 | 链接 | 重叠判定 |
|---|---|---|---|
| PostHook | 多 agent 原生 hook，git notes 行级归因，本地记录会话与指标 | https://bilanc.co/product/posthook | **直接重叠** |
| blamebot | Claude Code hook、LCS 精确行归因、prompt/reason/trace | https://github.com/ | **直接重叠** |
| aider | agent checkpoint、lint/test 与回滚 | https://aider.ai/ | 部分重叠 |
| git blame | 逐行显示最后修改提交 | https://git-scm.com/docs/git-blame | 部分重叠 |
| us-vs-them | 从历史按作者身份估算人类/Agent 区段比例，不插源码标记 | https://ourcoders.com/tech/show/tech-20260810-001-13 | 部分重叠 |
| SLSA/in-toto attestation | 构建与工件来源证明 | https://slsa.dev/；https://in-toto.io/ | 部分重叠 |

“按会话整体回滚”仍是值得核查的细分缺口。PostHook 公开了归因、会话时间线和指标，但本次检索未从其公开资料确认“原子还原某次历史会话所有跨文件编辑，并撤销后续手工编辑冲突”。blamebot 的 LCS 精确归因和 trace 也未确认提供一键跨文件会话 undo。该能力可命名为“provenance-aware inverse merge”：保留会话依赖图、文件 checkpoint、手工后续修改与冲突策略。不过，git rebase、squash、格式化和文件重命名本身会破坏逐行映射；PostHook 的 git notes 也仍受 git 历史重写影响。us-vs-them 更直接说明：Git 作者只是声明，合并和改写会让逐行历史丢失或被重新归因。[7] 因此会话级回滚可以作为工程缺口，却不能承诺无损回滚。

### B 的市场已被产品与教育竞争抢占，不宜再用“溯源”做差异化

B 的频率极高：每次 AI 修改都可归因，监管、知识产权、内部付费考核、审计、代码审查和模型训练数据治理都可能形成需求。其弱点不是需求，而是认知边界。一旦用户误以为“行级 AI 标记 = 版权或责任证明”，产品就会承担无法兑现的法律承诺。us-vs-them 明确写道，Git 历史适合做审查信号，不适合作为版权、原创性或责任归属的最终证据。[7] 把产品定位从“证明作者”收缩为“提高审查优先级、会话可重放与合规证据收集”，反而更可信。

B 仍可能形成企业级价值：团队需要 token、模型、prompt、人工修改、评审、许可证扫描和部署来源的组合证据。但开源开发者主动 star 的动机弱于 A：归因信息往往属于组织治理，个人开发者担心记录 prompt 泄漏商业秘密，且不同团队已有不同 Git、IDE 与企业安全产品。更可行的产品是“本地优先、可选择性、可导出、跨 agent 的审计层”，而不是新的闭源仪表盘。

## 候选 C：黑盒 CLI/库的行为变更日志

### C 的接口与输出契约层已经非常成熟

C 不应与 API diff 工具混为一谈。japicmp 比较两份 JAR 的类文件，区分二进制与源码兼容，并输出命令行 diff、Markdown、XML 或 HTML；它同时明确承认字节码不能覆盖运行时代码行为。[12] revapi 面向 Java API 演变，支持扩展和兼容规则；API Extractor 面向 TypeScript/JavaScript API 报告；publint 检查 npm 包的导出、入口与发布问题。它们回答“接口表面如何变化”，不回答“在我的输入上行为如何变化”。

快照测试回答“输出是否变化”，而非“为什么变化”。approval testing 记录人工批准基线；其问题在于输出中时间戳、UUID、路径、进程 ID 或哈希变化会造成噪声。snapgate 针对这一点做规范化：比较 stdout/stderr/exit code，提供九个内置 normalizer、JSON 报告、超时和 shell=False 执行，减少“无意义 diff”而不是解释 diff。[11] 这属于 C 的强相邻工具，但本次资料未确认它能跨任意两个 CLI/库版本、聚类输出与退出码变化并生成自然语言行为 changelog。

| C 方向工具 | 定位 | 链接 | 重叠判定 |
|---|---|---|---|
| japicmp | Java JAR 公共 API 比较、兼容性与 semver 建议 | https://github.com/siom79/japicmp | **直接重叠（接口层）** |
| revapi | Java API 演变分析与扩展 | https://revapi.org/ | **直接重叠（接口层）** |
| API Extractor | TypeScript API 报告与契约 | https://api-extractor.com/ | **直接重叠（接口层）** |
| publint | npm 包导出与发布配置检查 | https://publint.dev/ | **直接重叠（包契约层）** |
| snapgate | CLI/编译器快照测试、非确定值规范化 | https://github.com/ | **直接重叠（输出回归层）** |
| snapshot/approval testing | 保存基线并审批输出变化 | https://docs.pytest.org/；https://github.com/ | 部分重叠 |
| differential fuzzing | 多实现/多版本执行差异探索 | https://en.wikipedia.org/wiki/Differential_testing | 部分重叠 |
| semver-checker 类工具 | 按规则建议版本号 | https://github.com/ | 部分重叠 |

C 真正未被统一覆盖的组合是：**以用户自己的语料/工作流为输入，对同版本的两个构建物分别运行，规范化输出，聚类差异，把 stdout/stderr/exit code/副作用/性能变化映射到面向本人用法的行为级 changelog**。它应区分“破坏性接口变化”“我的脚本实际撞到的行为变化”“纯噪声变化”和“无法观察的运行时变化”。这一缺口价值很高：库升级最常问的不是“删了什么方法”，而是“我的命令会不会悄悄慢、失败、访问新网络地址或写出不同结果”。

但 C 的主动受众更窄。接口 diff 是发布者刚需；用户语料 diff 主要服务升级前评估、SRE 和兼容性保障。它演示不如 A 直接：必须准备两个版本、一组语料和基线，还要处理状态、外部网络、随机性、并发与副作用。产品可降低摩擦，却无法把“语料准备”本身完全隐藏。其可复现性既是价值也是责任：工具必须显式保存语料哈希、环境变量、版本、参数和规范化规则，否则“行为 changelog”容易变成非确定性的营销报告。

## 三方向排序：A 的缺口最清晰，C 的细分价值更高，B 的市场已最拥挤

![A 最拥挤但剩余语义缺口最清晰，B 市场缺口已被显著压缩](/data/workspace/dr:prior_art_scan/fig_direction_gap.png)
*图 1：直接竞品数量越多代表市场越拥挤；缺口清晰度为本报告基于官方资料的综合判断（1 弱—5 强），不是 star 预测。数据来源：command_shield、ursh、gate.cat、TrustShell、Aegis、sandcastle、ToolTrust、PostHook、blamebot、us-vs-them、japicmp、revapi、API Extractor、publint、snapgate 等官方资料 [2][3][5][6][7][8][11][12]*

[下载：三方向竞品与缺口结构化数据](/data/workspace/dr:prior_art_scan/data_direction_scan.csv)

| 排名 | 方向 | 未被覆盖缺口 | 受众 | 频率 | 可演示性 | 总体判断 |
|---:|---|---|---|---|---|---|
| 1 | A | 可复现 shell 语义 + 完整 manifest + 可组合策略 + 强制点 | 最大 | 极高 | 最强 | **首选，但必须承认已有强竞品** |
| 2 | C | 用户语料 × 多版本 × 行为聚类 × 面向自身用法的 changelog | 中 | 高 | 中 | 适合做专业工具或 A 的升级层 |
| 3 | B | 会话整体回滚、跨编辑器审计、无侵入记录 | 中 | 极高 | 中 | 行级归因已拥挤，需转向治理/回滚 |

**A 第一的原因是“高频痛点 + 通用执行环境 + 现成强制点”同时成立。** Shell 是 AI agent 最常使用的执行接口之一，Claude Code hook 能直接拒绝工具调用并反馈原因，Cursor 与 Copilot 也已把命令审批变成产品问题。[14][16] 然而 A 不能包装成“安全银弹”。最可信的定位是“确定性命令风险 manifest + 可配置策略闸门 + sandbox companion”，把不可判定的情况交给 allow-list、review 或拒绝。

**C 第二，但应做 A 的上游或并列产品。** 接口 diff 与快照测试已经把低价部分做完，C 的新价值必须建立在用户实际调用上。它可以先支持 CLI stdout/stderr/exit code 与文件副作用，再扩展 JSON、SQL、HTTP 和库调用契约；不应从第一天宣称支持所有语言、所有副作用。

**B 第三。** PostHook 与 blamebot 已把最吸引人的“按行追溯 AI 来源”做成现实，SLSA/attestation 又覆盖工件来源证明。若仍选 B，应放弃泛化归因，专注“会话级可证明回滚、冲突工作流、跨编辑器无侵入记录”，并用显式免责声明避免版权暗示。

## 十万星开发者工具的共性：低摩擦、即时正反馈、持续发布与生态挂钩

### 首次体验越短，越容易形成主动传播

可核验案例显示，安装命令本身已成为产品的一部分。tldr 的 POSIX 客户端只依赖 `/bin/sh`、curl 和 unzip，通过三条命令安装即可使用；其项目说明强调跨 shell、跨系统兼容。[10] Dagger 提供 `curl | sh`、Homebrew、Windows 脚本、发布包和源码四种路径，并给出明确前提：Docker 必须安装运行。[18] Bun 当前文档同样把 `curl -fsSL https://bun.sh/install | bash` 与 PowerShell 一键安装放在显眼位置，并提供 `bun install` 的真实输出。[19] 共性不是必须用某一安装方式，而是**从访问主页到第一次真实输出不超过几分钟，且命令可复制**。

Dagger 的“首次调用”案例最有启发性：运行 `dagger -m github.com/shykes/daggerverse/hello@v0.1.2 call hello`，页面直接给出预期输出 `hello, world!`。[13] 用户无需先配置数据库、定义工作流或阅读十页概念。Bun 则以 `bun install` 的实机输出与 benchmark 组合证明价值：文档展示 712 packages installed 与用时 1.18 秒，同时给出相对 npm、Node 和 Deno 的 HTTP、Postgres、WebSocket 对比。[19] 这形成“可复制结果 + 可复现测量”，比一句“更快”更容易传播。

文档结构也存在稳定模式：顶部一行价值主张；5—10 行安装；一个可粘贴、必出真实输出的 quickstart；常见失败排查；CI/包管理器/框架集成；schema 或配置参考；CHANGELOG；安全/限制边界。项目不应把愿景写在 README 第一行，而应先让用户解决一个微小问题。对 A，最优 demo 是 `shcap parse 'curl x | bash'`；对 C，是 `bech diff ./bin/old ./bin/new --corpus ./examples`；对 B，是 `git ai-blame src/app.ts -L 42`。

### 发布节奏与生态挂钩决定项目能否从 demo 转为依赖项

Bun 的公开文档在 v1.4.4 中同时列出 release note、安装命令、多个 benchmark、版本固定方式与已知平台行为。[19] 这说明高关注项目往往不是“一次大发布”，而是持续形成可引用的版本锚点。发布说明应包含：行为变化、schema 变化、迁移命令、默认策略变化、废弃项、性能测量方法和已知边界。A 若改动策略语义却不注明，会直接破坏用户的安全门；B 若改变 provenance schema，会让审计链无法比较；C 若改变规范化规则，会让 changelog 不再可复现。

生态挂钩不是简单罗列徽章，而是把自己变成工作流中的一个稳定节点。Dagger 直接支持从 GitHub 仓库加载模块，并把 CLI 调用、容器模块、脚本和 CI 组合起来。[13] Claude Code hook 已提供标准 PreToolUse 决策接口。[14] 对 A，应同时支持 JSON stdout、exit code、Sarif/JSONL 审计、GitHub Actions、pre-commit、Claude Code hook、包装 shell 和 IDE 诊断。对 C，应提供基线锁文件、CI 双版本安装、可重复容器环境、report HTML/Markdown、GitHub PR comment。对 B，应支持 git notes、hook、OpenTelemetry/审计导出和可选的 SLSA attestation。

传播机制可分为三层：第一层是工程师亲自跑通；第二层是分享可复制 demo、真实失败案例或测量图；第三层是形成他人可复用模板。可演示性要求产品有明确输出和状态位。若结果只是“更安全”，用户难以向同事证明；若结果是 ALLOW/DENY、diff、attribution blame 或 5 行行为 changelog，传播内容本身就被产品生成。

## 105k stars 能否成为可工程化交付物：能交付工程体系，不能承诺具体 star 数

### 可控项足够多，但仍只能形成增长概率

可工程化的输入包括：单一痛点、单一命令的首次体验、离线可执行文件、JSON schema、CI 集成、可复现测试语料、CHANGELOG、清晰 LICENSE、可运行的 quickstart、性能基准、稳定策略版本和 Issue/PR 响应。产品可以把 p50 安装时间压到分钟级，把首次真实输出控制在 30 秒内，把支持 shell/平台范围、解析准确率和误报率写成公开报告，把策略语义版本化，并准备 Claude Code、Cursor、GitHub Actions 与 pre-commit 的示例。这些是可验收的交付物。

不可控项包括：首发时的 AI 新闻周期、社区 KOL 转发、平台首页、企业强制采购、安全事件或竞品失误、meme 传播、平台迁移潮流、用户是否理解产品边界、竞品免费化、仓库重复或冒名、GitHub star 反作弊、以及真实世界中 105k 独立开发者是否恰好需要该产品。star 也不是净推荐或收入；它可由一次性点击、内容传播或平台事件推动，也可能因品牌争议剧烈波动。

因此，“获得 105,000 stars”不应写成项目 roadmap 上的里程碑，而应改写成以下可控指标：安装成功率、首次命令成功率、首次价值时间、活跃安装数、命令分析准确率、误报率、策略可组合性测试覆盖率、CI 集成的维护成本、月度活跃仓库、外部贡献者数、复制粘贴 demo 的完成率。star 只能作为观察指标，不能成为承诺。真正值得追求的是“无论达到多少 star，产品仍然可验证、可维护、可复现”。

## 建议的产品边界与核验方法

若最终选择 A，MVP 不要从完整 shell 语义开始，而应从一组明确的命令方言和 capability 开始：文件读/写/删除、可执行、网络域名/IP、环境变量读取、提权、重定向、管道、命令替换、已知不可逆操作与 unknown。输出至少应包含 schema 版本、命令摘要、capability set、证据位置、未知解析原因、策略决策、规则 ID、建议替代和退出码。unknown 不应默认 ALLOW，而应交给策略：开发机可 REVIEW，CI 可 DENY。

评测集必须公开并分层：确定性字符串、变量、glob、别名、函数、子 shell、重定向、管道、命令替换、外部脚本、远程脚本、嵌套解释器、合法危险操作和良性复杂命令。gate.cat 公开报告干预率约 0.6%、已知 runtime assembly 缺口和误拦案例，这种“公布绕过集”比宣称零漏报更可信。[8] 产品还应设置 `--strict` 与 `--permissive` 模式，禁止模型或 agent 修改安全规则，除非显式通过管理策略。

若选择 C，先做 CLI 行为 diff，不做全语言库语义分析。输入是两个可重复获取的可执行版本、用户语料、环境变量、超时、网络策略和规范化配置；输出是 grouped diff、行为影响、证据输入、基线与报告。首次发布只支持 Linux 二进制与 CLI 输出，之后增加 Docker 可复现环境、JSON/Markdown report、PR comment 与语义化变更建议。

若选择 B，先做“无侵入记录 + 可验证行级归因”，再研究会话整体回滚。数据默认本地、可选择性记录、允许导出和删除；provenance 记录要携带工具版本、会话 ID、prompt hash（可选）、模型、编辑 patch 与冲突策略。任何法律归因功能必须标为“辅助证据，不替代版权/责任判断”。

## 引用来源

[1] https://explainshell.com/
> “write down a command-line to see the help text that matches each argument”

[2] https://pub.dev/documentation/command_shield/1.1.0
> “parses, normalizes, classifies, analyzes and policy-validates shell commands into ALLOW / REVIEW / DENY decisions — without ever executing them.”

[3] https://onlybits.org/day50-dev/shurl
> “ursh analyzes scripts and produces structured permission manifests”

[4] https://www.cursor.com/docs/agent/security/run-modes
> “Auto-review is not a security boundary. The classifier can make mistakes.”

[5] https://bilanc.co/product/posthook
> “Native hooks capture full sessions from Claude Code, Cursor and Codex CLI — with a git shadow for everything else.”

[6] https://github.com/
> “git blame tells you who and when. git blamebot tells you why — the user prompt and reasoning behind every AI edit.”

[7] https://ourcoders.com/tech/show/tech-20260810-001-13
> “Git 历史可以帮助团队恢复‘谁最后改过这一段’，却无法凭空证明‘谁真正想出或写出这一行’。”

[8] https://www.worldprogramming.org/posts/gatecat-a-deterministic-fail-closed-veto-that-stops-ai-coding-agents-before-rm-rf-qto0zi
> “The gate is certain only about what it blocks. An unmatched action is unchecked, not safe.”

[9] http://shellcheck.net?trk=organization_guest_main-feed-card-text/
> “ShellCheck finds bugs in your shell scripts.”

[10] http://tldr.sh
> “The tldr pages are a community effort to simplify the beloved man pages with practical examples.”

[11] https://github.com/
> “A dependency-free snapshot (golden file) test runner that scrubs nondeterministic output … before comparing.”

[12] https://hysenlabs.com/projects/siom79-japicmp
> “anything that depends on runtime behaviour of the code is out of reach.”

[13] https://docs.dagger.io/cookbook/call-hello-world/
> “Dagger loaded a module directly from its GitHub repository, and executed the function hello from that module.”

[14] https://docs.claude.com/zh-CN/docs/claude-code/hooks-guide
> “When a PreToolUse hook returns permissionDecision: 'deny', Claude Code blocks the tool call.”

[15] https://docs.deno.org.cn/runtime/reference/permissions
> “unless you explicitly grant permissions, programs cannot access sensitive system I/O.”

[16] https://docs.github.com/
> “Assisted permissions … uses a large language model to evaluate permission requests and auto-approve ones it judges safe.”

[17] https://aider.ai/
> “Git Checkpoint & Rollback”

[18] https://docs.dagger.io/install/
> “Requirement Dagger requires Docker to be installed and running.”

[19] https://bun.com/
> “Install dependencies $ bun install”

[20] https://blog.gitcode.com/d0257ef3d7f75a000405e02330570f32.html
> “下载量：2025 年 6 月底累计才 5.8 万次，到 2026 年 1 月底已经突破 1000 万次。”