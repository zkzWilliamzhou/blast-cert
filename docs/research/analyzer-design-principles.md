# 零依赖安全关键 shell 命令能力判定器：架构原则与标准映射

## 摘要

该工具应被设计成一个**保守的静态判定器**，而不是一个自称能完整理解 shell 语义的“命令解释器”。可移植地回答“某个 shell 字符串能做什么”在数学上不可能做到；合理目标是以可追溯的词法与受限语法分析，过近似地枚举可能产生的调用、重定向、动态来源与未决项，并输出机器可验证的 `unknown`/`opaque` 状态。多伦多大学静态分析讲义将 sound over-approximation 定义为执行轨迹的超集，这是该工具正确的安全语义；Deno、WASI、macOS App Sandbox、Landlock、seccomp 与 AppArmor 则共同支持默认拒绝、显式授权、最小权限、内核/运行时强制和逐层防御[1][3][6][8][9][10][11][12]。

工程上，标准库 `shlex` 只能承担 POSIX/non-POSIX 词法切分，不应宣称解析 `$(...)`、反引号、别名、函数、变量展开或运行时 `$PATH`；其官方文档明确仅面向 Unix shell，且 `quote()` 在非 POSIX shell 上并不保证安全[4]。`argparse`、`json`、`tomllib`、`dataclasses`、`pathlib`、`fnmatch` 与 `unicodedata` 可用于 CLI、目录加载、序列化、值对象、纯路径计算和字符归一化，但都须设置硬边界，尤其不能把规范化路径误当作真实路径、把 fnmatch 当路径 glob、或把不可信 Unicode 归一化后用于权限比较。建议借鉴 Semgrep 的 `id/languages/pattern/severity/metadata/version/paths`、Kubernetes RBAC 的策略与绑定分离、AppArmor 的 ABI/附着点/enforce-complain，以及 ShellCheck 的宽容错误恢复[2][5][13]。输出清单至少应包含命令定位、能力、对象、动作、置信状态、证据区间、规则 ID、目录摘要与确定性指纹。

## 1. 正确安全目标不是“精确预测行为”，而是“不漏掉危险超集”

**工具必须证明其输出是真实执行行为的安全超集，而不是偶尔精确的模拟器。** 多伦多大学讲义将静态分析定义为“对程序执行语义的 sound、finite、approximate 计算”，其中 sound over-approximation 描述执行轨迹的超集；under-approximation 才是“可执行轨迹子集”。对安全判定而言，前者保证不会把危险执行静默漏掉，后者不能用于准入控制[1]。本报告因此不采用“精确预测运行结果”作为需求；其采用的需求是：任何实际可能产生的命令调用、写文件、读取敏感文件、网络行为、权限改变、进程执行、代码注入或信息泄露来源，要么出现在风险超集中，要么由明确的 `unknown`/`opaque` 状态阻止放行。

这条定义也划定了“soundness”在本题中的含义。它针对的是判定器的规范，不是 shell 语言的可判定性。判定器应对 source、语法模型、规则目录、环境和输出协议保持透明；若输入包含未知 shell 方言、动态命令名、未闭合引号、无法静态求值的变量、命令替换、别名、函数、eval、source 或无法解析的重定向目标，结果可以仍包含已经识别出的调用，但必须置 `analysis.status=needs_human_review` 或 `unknown_present=true`。若工程团队把“输出无 deny”解释成“执行后一定无副作用”，就是把 soundness 误用成了执行模拟。

**保守超近似并不等于粗糙的关键词黑名单。** 有效的近似应保持尽可能紧的安全边界：识别出 `rm -rf /tmp/x` 的写删除意图，而不是只看到字符串 `rm`；同时不把 `$VAR` 假装解析成固定路径。GitHub 公开解析器把每个命令名和参数标成“完整字面量或 null”，并对 `/tmp/$name.txt` 返回 `null` 而非半展开字符串；它还把动态命令名、命令替换、eval、source、未知函数与截断统一归入 `isOpaque`[15]。这是合适的最小范式。部分重构会制造假路径感；例如把 `./$cmd` 报告成 `./`，会误导人把动态可执行文件当成固定只读对象。

**异常、词法错误和未知项必须在同一判定通道中处理。** fail-closed 的正确实现不是只捕捉 Python 异常并退出码 2；而是任何无法完成完整分析的阶段都不得输出 `verdict=allow`。具体包括：输入不是 UTF-8 或采用未声明编码、词法器超时、token/语法模型构造失败、规则目录反序列化失败、规则版本不满足、能力合并冲突、对象规范非法、输出序列化失败。系统应生成结构化 `error` 与 `decision`，而不能只向 stderr 打印人类信息后退出；CI 与 AI 代理需要稳定字段来决定放行。Deno 的默认拒绝、`--deny-*` 优先于 `--allow-*`、`--allow-all` 会完全禁用沙箱，可作为策略优先级与全局逃逸开关的反面教材[3]。

## 2. 策略架构必须实现不可绕过、最小权限和可解释判定

**策略判定必须是一个独立的、可替换的纯函数，而不是分散在解析器各处的 `if cmd == "rm"`。** 建议核心接口为 `analyze(source, dialect, catalog, config) -> AnalysisResult`，其中 `AnalysisResult` 包含 token events、syntax model、capability assertions、unknowns、evidence spans、applied rules 与 verdict。所有阶段使用不可变值对象；catalog 只作为只读配置输入，不接收可变全局状态。该隔离使同一个分析结果可由人类阅读器、JSON schema 校验器、策略决策器和回归测试共同消费，也避免新增命令知识时污染解析器。

**判定必须默认为拒绝，且权限总和不得自动扩大。** 每个能力对象至少具有 `capability`、`action`（如 read/write/execute/network-bind/network-connect/process-spawn/substitute/environment-read/delete）、`object_kind`（file、directory、network-endpoint、process、descriptor、environment）、`object`、`scope`（exact/prefix/pattern/dynamic/unknown）、`confidence`（definite/possible/unknown）和 `evidence`。合并规则应从最严格者取上界；例如目录写入不能由一条只读例外自动降格为只读，未知对象不能升级成“允许”。Deno 允许按 read/write/net/env/run/sys/ffi/import 资源授予权限并支持拒绝优先，但即使其默认安全模型也不能替代本工具的目录语义[3]。

**每条结论必须能定位到原文，而不是只有规则 ID。** `Evidence` 至少包括 `start_line/start_column/end_line/end_column`、原始子串的规范化拷贝、token index、父语法节点 ID、规则 ID 与目录版本。对 `echo $X > /etc/foo`，写意图应主要附着到 `>` 和 `/etc/foo` 区间，而不是把整个命令当成一个含糊的“高危命令”。`ast` 模块是反面证据库：它虽能给节点提供 1-based `lineno/end_lineno` 与 UTF-8 byte `col_offset/end_col_offset`，但它是 Python 解析器，不是 shell 解析器；其文档还明确警告恶意输入可导致 CPU/内存耗尽甚至解释器崩溃[7]。因此只能自研 shell 词法与语法模型，不能把 `ast.parse` 用于 shell 输入。

**审计必须能复现“同一输入得到同一输出”，而不只是记录谁运行了工具。** 每次调用固定并输出：`tool.name/version/commit`、`catalog.digest/version`、`schema.version`、`dialect`、`input.normalized` 或 `input.sha256`、`parsed_at` 与时区固定为 UTC。默认不记录原始命令到远端；若实现支持上传诊断，必须经显式选择加入并再次确认。Deno 可将权限审计写成 JSONL，并用 `DENO_TRACE_PERMISSIONS` 增加调用栈，说明决策追踪可以结构化到帧级[3]；本工具应至少输出至规则的命中链，帧级堆栈只在未来扩展，且不得依赖运行时执行路径。

**“不可绕过”是部署约束，不是一句设计口号。** 若 AI 代理可以绕过判定器直接调用 shell，则判定器只是建议。实现必须：不导出会直接执行字符串的函数；提供独立二进制或锁定脚本入口；在 CI 中以失败退出码阻止合并；要求 catalog 与测试数据通过独立校验；记录 catalog digest；把 verdict 文件作为后续 executor 的唯一输入之一。WASI 的价值正在于能力由宿主显式授予并在运行时边界强制执行，代码默认没有环境权限[2]；本工具无法自行提供这一保证，必须清楚声明它只是“准入前静态判定”，执行层仍须 Landlock/seccomp/AppArmor/macOS sandbox 等机制兜底。

## 3. 权限标准可借鉴字段，但不能混用语义层

**最值得借鉴的是能力、对象、动作、范围、版本、附着点和执行状态，而不是照搬某一格式的完整 schema。** 下表是选型映射，而不是兼容性声明。OpenTelemetry semantic conventions 可借鉴命名稳定化与 attribute namespace，但公开 general 文档中没有确认到“command line”通用属性；因此不应宣称复用某个特定遥测字段[14]。

| 标准/机制 | 原适用场景 | 可借鉴字段 | 不建议直接照搬 |
|---|---|---|---|
| WASI P2/WIT | 组件能力导入 | capability namespace、import handle、filesystem/network/environment/clocks/random、静态可检查接口[2] | 运行时 handle、组件导入的 ABI 细节 |
| Deno permissions | JS 运行时资源授权 | allow/deny 双列表、资源类型、deny 优先、audit trace、allow-all 显式高危[3] | 直接执行授权；Deno 只审计运行时访问 |
| Android permission groups | 移动应用资源 | `permission_group`、危险权限分组、用途说明 | Android 的 package/install 语义 |
| npm package access | 包可见性与发布 | scope、visibility、`can view/download`、`can write/publish` | 把发布权限误当命令能力；npm 文档明确管的是查看、下载、发布[16] |
| OpenTelemetry conventions | 遥测属性 | stable namespace、语义属性命名、版本与弃用管理 | 未确认存在统一 command-line 属性时不得臆造 |
| CycloneDX | 软件供应链 BOM | BOM metadata、components、dependencies、VEX 关联 | 把 SBOM 当成 shell 能力模型；它是供应链风险格式[17] |
| SPDX | 软件物料清单 | 软件/包标识、校验码、关系 | SPDX 页面未能抓取到可用于命令能力判定的具体关系字段，故未确认[18] |
| SLSA provenance | 构建来源证明 | builder、buildDefinition、externalParameters、resolvedDependencies、产物输入指纹[19] | 把 provenance 当运行时权限；它证明构建来源 |
| Kubernetes RBAC | 集群授权 | Role/ClusterRole、rules(apiGroups/resources/verbs/resourceNames)、Binding、subjects[5] | 将主体身份、RBAC 动作或集群资源直译成 shell 文件能力 |
| Landlock | 进程文件系统限制 | ambient right 收缩、层叠、可自我约束[6] | 动态路径语义；Landlock 是执行层机制 |
| seccomp BPF | 内核系统调用过滤 | syscall number/arguments、action、最小化暴露面[8] | 把系统调用过滤当成完整沙箱；内核文档明确说不是沙箱[8] |
| macOS App Sandbox | 应用资源访问 | entitlement 名称、布尔开关、inbound/outbound network、文件选择范围[12] | 应用签名、容器路径与苹果私有 profile 格式 |
| AppArmor | 程序强制访问策略 | profile ABI、attachment path、enforce/complain、file/network/capability/D-Bus、拒绝日志字段[9] | 仅依赖 profile 名称；实际由内核应用 |

**能力清单宜采用“意图能力 + 执行层资源能力”两层模型。** 意图层描述命令作者可见的语义，例如 `filesystem.write`、`filesystem.delete`、`process.execute`、`network.connect`、`network.bind`、`code.eval`、`substitution.execute`；执行层描述本工具无法负责的残余风险，例如“通过未知命令访问未建模的系统调用”。前者可被人类审批，后者必须默认阻塞。这样可避免把“允许 `curl`”和“允许访问任意网络地址”混成一个布尔，也可避免把“允许读取 `/etc/os-release`”错误转成“允许执行 `cat`”。

**标准字段应显式区分“已知但拒绝”“未知”“动态”。** 可借鉴 AppArmor 的 `ALLOWED/DENIED/UNKNOWN_TOOL` 决策日志，但它记录的是内核强制事件，而非静态判定[9]。本工具应给每个 assertion 设置 `status`，可取值 `allowed/denied/unknown/opaque/error`；`unknown` 表示命令、flag、对象或环境解析失败，`opaque` 表示静态模型知道存在某种执行/替换但无法枚举具体内容。只有 `allowed` 才允许被后续组件放行，而且仍需执行层能力边界。

## 4. 声明式 command catalog 必须可验证增长，不能成为无边界黑名单

**目录的基本单元是“命令签名 + 条件 + 能力断言 + 解释”，而不是 `command: risk: high`。** 每条规则建议包括：

```yaml
id: posix.coreutils.rm.recursive_force
version: 1
applies:
  dialects: ["posix", "bash"]
  executables: ["rm"]
  # 语义版本区间指被建模的命令；不是 catalog 版本
  command_version: ["coreutils >= 8.0"]
matchers:
  flags:
    any_of: [["-r"], ["-R"], ["--recursive"]]
    all_of_required: []
    conflicts: []
  operands:
    min: 0
    accepts_options_after_operands: true
  positional_semantic: path
semantics:
  capabilities:
    - capability: filesystem.delete
      object_from: operand
      object_kind: file
      scope: prefix
      action: delete
      when:
        - flag_present: "--recursive"
      evidence: flag_token
effects:
  deny_by_default: true
  escalation: [filesystem.write]
severity: critical
justification: "递归删除可由路径参数覆盖大范围文件树；静态工具无法证明路径安全。"
tests:
  positive:
    - "rm -rf /tmp/x"
  negative:
    - "rm --version"
  opaque:
    - "rm $TARGET"
errors:
  - "rm -rf '/unclosed"
reviewers: ["security-tools"]
```

Semgrep 的公开结构已证明成熟规则语言通常需要 `id`、`pattern/patterns/pattern-either/pattern-regex`、`languages`、`severity`、`metadata`、`min/max-version` 和 `paths`[13]；其中 `paths` 在本工具中不宜直接复用为命令规则，因为路径过滤会混淆“被分析对象”和“规则适用范围”。

**防止目录膨胀的优先手段是归纳能力，而不是枚举每条命令。** 命令可分为 POSIX builtin、POSIX utility、shell 构造、包管理器、版本控制、容器/虚拟机、云 CLI 等族。先定义通用语法节点：`SimpleCommand`、`Pipeline`、`AndOrList`、`Subshell`、`CommandSubstitution`、`ProcessSubstitution`、`Redirect`、`Assignment`、`FunctionDef`、`Eval`、`Source`、`Heredoc`。命令特定规则只在通用节点无法表达意图时添加。Deno 把能力归纳为 read/write/net/env/run/sys/ffi/import，而不是为每种程序单独建规则[3]；AppArmor 的规则也归纳为 file/network/capability/dbus 等类型[9]。

**版本化到“被建模命令”，而不是只版本化目录文件。** 每条规则记录 `command_name`、来源发行版或包、语义版本区间、支持方言、最后观察日期和参考文档。Bash 3/4/5、BSD/macOS `cp`、GNU coreutils 对 `--`、长选项、短选项聚合、`=` 后的参数、选项与操作数边界处理不同。若 catalog 只写一个字符串版本，无法回答“这条 rm 规则适用于哪个 rm”。建议固定一个由 `id + command_name + command_version + dialect + matcher AST digest` 组成的 `rule_identity`，测试与决策结果都引用它。

**flag 组合必须用显式状态机或约束，而不是正则表达式。** 至少建模：`--` 终止选项扫描；短选项聚合 `-abc`；`-ofile`/`-o file`/`-o=file` 的差异；`=` 分隔；选项后是否允许操作数；重复选项的优先级；互斥、累积与副作用升级；依赖关系如 `-L` 需 `-h`；参数来自下一个 token、同一 token 或环境。命令替换和变量展开使大多数参数“可能未知”，此时应生成 `object_scope=dynamic` 的 assertion，而不是尝试猜值。

**未知命令应采用最保守的默认，但保持可配置升级路径。** 默认目录应只包含人工审核过的高价值程序；未知可执行文件产生 `capability=process.execute`、对象为 `executable_name`、scope 为 `unknown-or-unmodeled`，并置 `verdict=deny_or_review`。管理员可显式选择加入白名单，但必须记录例外原因、所有者、过期日和例外 digest。这里借鉴 Android permission groups 的“按资源类型分组”与 Deno 的 deny 优先，但不借鉴“仅按可执行文件名隐式信任”[3][16]。

## 5. 规则测试必须双向覆盖正常、拒绝、未知、错误与回归

**每个规则至少要有四组黄金样本。** positive 组必须触发目标能力，negative 组必须不触发，opaque/dynamic 组必须产生 unknown 或指定 evidence，error 组必须触发明确的结构化错误而不静默 allow。OPA 测试实践建议用 `test_` 前缀、最小化 mock input，并以“几乎相同但期望不同”的正负对防止字段拼写错误让两边都 undefined；其 `--fail-on-empty` 思想可直接转成本工具的“目录变更若无对应测试则拒绝合并”[20]。ShellCheck 被主流编辑器和多个代码质量平台集成，说明静态检查器可通过编辑器、CI 和自动检查进入开发流程[21]。

**删除测试（deletion test）应证明规则确实是结论的来源。** 对每个 positive 样本，测试删除单条规则后结果不再包含相同 capability/evidence，或决策改变；删除某条 negative 样本的规则则不应改变 verdict。这样能发现“两条规则都能匹配，删除其中一条仍通过测试”的假覆盖。实现上可运行完整 catalog、再运行排除该 rule ID 的子集；输出必须按规则 identity 而不是按“是否打印过 WARNING”比较。

**回归语料必须按风险原因和方言分层。** 目录可包括：`tokenization/`（引号、转义、换行、注释）、`expansion/`（变量、参数展开、命令替换、算术）、`control/`（pipeline、and-or、subshell、重定向）、`flags/`（聚合、=、--、位置）、`commands/`（按族和版本）、`catalog/`（版本、重复 ID、缺失字段）、`fixtures/`（真实开源脚本中已脱敏片段）。每个 fixture 保留 source、期望 capabilities、unknowns、verdict、最小 evidence 区间和冻结原因。CI 应输出新增/删除的 verdict 变化，任何从 `deny` 变 `allow` 的 fixture 必须要求显式批准。

**策略与执行绑定必须分开演化。** catalog 描述命令能做什么；policy 描述本次主体/环境允许什么；例外只描述“谁、在什么范围内、为何、到何时”接受偏离。Kubernetes RBAC 用 Role/ClusterRole 保存规则，用 RoleBinding/ClusterRoleBinding 保存 subjects 和 roleRef，明确把权限定义与授权绑定分开[5]。本工具可把三者分别序列化为 `command-catalog.toml`、`policy.yaml`、`exception.yaml`，输出 JSON 同时引用 `catalog.digest` 和 `policy.digest`。这样不允许直接修改命令规则来临时放行。

**规则加载与运行时必须采用 fail-closed 兼容性策略。** 旧目录不得被新引擎默默加载为不同语义；目录应声明 `catalog.schema_version`、`minimum_engine_version` 与 `maximum_engine_version`。缺少字段、未知顶层字段、规则 ID 重复、正则无效、版本区间空、循环 include 都应拒绝加载。Semgrep 允许规则用 `min/max-version` 跳过不兼容版本，但这只是规则选择机制；安全关键系统应额外把“跳过安全规则”视为风险，要求 `--strict` 下禁止跳过或至少产生非零退出[13]。

## 6. 标准库选型必须服从解析边界和确定性

**`shlex` 是受限词法器候选，不是完整 shell 解析器。** 其文档说明 `split()` 默认 POSIX 模式、默认关闭注释解析；POSIX 模式会剥离引号、处理未加引号反斜杠并允许引号空串，EOF 用 `None`，而 non-POSIX 模式不识别词内引号与转义、EOF 为空串。文档还警告模块仅面向 Unix shell，其 `quote()` 在非 POSIX 兼容 shell 上不能保证安全，可能形成命令注入[4]。这意味着它可以切分字面 token，却不能用于证明命令执行、控制流、参数语义或安全。

| 现象 | `shlex` 可以做什么 | 不应得出的结论 | 建议处理 |
|---|---|---|---|
| `# comment` | 可开启 `comments=True` 让 `#` 启动注释 | 能解析所有 shell 注释方言 | 需标明方言；未开启时把 `#` 当普通字符并产出 opaque |
| 未闭合引号 | POSIX 模式在遇到 EOF 时以 `None` 表示 | 命令完整或安全 | 输出 `lexical.error=unterminated_quote` 并 fail-closed |
| 换行 | 可跨多行继续切 token | 能识别 line continuation、heredoc 边界 | 保留原始行/列；heredoc 与续行交由自定义语法层 |
| `$(...)` | 可以切出 `$`、`(`、`...`、`)` 等 token | 已解析内部命令 | 输出 `command_substitution` 节点和 opaque operand |
| 反引号 | 可以切出反引号 token | 已解析内部命令或转义等价 | 输出 `backtick_command_substitution`；标记为 legacy/deprecated 但不静默化 |
| `$VAR`、`${VAR}` | 可以切出字面片段 | 已知展开值 | `object_scope=dynamic`，禁止半展开猜测 |
| `eval`、`source` | 可识别 token | 知道后续内容安全 | 强制 opaque/execute；不递归执行 |
| `> file` | 可切出重定向符号与字面 file | 已证明写发生 | 生成 write/delete assertion；动态目标 opaque |

**`tokenize` 与 `ast` 适合做工具自身的插件/扩展源码分析，而不是 shell 输入。** `tokenize.tokenize` 以字节行的 readline 接口消费 Python 源码，返回 comment 与 `OP` token，并提供 `(row, col)` 的 start/end 定位[22]。`ast.parse` 可生成 Python AST 且不执行代码，节点有 `lineno/col_offset/end_lineno/end_col_offset`[7]。二者适合分析用户用 Python 编写的 catalog 扩展、策略 DSL 编译产物或自定义检查器；绝不可把任意 shell 字符串喂给 `ast`。`ast.literal_eval` 也不应成为命令参数解析器。

**`tomllib` 适合只读 catalog，`argparse` 只适合本工具 CLI。** `tomllib` 自 Python 3.11 起提供只读 TOML 1.0.0 解析，返回 dict，是标准库且不依赖第三方包；它不写 TOML[23]。因此 catalog 文件可用 TOML，但必须规定 schema 版本、稳定表名和严格类型。argparse 负责 `--input/--catalog/--policy/--format/--dialect/--strict/--output` 等人类与 CI 接口；其文档明确指出它不能充分控制选项与位置参数交织等行为，也不能保留原始命令行[24]。因此不能让 argparse 去解析被分析命令，只能解析工具的调用参数。

**`json` 与 `dataclasses` 应被约束为确定性序列化。** `json` 是标准库，可用 `ensure_ascii=False` 与固定 `indent` 提升可读性，但 NaN/Infinity、浮点、map 顺序、编码错误都可能破坏 diff/reproducibility；建议显式禁用 NaN/Infinity、规定 UTF-8、按 schema 排序键并给每个输出加 SHA-256。dataclasses 可用 `@dataclass(frozen=True)` 生成不可变值对象，`asdict` 递归转换结构[25]；但文档明确说它只模拟不可变，不等于真正不可变。因此版本比较、hash 与工厂函数应在 domain 层完成，不能把 dataclass 当安全边界。

**`pathlib` 与 `fnmatch` 只做语法计算，不代替访问检查。** `PurePath` 及纯路径操作不访问文件系统；`Path.absolute()` 不规范化或解析符号链接，而 `resolve()` 会解析链接并在 strict 模式下对不存在路径或循环报错。pathlib 还会把 `my_folder/` 规范化成 `my_folder`，文档警告这种处理可能不适合某些 OS API[26]。故输出应同时保留 `raw_token` 与 `normalized_form`；规范路径仅在未开启真实解析的模式中作显示用。fnmatch 只理解 `*`、`?`、`[seq]`、`[!seq]`，默认用 `os.path.normcase`，且不把 `/` 视为特殊字符[27]；不可把它直接用于目录遍历白名单。

**`unicodedata` 可用于归一化，但归一化本身不能消除安全风险。** 模块提供 UCD 字符属性与 `NFC/NFKC/NFD/NFKD`；NFKC 会应用兼容性分解，可能把视觉相似但语义不同的输入合并，不能盲用于权限字符串[28]。建议：对 source 保留原始 UTF-8；只对明确的 display 字段用固定 NFC；能力对象与 executable identity 使用字节级原始值或可复现 digest；不把 Unicode 类别单独作为命令可信度证据。

## 7. 用“模块深度、接口即测试面、deletion test、seam、adapter、locality”评审结构

**模块深度（module depth）是调用栈中从稳定接口到具体实现的抽象层数，不是文件数。** 对判定器，合理深度应至少把 CLI、应用编排、分析编排、词法/语法模型、catalog repository、capability algebra、policy engine、evidence formatter 分开。若一个 HTTP/文件系统 adapter、规则加载逻辑和 verdict 计算混在一个函数，模块深度看似浅，认知深度却过高。评审问法不是“能否再拆一层”，而是“该层是否只依赖上一层的契约”。Python `dataclasses` 的 frozen 值对象可作为跨层不可变契约，但不能替代接口边界[25]。

**接口即测试面（interface as test surface）要求每个公共接口都有可替换实现和可观察输出。** 应列出 `Lexer`、`Parser`、`CatalogLoader`、`CapabilityEvaluator`、`PolicyEngine`、`Reporter` 的接口、前置条件、后置条件和失败语义，而不是只画架构图。单元测试用内存 catalog，fuzz 用随机 token 生成器，CI 用冻结 fixture，验收用真实方言样本。接口签名必须说明何时返回 unknown、何时抛错、何时永远终止；静态分析讲义要求有限终止，意味着词法器、递归语法分析和规则匹配都应有深度/时间/节点数预算[1]。

**删除测试（deletion test）用于证明规则、分支或适配器是决策的必要来源。** 删除某条 catalog 规则后，相关 positive fixture 的结论必须变化；删除某 seam 的 adapter 后，受影响集成测试必须失败。其价值在于排除“另一个分支恰好给出同一 verdict”的伪覆盖。对未知命令默认，删除默认规则必须使 unknown 命令从 deny 变 error/deny，而非 allow；删除 JSON reporter 必须使 CLI 格式化测试失败。它不能证明规则在所有输入上 sound，但能证明测试 fixture 真正约束了规则。

**seam（接缝）是可在测试中以不同实现替换行为边界的位置，adapter 则是该边界的单向隔离器。** `FileSystem`、clock、`subprocess` 目录校验、policy store、reporter 都应是 seam。即使本工具主打离线零依赖，也可在测试中提供 in-memory adapter；生产 adapter 只调用标准库。adapter 不应把路径、环境、权限等底层细节泄漏给 evaluator。Landlock/seccomp/AppArmor/macOS sandbox 的 adapter 尤其不应让静态判定器假设执行层一定存在；若执行平台不支持，应 fail-closed 或显式要求人工审批。

**locality（局部性）指相关不变量、错误状态和证据尽量存在于一个可检查范围。** 一个 token 对象应携带其 raw value、kind、行/列、解码状态、是否已规范化；一个 capability assertion 应携带 action、object、scope、status 与 evidence。把行号散落在全局 parser state、capability 生成时再重新扫描 source，会制造隐蔽一致性缺陷。locality 不要求把所有逻辑塞进一个类，而是要求“修改语法模型时必须同步更新哪些字段”能由类型与测试明确表达。

**结构评审应产生可关闭的问题，而不是笼统“需要重构”。** 每条问题应包含：模块路径、违反的词汇、触发样本、当前输出、期望输出、是否阻断目录发布。建议门槛包括：任何 `verdict` 由未测试分支计算、任何规则 ID 在多个文件定义、任何错误被吞掉后继续输出 allow、任何 CLI flag 直接访问 catalog 文件、任何 reporter 改变 decision、任何适配器在测试外直接调用真实环境。AppArmor profile 的 header/rules 分离、ABI、attachment 与 enforce/complain 字段可作为评审清单的启发式来源，但不是硬性模板[9]。

## 8. 硬性设计约束：直接写入设计文档的验收条款

1. **令 `AnalysisResult` 对真实执行行为构成保守超集；每条可能调用、写、删除、执行、网络、替换或信息泄露来源要么显式建模，要么以 `unknown`/`opaque` 状态阻止自动放行。**
2. **令 verdict 默认为 deny，且仅当规则显式 allow、目录加载成功、所有输入和规则均通过 schema 校验、无任何 unknown/opaque/error 阻止条件时方可输出 allow；任何异常不得改写为 allow。**
3. **令每个 assertion、token 和语法节点携带原始值及 UTF-8 行列区间，任何人类/机器结论都能追溯到 source span、语法节点 ID、规则 ID 和目录版本。**
4. **令命令目录将 command identity、语义版本、shell dialect、flag 约束、能力断言、严重度、理由与 positive/negative/opaque/error 测试放在同一规则单元，并禁止同名重复 ID、未知字段和无效版本区间。**
5. **令未知命令、未知 flag 语义、动态参数、未闭合引号、命令替换、反引号、变量展开、eval、source、函数和别名统一进入 `unknown`/`opaque` 状态，禁止通过默认值、占位路径或半展开猜测提升为 safe。**
6. **令 catalog schema、catalog digest、policy digest、工具版本与 source digest 进入确定性输出；除显式选择的脱敏模式外，禁止把原始命令或环境发送到外部端点。**
7. **令 `shlex` 只承担受限词法与 raw token 生成，不赋予其完整 shell 语义；所有 `$(...)`、反引号、重定向、控制流和参数语义由自研语法模型显式表示。**
8. **令目录规则通过删除测试证明其必要性，且任何目录变更若无对应测试、或导致已有 deny 变为 allow，均不得自动合并。**
9. **令策略定义、主体/环境绑定和临时例外分别配置并分别签名或摘要化；例外必须包含 owner、reason、scope 和 expiry，且不得修改命令规则本身。**
10. **令该工具仅作为执行前静态判定器，声明自身不可替代运行时强制；真实执行仍须独立的最小权限与系统沙箱机制，并在该层不可用时按配置 fail-closed。**

## 引用来源

[1] https://www.cs.toronto.edu/~chechik/courses06/csc2125/DaveUruguay3.pdf
> “a sound overapproximation describes a superset of the program’s executions (safe descriptions)”

[2] http://wasi.dev/security
> “Code running under WASI has no ambient authority… can only perform operations that the host explicitly grants.”

[3] https://docs.deno.org.cn/runtime/reference/permissions
> “默认情况下，对大多数系统 I/O 的访问是被拒绝的。”

[4] https://docs.python.org/3/library/shlex.html
> “Warning The shlex module is only designed for Unix shells.”

[5] https://kubernetes.io/docs/reference/access-authn-authz/rbac/
> “The RBAC API declares four kinds of Kubernetes object: Role, ClusterRole, RoleBinding and ClusterRoleBinding.”

[6] https://landlock.io/
> “The goal of Landlock is to enable restricting ambient rights… for a set of processes.”

[7] https://docs.python.org/3/library/ast.html
> “Instances of ast.expr and ast.stmt subclasses have lineno, col_offset, end_lineno, and end_col_offset attributes.”

[8] https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
> “System call filtering isn’t a sandbox. It provides a clearly defined mechanism for minimizing the exposed kernel surface.”

[9] https://apparmor.net/profiles/profile-types-and-syntax
> “The Header: Defines the context and application of the profile.”

[10] https://developer.apple.com/cn/documentation/security/app-sandbox?changes=__1&language=objc
> “限制 macOS App 对系统资源和用户数据的访问，以防止 App 受损后造成损害。”

[11] https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox?language=_2
> “A sandboxed app must explicitly state its intent to access a restricted resource… otherwise the system prohibits any attempts.”

[12] https://developer.apple.com/cn/documentation/security/app-sandbox?changes=__1&language=objc
> “App Sandbox Entitlement 一个布尔值，表示当 App 遭到入侵时…是否可以…遏制…损害。”

[13] https://semgrep.dev/docs/writing-rules/rule-syntax/
> “id: Unique, descriptive identifier… severity: Severity can be LOW, MEDIUM, HIGH, or CRITICAL.”

[14] https://opentelemetry.io/docs/specs/semconv/general/attributes/
> “The attributes described in this section are not specific to a particular operation but rather generic.”

[15] https://github.com/github/bash-parser
> “analysis.commandNames… isOpaque… Static analysis cannot see through: dynamic dispatch… command substitution… eval…”

[16] https://docs.npmjs.com/package-scope-access-level-and-visibility
> “Can view and download” and “Can write (publish)” columns indicate permissions…

[17] https://cyclonedx.org/
> “CycloneDX is a modern standard for the software supply chain.”

[18] https://spdx.org/
> “An open standard capable of representing systems with software components in as SBOMs.”

[19] https://slsa.dev/spec/v1.0-rc1/provenance
> “externalParameters: The parameters that are under external control… They MUST be included in the provenance.”

[20] https://open-policy-agent.github.io/opa/documentation/latest/policy-testing/
> “policy-testing… unit tests for Rego policies with opa test”

[21] https://www.shellcheck.net/
> “ShellCheck finds bugs in your shell scripts.”

[22] https://docs.python.org/3/library/tokenize.html
> “The tokenize() generator requires one argument, readline… start: A 2-tuple (srow, scol).”

[23] https://docs.python.org/3/library/tomllib.html
> “Added in version 3.11. This module provides an interface for parsing TOML 1.0.0.”

[24] https://docs.python.org/3/library/argparse.html
> “argparse is the default recommended standard library module for implementing basic command line applications.”

[25] https://docs.python.org/3/library/dataclasses.html
> “frozen: If true… assigning to fields will generate an exception.”

[26] https://docs.python.org/3/library/pathlib.html
> “Pure path objects provide path-handling operations which don’t actually access a filesystem.”

[27] https://docs.python.org/3/library/fnmatch.html
> “Note that the filename separator (‘/’ on Unix) is not special to this module.”

[28] https://docs.python.org/3/library/unicodedata.html
> “unicodedata.normalize(form, unistr)… Valid values… are ‘NFC’, ‘NFKC’, ‘NFD’, and ‘NFKD’.”
