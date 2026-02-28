# ckb-cli 安全审计 TODO

> 版本: v2 | 最后更新: 2026-02-28 | 状态: 已完成

## 项目概况
  - 语言: Rust (Edition 2021)
  - 类型: CLI 工具 / 加密钱包 / 区块链客户端
  - 依赖数: ~65 direct dependencies
  - 源文件数: 69 .rs files
  - 现有测试数: ~16 unit tests + integration tests

## 审计进度
  - 总 TODO 项: 15
  - ✅ 已完成: 15 | ❌ 发现问题: 8 | ⏳ 待审计: 0

---

## 第 1 章: DIM-CRYPTO — 密码学操作

- [x] 🔴 **AUDIT-CRYPTO-001**: MAC 比较使用非恒定时间运算
  - **关联代码**: ckb-signer/src/keystore/passphrase.rs:check_password_inner:337-339
  - **审计内容**:
    - MAC 值与计算结果使用 `==` 进行比较，非恒定时间
    - 是否存在时序侧信道攻击风险
    - scrypt KDF 的延迟是否足以缓解
  - **现有覆盖**: 有 check_password 测试但未测试时序安全性
  - **发现记录**: ❌ 已修复 — 使用 constant_time_eq 替代 `==`

- [x] 🔴 **AUDIT-CRYPTO-002**: 密钥材料中间变量未清零
  - **关联代码**: ckb-signer/src/keystore/mod.rs:Key::from_json:771-773, Key::to_json:788
  - **审计内容**:
    - `Key::from_json` 中 `key_vec` (Vec<u8>) 包含解密后私钥，Drop 后堆内存未清零
    - `Key::to_json` 中 `master_privkey` 返回的 `[u8; 64]` 包含原始私钥
    - `Crypto::decrypt` 返回的 Vec<u8> 的堆内存何时被回收和清除
  - **现有覆盖**: 无
  - **发现记录**: ❌ 已修复 — 在 from_json 和 to_json 中使用后调用 zeroize_slice

- [x] 🟠 **AUDIT-CRYPTO-003**: KDF 参数从 JSON 解析时的安全性
  - **关联代码**: ckb-signer/src/keystore/passphrase.rs:ScryptParams::from_json:99-130
  - **审计内容**:
    - 从 JSON 解析的 scrypt 参数 (N, r, p) 是否可以被攻击者控制以触发 DoS
    - 极大的 N/r/p 值是否会导致 OOM
    - log_n 的 u8 转换是否安全
  - **现有覆盖**: 无
  - **发现记录**: ⚠️ 建议改进 — log_n 是 u8 类型，N 最大为 2^255，足够大可能造成 OOM。scrypt crate 内部有参数校验，但极端值（如 log_n=30）可消耗大量内存。建议设置合理上限。

- [x] 🟠 **AUDIT-CRYPTO-004**: AES-128-CTR IV 重用风险
  - **关联代码**: ckb-signer/src/keystore/passphrase.rs:CipherParams::default:267-271
  - **审计内容**:
    - IV 由 `rand::thread_rng().gen()` 生成，是否为 CSPRNG
    - 同一密钥下 IV 是否可能重复
    - rand 0.7 的 thread_rng 是否使用系统级 CSPRNG
  - **现有覆盖**: 无
  - **发现记录**: ✅ 通过 — rand 0.7 的 thread_rng() 使用 ChaCha20 CSPRNG。每次加密都重新生成 salt 和 IV，且使用 scrypt 派生不同的加密密钥，IV 重用风险极低。

- [x] 🟡 **AUDIT-CRYPTO-005**: MasterPrivKey 和 PrivkeyWrapper 的 Clone 实现
  - **关联代码**: ckb-signer/src/keystore/mod.rs:802, src/utils/arg_parser.rs:266
  - **审计内容**:
    - `#[derive(Clone)]` 在包含私钥的结构体上
    - 分析所有 clone 调用点，评估泄露风险
    - MasterPrivKey 有 Drop impl 但 Clone 出的副本也会执行 Drop
  - **现有覆盖**: 无
  - **发现记录**: ⚠️ 建议改进 — Clone 导出的副本在 Drop 时会调用 zeroize_privkey，因此不会泄露到内存。但 Clone 增加了攻击面——越多副本，越多时间窗口。MasterPrivKey 的 Clone 是功能需要的（keystore 操作），当前实现可接受但建议减少不必要的 clone 调用。

---

## 第 2 章: DIM-INPUT — 输入验证

- [x] 🟠 **AUDIT-INPUT-001**: CLI 参数中的 unwrap/expect 使用
  - **关联代码**: src/main.rs:69,84,117
  - **审计内容**:
    - `dirs::home_dir().unwrap()` — home 目录不存在时 panic
    - `serde_json::from_str(content.as_str()).unwrap()` — 配置文件损坏时 panic
    - `PluginManager::init(&ckb_cli_dir, ckb_url).unwrap()` — 插件加载失败时 panic
  - **现有覆盖**: 无
  - **发现记录**: ⚠️ 建议改进 — 这些 unwrap 调用可导致用户遇到不友好的 panic 错误。对于 CLI 工具，建议将这些转为优雅的错误消息。当前不构成安全漏洞但影响可用性和可靠性。

- [x] 🟡 **AUDIT-INPUT-002**: 文件路径输入的路径穿越
  - **关联代码**: src/utils/arg_parser.rs:PrivkeyPathParser:296-313, HexFilePathParser:286-292
  - **审计内容**:
    - FilePathParser 验证文件存在但未规范化路径
    - 是否可以通过 `../` 或符号链接读取任意文件
  - **现有覆盖**: 无
  - **发现记录**: ✅ 通过 — 作为 CLI 工具，用户已拥有本地文件系统权限，路径穿越不构成额外威胁。用户本身就可以读取这些文件。

- [x] 🟡 **AUDIT-INPUT-003**: DurationParser 边界值处理
  - **关联代码**: src/utils/arg_parser.rs:DurationParser:542-564
  - **审计内容**:
    - 超大数值乘法是否可能导致整数溢出 (u64)
    - 例如 `18446744073709551615d` 会导致 `value * 86400` 溢出
  - **现有覆盖**: 无
  - **发现记录**: ❌ 已修复 — 使用 checked_mul 替代直接乘法，溢出时返回错误

---

## 第 3 章: DIM-MEMORY — 内存与资源安全

- [x] 🟡 **AUDIT-MEMORY-001**: unsafe String::from_utf8_unchecked 使用
  - **关联代码**: src/utils/json_color.rs:166
  - **审计内容**:
    - 输入数据来自 serde_json 序列化，JSON 输出保证为有效 UTF-8
    - 是否存在 serde_json 输出非 UTF-8 的边界情况
  - **现有覆盖**: 无
  - **发现记录**: ✅ 通过 — serde_json 序列化保证输出有效 UTF-8，unsafe 使用是安全的。

- [x] 🟢 **AUDIT-MEMORY-002**: 密码在内存中的生命周期
  - **关联代码**: src/utils/other.rs:read_password:41-53, src/utils/signer.rs:149-151
  - **审计内容**:
    - 密码字符串 (String) 存储在堆上，Drop 后不清零
    - KeyStoreHandlerSigner::passwords HashMap 持有密码
  - **现有覆盖**: 无
  - **发现记录**: ⚠️ 建议改进 — 密码以 String 形式持有，Drop 时不会清零堆内存。建议使用 secrecy crate 的 SecretString 包装密码。当前风险较低因为内存需要其他漏洞才能读取。

---

## 第 4 章: DIM-ERRINFO — 错误处理与信息泄露

- [x] 🟡 **AUDIT-ERRINFO-001**: 错误信息中的敏感数据泄露
  - **关联代码**: src/utils/other.rs:108-112
  - **审计内容**:
    - 签名错误信息泄露原始签名数据 `data: {:?}`
    - Error 类型暴露内部 hash160 值
  - **现有覆盖**: 无
  - **发现记录**: ❌ 已修复 — 移除了错误消息中的原始签名数据输出

---

## 第 5 章: DIM-LOGIC — 业务逻辑

- [x] 🟠 **AUDIT-LOGIC-001**: API Server 的 CORS 配置
  - **关联代码**: src/subcommands/api_server.rs:124-128
  - **审计内容**:
    - CORS 设置为 `AccessControlAllowOrigin::Any`
    - API 无认证机制
    - 转账等敏感操作通过 API 暴露
  - **现有覆盖**: 无
  - **发现记录**: ⚠️ 建议改进 — CORS 配置过于宽松，但 API Server 默认绑定 127.0.0.1 且使用 privkey-path 时强制本地监听。主要风险来自本地浏览器 CSRF 攻击。建议限制 CORS 为 Null only 或特定域名。

- [x] 🟡 **AUDIT-LOGIC-002**: 插件系统安全
  - **关联代码**: src/plugin/manager.rs:60-97
  - **审计内容**:
    - 插件以子进程方式运行，无沙箱
    - 无插件二进制签名验证
    - 插件可接收敏感密钥数据
  - **现有覆盖**: 有集成测试
  - **发现记录**: ⚠️ 建议改进 — 插件系统信任模型是隐式信任。用户手动安装插件到 plugins 目录。建议添加插件签名验证或至少在安装时提示用户确认。当前设计中，恶意插件可完全控制密钥操作。

---

## 第 6 章: DIM-DEPS — 依赖安全

- [x] 🟡 **AUDIT-DEPS-001**: 已知 CVE 和过时依赖
  - **关联代码**: Cargo.toml, ckb-signer/Cargo.toml
  - **审计内容**: 检查核心加密和安全依赖
  - **现有覆盖**: deny.toml 存在
  - **发现记录**: ⚠️ 建议改进 — 多个依赖版本较旧但未发现关键 CVE：rand 0.7 (无已知安全漏洞), aes-ctr 0.6 (API 差异，无安全漏洞), tiny-keccak 1.4/1.5 (无已知漏洞), scrypt 0.2 (功能正常), uuid 0.7 (无安全影响)。建议定期运行 cargo audit。

---

## 附录 A: 审计执行日志
| 日期 | 审计项 | 发现摘要 | 状态 |
|------|--------|---------|------|
| 2026-02-28 | CRYPTO-001 | 非恒定时间 MAC 比较 | ❌ 已修复 |
| 2026-02-28 | CRYPTO-002 | 密钥材料未清零 | ❌ 已修复 |
| 2026-02-28 | CRYPTO-003 | KDF 参数无上限 | ⚠️ 建议改进 |
| 2026-02-28 | CRYPTO-004 | AES-CTR IV 安全性 | ✅ 通过 |
| 2026-02-28 | CRYPTO-005 | 私钥类型 Clone | ⚠️ 建议改进 |
| 2026-02-28 | INPUT-001 | unwrap 导致 panic | ⚠️ 建议改进 |
| 2026-02-28 | INPUT-002 | 路径穿越 | ✅ 通过 |
| 2026-02-28 | INPUT-003 | 整数溢出 | ❌ 已修复 |
| 2026-02-28 | MEMORY-001 | unsafe 使用 | ✅ 通过 |
| 2026-02-28 | MEMORY-002 | 密码生命周期 | ⚠️ 建议改进 |
| 2026-02-28 | ERRINFO-001 | 信息泄露 | ❌ 已修复 |
| 2026-02-28 | LOGIC-001 | CORS 配置 | ⚠️ 建议改进 |
| 2026-02-28 | LOGIC-002 | 插件安全 | ⚠️ 建议改进 |
| 2026-02-28 | DEPS-001 | 依赖安全 | ⚠️ 建议改进 |

## 附录 B: 新增项跟踪
| 日期 | 新增项 ID | 来源 | 描述 |
|------|----------|------|------|
| (无新增) | | | |

## 附录 C: 修复建议
| 审计项 | 严重级别 | 建议方案 | 修复状态 |
|--------|---------|---------|---------|
| CRYPTO-001 | P0-Critical | 使用恒定时间比较 | ✅ 已修复 |
| CRYPTO-002 | P0-Critical | 调用 zeroize_slice | ✅ 已修复 |
| CRYPTO-003 | P1-High | 添加 scrypt 参数上限验证 | 待修复 |
| INPUT-003 | P1-High | 使用 checked_mul | ✅ 已修复 |
| ERRINFO-001 | P1-High | 移除敏感数据输出 | ✅ 已修复 |
| LOGIC-001 | P1-High | 限制 CORS 配置 | 待修复 |
| INPUT-001 | P2-Medium | 替换 unwrap 为错误处理 | 待修复 |
| MEMORY-002 | P3-Low | 使用 SecretString | 待修复 |
| CRYPTO-005 | P3-Low | 减少不必要的 Clone | 待修复 |
| LOGIC-002 | P2-Medium | 添加插件签名验证 | 待修复 |
| DEPS-001 | P3-Low | 定期 cargo audit | 待修复 |
