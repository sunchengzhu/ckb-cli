# ckb-cli 安全审计 TODO

> 版本: v1 | 最后更新: 2026-02-28 | 状态: 进行中

## 项目概况
  - 语言: Rust (Edition 2021)
  - 类型: CLI 工具 / 加密钱包 / 区块链客户端
  - 依赖数: ~65 direct dependencies
  - 源文件数: 69 .rs files
  - 现有测试数: ~16 unit tests + integration tests

## 审计进度
  - 总 TODO 项: 15
  - ✅ 已完成: 0 | ❌ 发现问题: 0 | ⏳ 待审计: 15

---

## 第 1 章: DIM-CRYPTO — 密码学操作

- [ ] 🔴 **AUDIT-CRYPTO-001**: MAC 比较使用非恒定时间运算
  - **关联代码**: ckb-signer/src/keystore/passphrase.rs:check_password_inner:337-339
  - **审计内容**:
    - MAC 值与计算结果使用 `==` 进行比较，非恒定时间
    - 是否存在时序侧信道攻击风险
    - scrypt KDF 的延迟是否足以缓解
  - **现有覆盖**: 有 check_password 测试但未测试时序安全性
  - **发现记录**: （审计完成后填写）

- [ ] 🔴 **AUDIT-CRYPTO-002**: 密钥材料中间变量未清零
  - **关联代码**: ckb-signer/src/keystore/mod.rs:Key::from_json:771-773, Key::to_json:788
  - **审计内容**:
    - `Key::from_json` 中 `key_vec` (Vec<u8>) 包含解密后私钥，Drop 后堆内存未清零
    - `Key::to_json` 中 `master_privkey` 返回的 `[u8; 64]` 包含原始私钥，函数返回后栈帧未清零
    - `Crypto::decrypt` 返回的 Vec<u8> 的堆内存何时被回收和清除
  - **现有覆盖**: 无
  - **发现记录**: （审计完成后填写）

- [ ] 🟠 **AUDIT-CRYPTO-003**: KDF 参数从 JSON 解析时的安全性
  - **关联代码**: ckb-signer/src/keystore/passphrase.rs:ScryptParams::from_json:99-130
  - **审计内容**:
    - 从 JSON 解析的 scrypt 参数 (N, r, p) 是否可以被攻击者控制以触发 DoS
    - 极大的 N/r/p 值是否会导致 OOM
    - log_n 的 u8 转换是否安全
  - **现有覆盖**: 无
  - **发现记录**: （审计完成后填写）

- [ ] 🟠 **AUDIT-CRYPTO-004**: AES-128-CTR IV 重用风险
  - **关联代码**: ckb-signer/src/keystore/passphrase.rs:CipherParams::default:267-271
  - **审计内容**:
    - IV 由 `rand::thread_rng().gen()` 生成，是否为 CSPRNG
    - 同一密钥下 IV 是否可能重复 (更换密码时 salt+IV 都随机重新生成)
    - rand 0.7 的 thread_rng 是否使用系统级 CSPRNG
  - **现有覆盖**: 无
  - **发现记录**: （审计完成后填写）

- [ ] 🟡 **AUDIT-CRYPTO-005**: MasterPrivKey 和 PrivkeyWrapper 的 Clone 实现
  - **关联代码**: ckb-signer/src/keystore/mod.rs:802, src/utils/arg_parser.rs:266
  - **审计内容**:
    - `#[derive(Clone)]` 在包含私钥的结构体上，克隆的副本可能不会被正确清零
    - 分析所有 clone 调用点，评估泄露风险
    - MasterPrivKey 有 Drop impl 但 Clone 出的副本也会执行 Drop
  - **现有覆盖**: 无
  - **发现记录**: （审计完成后填写）

---

## 第 2 章: DIM-INPUT — 输入验证

- [ ] 🟠 **AUDIT-INPUT-001**: CLI 参数中的 unwrap/expect 使用
  - **关联代码**: src/subcommands/account.rs, src/main.rs
  - **审计内容**:
    - 用户输入触发的 unwrap()/expect() 是否可导致 panic
    - 特别关注 `dirs::home_dir().unwrap()` 和 JSON 解析的 unwrap
    - serde_json::from_str(...).unwrap() 在配置文件损坏时的行为
  - **现有覆盖**: 部分 (arg_parser 有测试)
  - **发现记录**: （审计完成后填写）

- [ ] 🟡 **AUDIT-INPUT-002**: 文件路径输入的路径穿越
  - **关联代码**: src/utils/arg_parser.rs:PrivkeyPathParser:296-313, HexFilePathParser:286-292
  - **审计内容**:
    - FilePathParser 验证文件存在但未规范化路径
    - 是否可以通过 `../` 或符号链接读取任意文件
    - 对于 CLI 工具，用户已有本地权限，路径穿越风险较低
  - **现有覆盖**: 无
  - **发现记录**: （审计完成后填写）

- [ ] 🟡 **AUDIT-INPUT-003**: DurationParser 边界值处理
  - **关联代码**: src/utils/arg_parser.rs:DurationParser:542-564
  - **审计内容**:
    - 单字符输入 (如 "s") 的解析行为 — value_part 为空字符串
    - 超大数值乘法是否可能导致整数溢出 (u64)
    - 空字符串输入已有检查
  - **现有覆盖**: 无
  - **发现记录**: （审计完成后填写）

---

## 第 3 章: DIM-MEMORY — 内存与资源安全

- [ ] 🟡 **AUDIT-MEMORY-001**: unsafe String::from_utf8_unchecked 使用
  - **关联代码**: src/utils/json_color.rs:166
  - **审计内容**:
    - 输入数据来自 serde_json 序列化，JSON 输出保证为有效 UTF-8
    - 是否存在 serde_json 输出非 UTF-8 的边界情况
    - 安全性评估：数据来源可信
  - **现有覆盖**: 无
  - **发现记录**: （审计完成后填写）

- [ ] 🟢 **AUDIT-MEMORY-002**: 密码在内存中的生命周期
  - **关联代码**: src/utils/other.rs:read_password:41-53, src/utils/signer.rs:149-151
  - **审计内容**:
    - 密码字符串 (String) 存储在堆上，Drop 后不清零
    - KeyStoreHandlerSigner::passwords HashMap 持有密码直到 signer 被销毁
    - rpassword 读取密码后的内存处理
  - **现有覆盖**: 无
  - **发现记录**: （审计完成后填写）

---

## 第 4 章: DIM-ERRINFO — 错误处理与信息泄露

- [ ] 🟡 **AUDIT-ERRINFO-001**: 错误信息中的敏感数据泄露
  - **关联代码**: ckb-signer/src/keystore/error.rs, src/utils/other.rs
  - **审计内容**:
    - `Error::WrongPassword(H160)` 泄露了账户 hash160
    - `Error::KeyMismatch` 泄露了期望的和实际的 hash160
    - 签名数据长度错误时泄露原始数据: `format!("Invalid signature data length: {}, data: {:?}", data.len(), data)` (src/utils/other.rs:109-111)
  - **现有覆盖**: 无
  - **发现记录**: （审计完成后填写）

---

## 第 5 章: DIM-LOGIC — 业务逻辑

- [ ] 🟠 **AUDIT-LOGIC-001**: API Server 的访问控制
  - **关联代码**: src/subcommands/api_server.rs:72-77
  - **审计内容**:
    - 当 privkey-path 提供时，已强制 listen IP 为 127.0.0.1
    - CORS 设置是否安全
    - 无 privkey 时的 API Server 暴露范围
  - **现有覆盖**: 无
  - **发现记录**: （审计完成后填写）

- [ ] 🟡 **AUDIT-LOGIC-002**: 插件系统安全
  - **关联代码**: src/plugin/manager.rs:60-97
  - **审计内容**:
    - 插件以子进程方式运行，通过 stdin/stdout JSON-RPC 通信
    - 插件配置验证是否充分
    - 插件是否可能篡改 keystore 操作
    - 恶意插件的影响范围
  - **现有覆盖**: 有集成测试
  - **发现记录**: （审计完成后填写）

---

## 第 6 章: DIM-DEPS — 依赖安全

- [ ] 🟡 **AUDIT-DEPS-001**: 已知 CVE 和过时依赖
  - **关联代码**: Cargo.toml, ckb-signer/Cargo.toml
  - **审计内容**:
    - rand 0.7 是否有已知漏洞
    - url 1.7.2 是否有已知漏洞
    - aes-ctr 0.6.0 是否有已知漏洞
    - tiny-keccak 1.4 是否有已知漏洞
    - serde_yaml 0.8.23 是否有已知漏洞
    - uuid 0.7.4 是否有已知漏洞
  - **现有覆盖**: deny.toml 存在
  - **发现记录**: （审计完成后填写）

---

## 附录 A: 审计执行日志
| 日期 | 审计项 | 发现摘要 | 状态 |
|------|--------|---------|------|

## 附录 B: 新增项跟踪
| 日期 | 新增项 ID | 来源 | 描述 |
|------|----------|------|------|

## 附录 C: 修复建议
| 审计项 | 严重级别 | 建议方案 | 修复状态 |
|--------|---------|---------|---------|
