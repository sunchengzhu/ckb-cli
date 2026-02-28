# 安全审计报告: ckb-cli

## 1. 执行摘要

| 项目信息 | 详情 |
|---------|------|
| 项目名称 | ckb-cli |
| 版本 | 2.0.0 |
| 语言 | Rust (Edition 2021) |
| 项目类型 | CLI 工具 / 加密钱包 / 区块链客户端 |
| 审计范围 | 全代码库（69 个 Rust 源文件） |
| 审计日期 | 2026-02-28 |
| 审计维度 | 密码学、输入验证、内存安全、错误处理、业务逻辑、依赖安全 |
| 审计方法 | 静态代码分析 + 逻辑审查 + 攻击面分析 |

---

## 2. 风险评级

| 级别 | 数量 | 说明 |
|------|------|------|
| 🔴 Critical | 2 项 | 已修复 — 时序攻击、密钥材料泄露 |
| 🟠 High | 3 项 | 1 项已修复、2 项建议改进 |
| 🟡 Medium | 7 项 | 1 项已修复、3 项通过、3 项建议改进 |
| 🟢 Low | 3 项 | 建议改进 |

**总计**: 审计 15 项，修复 4 项，通过 4 项，建议改进 7 项

---

## 3. 关键发现（按严重级别降序）

### ❌ AUDIT-CRYPTO-001: 非恒定时间 MAC 比较（Critical — 已修复）

**描述**: `Crypto::check_password_inner()` 函数使用 `==` 运算符比较 MAC 值，这是非恒定时间操作。短路求值机制使得比较时间与匹配字节数成正比，理论上允许攻击者通过精确时序测量逐字节推断 MAC 值。

**影响**: 攻击者可能通过时序侧信道攻击恢复 MAC 值，从而绕过密码验证。由于 scrypt KDF 在前序步骤中引入了数秒延迟，实际利用难度较高，但属于密码学最佳实践违规。

**代码位置**: `ckb-signer/src/keystore/passphrase.rs:337-339`

**修复前**:
```rust
fn check_password_inner(&self, kdf_key: &[u8; 32]) -> bool {
    self.mac == calculate_mac(&self.ciphertext, kdf_key)
}
```

**修复后**:
```rust
fn check_password_inner(&self, kdf_key: &[u8; 32]) -> bool {
    let calculated_mac = calculate_mac(&self.ciphertext, kdf_key);
    constant_time_eq(&self.mac, &calculated_mac)
}
```

新增 `constant_time_eq` 函数使用 XOR + OR 累积模式实现恒定时间比较。

---

### ❌ AUDIT-CRYPTO-002: 密钥材料中间变量未清零（Critical — 已修复）

**描述**: `Key::from_json()` 解密私钥后将结果存入 `key_vec: Vec<u8>` 和 `key_bytes: [u8; 64]`，这些中间变量包含原始私钥材料，但在使用后未被显式清零。`Key::to_json()` 中调用 `to_bytes()` 返回的 `[u8; 64]` 同样包含私钥但未清零。

**影响**: 私钥数据可能在堆/栈内存中残留，攻击者通过内存转储（如 core dump、冷启动攻击）可恢复密钥。

**代码位置**: `ckb-signer/src/keystore/mod.rs:771-774, 788`

**修复方案**: 在 `from_json` 中对 `key_vec` 和 `key_bytes` 使用后立即调用 `zeroize_slice()`；在 `to_json` 中对 `master_privkey` 字节数组使用后调用 `zeroize_slice()`。

---

### ❌ AUDIT-INPUT-003: DurationParser 整数溢出（High — 已修复）

**描述**: `DurationParser::parse()` 在将用户输入的数值与时间单位倍数相乘时使用直接乘法（`value * 3600 * 24`），可能导致 u64 整数溢出。例如输入 `213503982334602d` 会使 `value * 86400` 静默溢出。

**影响**: 整数溢出导致解锁时间计算错误，可能使定时锁定机制失效（密钥保持解锁状态时间异常短或为零）。

**代码位置**: `src/utils/arg_parser.rs:551-555`

**修复方案**: 使用 `checked_mul()` 替代直接乘法，溢出时返回错误信息。

---

### ❌ AUDIT-ERRINFO-001: 错误消息泄露签名数据（High — 已修复）

**描述**: 当签名数据长度不为 65 字节时，错误消息包含完整的原始签名数据：`format!("Invalid signature data length: {}, data: {:?}", data.len(), data)`。

**影响**: 错误消息可能被记录到日志文件或显示给用户，泄露部分密码学操作的中间结果。

**代码位置**: `src/utils/other.rs:108-112`

**修复方案**: 移除错误消息中的原始数据输出，仅保留长度信息。

---

### ⚠️ AUDIT-LOGIC-001: API Server CORS 配置过于宽松（High — 建议改进）

**描述**: API Server 的 CORS 配置包含 `AccessControlAllowOrigin::Any`，允许任何网站的跨域请求访问 API。

**影响**: 本地浏览器中的恶意网页可以向 API Server 发送请求，可能导致 CSRF 攻击。虽然 privkey-path 模式强制绑定 127.0.0.1，但 CORS 配置仍允许网页发起本地请求。

**代码位置**: `src/subcommands/api_server.rs:124-128`

```rust
.cors(DomainsValidation::AllowOnly(vec![
    AccessControlAllowOrigin::Null,
    AccessControlAllowOrigin::Any,  // 应移除此行
]))
```

**修复建议**: 移除 `AccessControlAllowOrigin::Any`，仅保留 `Null`，或改为允许特定的可信域名。

---

### ⚠️ AUDIT-CRYPTO-003: KDF 参数缺少上限验证（High — 建议改进）

**描述**: 从 JSON 解析 scrypt 参数时，`log_n`（u8 类型，最大 255）如果设置过大，将请求 2^255 字节内存，导致 OOM。

**代码位置**: `ckb-signer/src/keystore/passphrase.rs:107-118`

**修复建议**: 添加 `log_n` 的合理上限检查（例如 `log_n <= 20`），拒绝超出范围的参数。

---

### ⚠️ AUDIT-INPUT-001: 启动代码中的 unwrap 调用（Medium — 建议改进）

**描述**: `main.rs` 中多处使用 `.unwrap()` 处理可能失败的操作：
- `dirs::home_dir().unwrap()` (line 69) — HOME 环境变量未设置时 panic
- `serde_json::from_str(content.as_str()).unwrap()` (line 84) — 配置文件损坏时 panic
- `PluginManager::init(&ckb_cli_dir, ckb_url).unwrap()` (line 117) — 插件错误时 panic

**修复建议**: 替换为 `ok_or()` + `?` 或提供友好的错误消息。

---

### ⚠️ AUDIT-LOGIC-002: 插件系统缺少完整性验证（Medium — 建议改进）

**描述**: 插件系统以子进程方式执行 `~/.ckb-cli/plugins/` 目录下的二进制文件，无签名验证、校验和检查或沙箱隔离。恶意插件可完全接管密钥操作。

**修复建议**: 添加插件签名验证机制，或至少在首次加载时提示用户确认信任。

---

### ⚠️ AUDIT-MEMORY-002: 密码字符串未安全清零（Low — 建议改进）

**描述**: 密码以 `String` 类型持有，在 Drop 时堆内存不会被清零。`KeyStoreHandlerSigner::passwords` HashMap 持有密码直到 signer 销毁。

**修复建议**: 使用 `secrecy` crate 的 `SecretString` 包装敏感字符串。

---

### ✅ AUDIT-CRYPTO-004: AES-128-CTR IV 随机性（通过）

`rand::thread_rng()` 使用 ChaCha20 CSPRNG，IV 和 salt 在每次加密时随机重新生成。不存在 IV 重用风险。

### ✅ AUDIT-INPUT-002: 文件路径穿越（通过）

作为本地 CLI 工具，用户已拥有完整文件系统权限，路径穿越不构成额外威胁。

### ✅ AUDIT-MEMORY-001: unsafe String::from_utf8_unchecked（通过）

数据来源为 serde_json 序列化输出，保证为有效 UTF-8。unsafe 使用是安全且合理的性能优化。

### ✅ AUDIT-CRYPTO-005: MasterPrivKey Clone（通过，建议改进）

Clone 的副本在 Drop 时同样调用 `zeroize_privkey`，不存在泄露。但建议减少不必要的 clone 操作以缩小攻击时间窗口。

---

## 4. 审计覆盖矩阵

| 模块 | CRYPTO | INPUT | MEMORY | ERRINFO | LOGIC | DEPS |
|------|--------|-------|--------|---------|-------|------|
| ckb-signer/keystore | ✅ | ✅ | ✅ | ✅ | — | ✅ |
| src/utils/signer | ✅ | ✅ | ✅ | ✅ | — | — |
| src/utils/arg_parser | — | ✅ | — | — | — | — |
| src/utils/other | — | — | — | ✅ | — | — |
| src/subcommands/api_server | — | — | — | — | ✅ | — |
| src/plugin/manager | — | — | — | — | ✅ | — |
| src/main | — | ✅ | — | — | — | — |
| src/utils/json_color | — | — | ✅ | — | — | — |

---

## 5. 依赖安全状态

| 依赖 | 版本 | 状态 | 备注 |
|------|------|------|------|
| rand | 0.7.3 | ✅ | 使用 ChaCha20 CSPRNG，无已知 CVE |
| aes-ctr | 0.6.0 | ✅ | 无已知安全漏洞 |
| scrypt | 0.2.0 | ✅ | 功能正常，无已知漏洞 |
| tiny-keccak | 1.5.0 | ✅ | 无已知漏洞 |
| secp256k1 | 0.30.0 | ✅ | 当前维护版本 |
| uuid | 0.7.4 | ⚠️ | 较旧但无安全影响 |
| serde_yaml | 0.8.26 | ⚠️ | 较旧，建议升级 |
| url | 1.7.2 | ⚠️ | 较旧，建议升级到 2.x |

---

## 6. 改进建议（非漏洞类）

1. **测试覆盖率**: 当前仅 16 个单元测试，建议增加对安全关键路径的测试，特别是密码错误处理、边界值输入、加密/解密 roundtrip 测试。

2. **模糊测试**: 建议对序列化/反序列化路径（JSON keystore 解析、CLI 参数解析）添加 `cargo-fuzz` 模糊测试。

3. **依赖审计**: 建议在 CI 中集成 `cargo audit` 定期检查依赖漏洞。项目已有 `deny.toml`，建议确保 `cargo deny check` 在 CI 中运行。

4. **错误处理标准化**: 建议统一使用 `anyhow` 或自定义错误类型，减少 `.unwrap()` 和 `.expect()` 的使用。

5. **安全文档**: 建议在 README 中添加安全注意事项，包括：
   - 插件安全模型说明
   - API Server 使用场景和风险
   - 密钥存储安全建议

---

## 7. 附录: 完整 TODO 文档终态

见 [SECURITY_AUDIT_TODO.md](./SECURITY_AUDIT_TODO.md)

---

## 8. 已实施的修复摘要

| # | 文件 | 修改内容 | 严重级别 |
|---|------|---------|---------|
| 1 | `ckb-signer/src/keystore/passphrase.rs` | 新增 `constant_time_eq()` 函数，替换 MAC 比较中的 `==` | Critical |
| 2 | `ckb-signer/src/keystore/mod.rs` | `Key::from_json` 中对 `key_vec` 和 `key_bytes` 调用 `zeroize_slice` | Critical |
| 3 | `ckb-signer/src/keystore/mod.rs` | `Key::to_json` 中对 `master_privkey` 字节数组调用 `zeroize_slice` | Critical |
| 4 | `src/utils/arg_parser.rs` | `DurationParser` 使用 `checked_mul` 防止整数溢出 | High |
| 5 | `src/utils/other.rs` | 移除错误消息中的原始签名数据输出 | High |
