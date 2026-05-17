# PacketScope Architecture

本文件记录贯穿整个仓库的**架构约定**——review 反复纠正同类问题后总结的边界划分。
新写代码 / review 时按此对照，可以避免大半重复 finding。

详细的"Android 平台陷阱"清单见 [`ANDROID_PITFALLS.md`](ANDROID_PITFALLS.md)。

---

## 1. 包结构 / 模块边界

```
io.github.packetscope
├── core/                      ← 纯 Kotlin，不依赖 Android SDK
│   ├── pcap/                  ← PCAP 文件 / Frame / Layer / Field 模型 + 协议名常量
│   │   ├── Protocols          ← 协议名常量
│   │   ├── FieldNames         ← 字段名常量（dissector 产出端 + 消费端都用）
│   │   └── ...
│   ├── dissector/             ← 协议解析器；sealed NextStep 表达"下一步"
│   ├── analysis/              ← TCP 会话 / Conversation 等 post-processing pass
│   ├── decrypt/               ← TLS 1.3 keylog 消费 + 解密
│   ├── extension/             ← PCAPdroid trailer 解析
│   ├── filter/                ← 过滤表达式 AST / parser / 索引
│   │   ├── FilterParseError   ← sealed 错误类型，core 不持有 user-facing 字符串
│   │   └── FilterIndex        ← per-frame 预算索引
│   └── stream/                ← UDP Exporter 监听（co-routines flow）
├── service/                   ← Android Service
└── ui/                        ← Compose UI + ContentResolver / 资源相关代码
    ├── PcapLoader             ← UI 层入口，接 Context 拿资源 + ContentResolver
    └── screen/                ← Composable
```

**分层规则**：

- `core/*` 不能 import `android.*`（fakes / Robolectric 例外）—— 保证纯 Kotlin 可单测
- `service/*` / `ui/*` 可以 import `core/*` 和 `android.*`
- `ui/screen/*` 内部不直接读 R.string，通过 `stringResource(R.string.xxx)` 或
  `pluralStringResource`；非 Composable（Service、PcapLoader）通过 `Context.getString`

---

## 2. 三条核心约定

### 2.1 i18n：core 不持有 user-facing 字符串

凡是会被显示给用户的文本，**core 层不持有**。core 抛 sealed error / 返回错误码，
UI 层做 locale 映射。

**正例**（[`FilterParser`](app/src/main/java/io/github/packetscope/core/filter/FilterParser.kt) +
[`FilterParseError`](app/src/main/java/io/github/packetscope/core/filter/FilterParseError.kt)）：

```kotlin
// core 层
sealed interface FilterParseError {
    data object MissingRightParen : FilterParseError
    data class PortOutOfRange(val port: Int) : FilterParseError
    // ...
}
class FilterParseException(val error: FilterParseError) : RuntimeException(error.toString())

// UI 层
@Composable
private fun filterErrorMessage(err: FilterParseError): String = when (err) {
    is FilterParseError.MissingRightParen -> stringResource(R.string.filter_error_missing_right_paren)
    is FilterParseError.PortOutOfRange -> stringResource(R.string.filter_error_port_out_of_range, err.port)
    // ...
}
```

**反例**（不要这样）：

```kotlin
// core 层抛中文，UI 直接 e.message —— 切到英语 locale 时仍显示中文
throw FilterParseException("端口超出 0-65535: $port")
```

**例外**：`PcapLoader` 在 `ui/` 包下（不是 core），可以直接接 `Context.getString`。

---

### 2.2 错误处理：sealed 类型 / 错误码而非自由 message

用户可见的错误必须**类型化**：

- 不同错误用不同 sealed variant（带必要参数）
- `Exception.message` 退到 toString，**仅供开发者诊断**
- UI 层 when-over-sealed 映射到 `stringResource`
- 测试断言 `e.error is X.Y`，**不**断言 `e.message.contains("xxx")`（脆，随
  翻译变化破裂）

参考 `FilterParseError` 实现。

---

### 2.3 Type-driven 表达不变量

互斥状态 / 协议 API 返回值用 sealed，让编译器替你守约定，不靠注释 / 注意。

**正例**（[`NextStep`](app/src/main/java/io/github/packetscope/core/dissector/Dissector.kt)）：

```kotlin
// 互斥状态：要么继续 dissect 下一层，要么已经预 dissect 完毕，要么链结束
sealed interface NextStep {
    data class Continue(val offset: Int, val dissector: Dissector) : NextStep
    data class Prefetched(val result: DissectResult) : NextStep
    data object Done : NextStep
}
```

**反例**：两个可空字段并存（"哪个非空才算下一步？"）。

---

## 3. 常量收敛

### 协议名（`Protocols`）
所有 `layer.protocol` 值都从 [`Protocols`](app/src/main/java/io/github/packetscope/core/pcap/Protocols.kt) 取。
新增协议在此加一行常量。

### 字段名（`FieldNames`）
所有 `Field.name`（dissector 产出端 + filter/analyzer 消费端）都从
[`FieldNames`](app/src/main/java/io/github/packetscope/core/pcap/FieldNames.kt) 取。
**两端同步用**，避免单向同步导致改一端另一端默默失效。

`KeyLogStoreTest` / `FieldNames` 守约定测试（见
`app/src/test/java/io/github/packetscope/core/pcap/FieldNamesUsageTest.kt`，
若未来实现）扫源码强制 `Field("...", ...)` 第一参数都在 `FieldNames` 集合里。

### 资源 keys（`strings.xml`）
按 prefix 分组：`app_*` / `action_*` / `dialog_*` / `status_*` / `hint_*` /
`error_*` / `header_*` / `filter_*` / `notif_*` / `conv_*` / `nav_*`。
分组说明写在 [values/strings.xml](app/src/main/res/values/strings.xml) 头注释。
values + values-zh **key 必须一一对应**。

### Plurals
凡计数 → 必须 plurals（"1 packet" / "5 packets"）：
`count_packets` / `count_bytes` / `count_characters` / `count_sessions` /
`count_session_keys_loaded` / `count_packets_received`。
中文只写 `quantity="other"`，英文写 `one` + `other`。

---

## 4. 性能约定（filter / dissector 路径）

- `FilterIndex` per-frame 预算 lowercase 字段（`sniLower` / `httpHostLower` /
  `httpPathLower` 等）；matches 热路径**不**重新 lowercase
- `FrameFilter` atom 持 `pattern: String` 时同时持 `private val patternLower`，
  matches 用 `patternLower` 而非 `contains(pattern, ignoreCase=true)`
- dissector fallback 探针走 `NextStep.Prefetched`，Pipeline 复用结果不重复 dissect

---

## 5. 测试策略

- **core 层**纯 Kotlin 单测，不依赖 Robolectric
- **filter 错误类型**断言 `e.error is X`，不靠 message 字符串
- **UI 层** Compose UI 测用 Roborazzi 截图基线 + Robolectric @Config sdk = 35
  （与生产 compileSdk 严格对齐）
- **Robolectric** 测试硬编码字符串用 `context.getString(R.string.xxx)`，不直接
  写中文/英文字面量 —— locale 切换不破测试
- **截图基线**每次 UI 文本 / API / SDK 变动后重录：`./gradlew recordRoborazziDebug`

---

## 6. 静态分析

| 工具 | 范围 | baseline |
|---|---|---|
| Android lint | 资源 / API level / i18n / 性能 | `app/lint-baseline.xml` |
| detekt | Kotlin 代码风格 / 复杂度 / 反模式 | `config/detekt/detekt-baseline.xml` |
| Roborazzi verify | UI 视觉回归 | `app/build/outputs/roborazzi/*.png` |

CI 跑：

```bash
./gradlew :app:lintDebug detekt :app:testDebugUnitTest verifyRoborazziDebug
```

新增 lint / detekt 问题 **fail build**；baseline 内的旧问题作为债务渐进消减。

---

## 7. 历史决策追溯

每条 review finding → commit message 都带 `review vX.Y-roundN F-NNN`
引用。`git log --grep` 直接定位决策来源。reviews/ 在 .gitignore（信件不入库），
但 commit 引用永存。
