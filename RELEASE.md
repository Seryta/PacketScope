# 正式发布指南

PacketScope 当前是 debug build。正式发布需要：

1. **生成 release keystore**（一次性，妥善保管，丢了无法更新已发布的 app）
2. **配置 release signingConfig**（不要把密码硬编码到 build.gradle，用 gradle.properties 或环境变量）
3. **启用 R8 minify + resource shrink**
4. **构建 release APK / AAB**
5. **签名校验**
6. **选择分发渠道**

## 1. 生成 release keystore

**关键**：生成一次，保管好。**丢失等于这个 applicationId 在 Google Play 永远无法更新**。建议异地多备份。

```bash
mkdir -p ~/.android-release
docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v ~/.android-release:/work \
  mingc/android-build-box:latest \
  keytool -genkey -v \
    -keystore /work/packetscope-release.keystore \
    -alias packetscope \
    -keyalg RSA -keysize 4096 -validity 10000 \
    -storepass '替换为强密码' \
    -keypass '替换为强密码' \
    -dname "CN=PacketScope, O=YourName, C=CN"
```

记录：
- keystore 路径：`~/.android-release/packetscope-release.keystore`
- alias：`packetscope`
- store/key password：保存到密码管理器，**不要进 git**

## 1.5. GitHub Actions 签名配置（自动 release 用）

REL-002 的 `.github/workflows/release.yml` 用 GitHub Secrets 自动签名
release APK / AAB。**这步等本地 keystore 已经按 §1 生成 + 备份完成后做**。

### Step 1：base64 编码 keystore

```bash
base64 -w 0 ~/.android-release/packetscope-release.keystore > /tmp/keystore.b64
wc -c /tmp/keystore.b64   # sanity check 非空
```

### Step 2：到 GitHub 仓库新建 Secrets

打开 `https://github.com/Seryta/PacketScope/settings/secrets/actions`，
**New repository secret**，按下表逐个添加：

| Secret name | 值 |
| --- | --- |
| `RELEASE_KEYSTORE_BASE64` | `/tmp/keystore.b64` 文件内容（整段贴） |
| `RELEASE_STORE_PASSWORD` | §1 keytool `-storepass` 用的强密码 |
| `RELEASE_KEY_PASSWORD` | §1 keytool `-keypass` 用的强密码 |
| `RELEASE_KEY_ALIAS` | `packetscope`（§1 `-alias` 值） |

### Step 3：擦除本地临时文件

```bash
shred -u /tmp/keystore.b64
```

### Step 4：验证

到 GitHub Secrets 列表确认 4 项都在。**不要** 在 Secrets 页测试 reveal
（GitHub 不允许读取已存 secret，只能覆盖）。后续 `git tag v… && git push
… v…` 触发 release workflow 时验证签名是否正常工作。

### 安全注意

- Secret 一次写入后只能覆盖不能读取，**本地 keystore 是真相来源**——keystore
  丢失即此 applicationId 在 Play 永远无法更新
- 任何 workflow 必须 `echo "${{ secrets.RELEASE_STORE_PASSWORD }}" | sed ...`
  这种逐字符渲染都被 GitHub Actions runner masking，不会在 build log
  里泄漏；但**自定义 shell 把 secret 写进文件 / env**仍可能在 log 抓到，
  REL-002 workflow 已经把 keystore 写 `$RUNNER_TEMP/release.keystore`
  + final `rm -f`，符合安全实践
- 一旦 secret 怀疑泄漏：立刻去 §1 重新生成新 keystore + 覆盖 4 个
  secret + 旧 keystore 文件 shred。Play 端要走开发者证书更换流程

## 2. 配置 release signingConfig

在工程根目录创建 `keystore.properties`（**加到 .gitignore**）：

```properties
storeFile=<absolute path to your release keystore .keystore file>
storePassword=替换为强密码
keyAlias=packetscope
keyPassword=替换为强密码
```

`app/build.gradle.kts` 加：

```kotlin
import java.util.Properties
import java.io.FileInputStream

val keystoreProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) load(FileInputStream(f))
}

android {
    signingConfigs {
        // ...debug 已有...
        if (keystoreProps.isNotEmpty()) {
            create("release") {
                storeFile = file(keystoreProps["storeFile"] as String)
                storePassword = keystoreProps["storePassword"] as String
                keyAlias = keystoreProps["keyAlias"] as String
                keyPassword = keystoreProps["keyPassword"] as String
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            if (keystoreProps.isNotEmpty()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }
}
```

`.gitignore` 加：

```
keystore.properties
```

## 3. ProGuard 规则

新建 `app/proguard-rules.pro`，PacketScope 用了 Compose / Kotlin 反射 / Robolectric 测试，保留必要规则：

```proguard
# Compose 不需要额外规则（Compose 自带 consumer ProGuard 文件）
# Kotlinx coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}

# PacketScope core 数据类大量用 data class + by remember，
# 反射不重要，但保留 enum 和 sealed class 名以便日志可读
-keepnames enum io.github.packetscope.** { *; }
-keep class io.github.packetscope.core.pcap.LinkType { *; }
```

## 4. 构建 release

```bash
docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "$PWD":/work -w /work \
  -v ~/.android-release:/work/.android-release \
  -v "$HOME/.gradle-docker":/work/.gradle-cache \
  -e GRADLE_USER_HOME=/work/.gradle-cache \
  mingc/android-build-box:latest \
  ./gradlew assembleRelease bundleRelease
```

输出：
- APK：`app/build/outputs/apk/release/app-release.apk`（直接分发用）
- AAB：`app/build/outputs/bundle/release/app-release.aab`（Google Play 上传用）

## 5. 签名校验

```bash
docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "$PWD":/work mingc/android-build-box:latest \
  apksigner verify --verbose --print-certs \
    /work/app/build/outputs/apk/release/app-release.apk
```

应看到「Verifies / v2 scheme: true」。

## 6. 分发渠道

### F-Droid（开源项目首选）

无需开发者账号；用户从 F-Droid 客户端直接更新。

1. 准备 metadata（已经有 `fastlane/metadata/android/zh-CN/` 目录可放）：
   - `title.txt` / `short_description.txt` / `full_description.txt`
   - `images/icon.png`（512×512）
   - `images/phoneScreenshots/*.png` (1-8 张)
2. 推荐自建 F-Droid 仓库（更快、不依赖官方）：
   - `fdroidserver fdroid init` 创建 repo
   - `fdroidserver fdroid update` 把 APK 加入
   - 把生成的 repo 部署到任意你能访问的静态 web 服务器
3. 或提 PR 到官方 `fdroiddata`：写 `metadata/io.github.packetscope.yml`，等 build server 自动构建

### Google Play

1. 注册开发者账号（25 USD 一次性）
2. Play Console 创建应用，上传 AAB（不是 APK）
3. 填写应用信息、隐私政策（PacketScope 需要 PCAP 文件访问 + 通知权限）、内容分级
4. 内部测试 → 封闭测试 → 公开发布

#### Play Console 提交准备清单（DEPLOY-002）

提交前预备好所有资产，避免反复来回 Console UI：

| 资产 | 尺寸 / 格式 | 来源 |
| --- | --- | --- |
| App icon | 512×512 PNG | 复用 `fastlane/metadata/android/en-US/images/icon.png`（见 `fastlane/README.md` 生成步骤） |
| Feature graphic | 1024×500 PNG/JPG | **新设计**，规格见 `docs/assets/feature-graphic-spec.md` |
| Phone screenshots | 长边 320-3840px，比例 1.78~2.33:1，2-8 张 | 真机 QA 阶段拍（参考 QA_CHECKLIST.md） |
| Short description | ≤ 80 chars | 复用 `fastlane/metadata/android/en-US/short_description.txt` |
| Full description | ≤ 4000 chars | 复用 `fastlane/metadata/android/en-US/full_description.txt` |
| Privacy policy URL | https URL | `https://raw.githubusercontent.com/Seryta/PacketScope/master/PRIVACY.md` |
| Content rating | Play Console 问卷 | 选项：网络工具 / 无暴力 / 无 IAP / 无广告 / 无用户内容 |
| Data safety | Play Console 问卷 | "no data collected, no data shared"（跟 PRIVACY.md 一致） |

资产对应中文 store 翻译走 `fastlane/metadata/android/zh-CN/*`。Play
Console 在 Store listing → "Manage translations" 里加 `zh-CN` locale 后
逐条对照填。

### GitHub Releases（推荐：自动化路径）

`.github/workflows/release.yml`（REL-002）让 tag push 自动构建 + 签名 +
发 Release。完整 release 流程：

1. **整理 CHANGELOG**：把 `[Unreleased]` 段下累积的条目 promote 到新版本
   段：

   ```markdown
   ## [Unreleased]

   ## [1.0.0] - 2026-MM-DD
   ### Added / Changed / Fixed
   - ...
   ```

2. **bump 版本号**（`app/build.gradle.kts`）：

   ```kotlin
   versionCode = 14    // +1
   versionName = "1.0.0"
   ```

3. **同步 README**「当前状态」行：`## 当前状态：v1.0.0`

4. **本地跑 guard 校验对齐**：

   ```bash
   ./gradlew checkVersionAlignment
   ```

5. **commit + tag + push**：

   ```bash
   git add app/build.gradle.kts README.md CHANGELOG.md
   git commit -m "release(v1.0.0): bump version + CHANGELOG"
   git tag v1.0.0
   git push origin master           # gitea
   git push origin v1.0.0
   git push github master           # github（双 remote 策略见 CONTRIBUTING）
   git push github v1.0.0           # 这步触发 release workflow
   ```

6. **等 Actions 跑完**，到 https://github.com/Seryta/PacketScope/releases
   验证：
   - Release 是否创建 + 描述是从 CHANGELOG 抽对了对应版本段
   - APK + AAB 两个 artifact 是否附上
   - prerelease 标签是否合适（tag 含 `-rc` / `-beta` / `-alpha` 时应自动
     标 prerelease）

7. **失败回滚**：删 tag，修复，重 tag：

   ```bash
   git push --delete origin v1.0.0
   git push --delete github v1.0.0
   git tag -d v1.0.0
   # 修问题（CHANGELOG / version / workflow）
   git tag v1.0.0
   git push origin v1.0.0 && git push github v1.0.0
   ```

   tag 重打会触发新 workflow run；如果 GitHub Release 已经创建，需要
   先到 Releases 页手工删旧 Release（或在 workflow 里加 `allow_overwrite`）。

### GitHub Releases（手动，调试用）

调试 workflow / 不想触发 CI 时手动发：

```bash
gh release create v1.0.0 \
  app/build/outputs/apk/release/app-release.apk \
  app/build/outputs/bundle/release/app-release.aab \
  --title "PacketScope 1.0.0" \
  --notes-file /tmp/release-notes.md
```

### Gitea Releases（备份镜像）

主仓在 GitHub，Gitea 是私有镜像。Gitea Releases 可选：

```bash
# tea CLI 类似 gh
tea release create --tag v1.0.0 --asset app-release.apk ...
```

solo dev 场景下通常不维护 Gitea Releases；推 tag 到 Gitea 让历史完整即可。

### 自托管 web 直链

把 APK 放自己服务器，用户「未知来源」安装。建议同时提供 SHA-256 校验：

```bash
sha256sum app/build/outputs/apk/release/app-release.apk
```

## 7. 版本管理

每次发布前更新 `app/build.gradle.kts`：

```kotlin
defaultConfig {
    versionCode = X   // 整数，严格递增（占位，按当前实际值 +1）
    versionName = "Y.Z"  // semver 字符串
}
```

> 用占位 `X` / `"Y.Z"` 而非具体数字 —— 文档不需要随 release 同步更新
> （review v0.6-round4 F-009）。具体值看 `app/build.gradle.kts` HEAD。

`versionCode` 必须严格递增（Google Play / F-Droid 用它判更新），`versionName` 给用户看。

**同步更新** `README.md` "当前状态：vX.Y.Z" 那行 —— 新用户看 README 判
项目阶段，跟 versionName 长在一起避免不一致（review v0.6-round3 F-006）。

## 8. 后续考虑

- **混淆 + R8 缩减**：debug 包 ~9.6MB，release minify 后估计 ~3-4MB
- **架构分包**：abi splits（armeabi-v7a / arm64-v8a / x86_64）能进一步减小单包大小
- **应用大小优化**：用 `./gradlew :app:assembleRelease --scan` 看哪些库占最多
- **CI/CD**：Gitea Actions 或 GitHub Actions 自动构建 + 签名（keystore 用 secret）
- **Crash 上报**：Firebase Crashlytics / Sentry（注意隐私政策）

## 当前 debug 用法（开发期间）

```bash
docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "$PWD":/work -w /work \
  -v "$HOME/.gradle-docker":/work/.gradle-cache \
  -e GRADLE_USER_HOME=/work/.gradle-cache \
  mingc/android-build-box:latest \
  ./gradlew assembleDebug
# → app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

签名固定来自 `app/keystore/debug.keystore`，每次构建覆盖安装不会冲突。
