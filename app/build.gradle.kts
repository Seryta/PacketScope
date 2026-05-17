import java.io.FileInputStream
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.roborazzi)
}

// release 签名配置：keystore.properties 在 gitignore 里，本地有就启用
// release signingConfig + minify；没有就 release 构建保持未签名（仍可 assembleDebug）
val keystoreProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) FileInputStream(f).use { load(it) }
}

android {
    namespace = "io.github.packetscope"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.packetscope"
        minSdk = 26
        targetSdk = 36
        // versionCode 严格递增，Play/F-Droid 用它判 OTA 升级。下次 release
        // 至少 +1。当前对齐 README "v0.9.0" 状态。
        // v0.6→8, v0.7→9, v0.8a→10, v0.8b→11, v0.8c→12, v0.9→13 —— review
        // v0.6-round7 F-001 把 v0.7..v0.9 漏 release 的版本一次性补上。
        versionCode = 13
        versionName = "0.9.0"
    }

    // 项目级 debug keystore：保证每次构建签名一致，覆盖安装不冲突
    signingConfigs {
        getByName("debug") {
            storeFile = file("keystore/debug.keystore")
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
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
        debug {
            signingConfig = signingConfigs.getByName("debug")
            // debug 包独立 applicationId，可与 release 同设备共存便于对比
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        release {
            // 没 keystore.properties 时 release 不签名也不 minify，保留 assembleRelease
            // 可跑（产物未签名，用于 CI 验证编译路径），但实际发布走 RELEASE.md 流程
            if (keystoreProps.isNotEmpty()) {
                signingConfig = signingConfigs.getByName("release")
                isMinifyEnabled = true
                isShrinkResources = true
                proguardFiles(
                    getDefaultProguardFile("proguard-android-optimize.txt"),
                    "proguard-rules.pro",
                )
            } else {
                isMinifyEnabled = false
                logger.warn("[PacketScope] release 构建未签名：未找到 keystore.properties，" +
                    "见 RELEASE.md §2。assembleRelease 仍可跑但产物无法安装。")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        // 生成 BuildConfig 以便 UdpExporterListener 用 BuildConfig.DEBUG 守日志
        buildConfig = true
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
        }
    }

    // Android lint：本地 / CI 跑 ./gradlew :app:lintDebug 检查资源、API、i18n 问题。
    // baseline 模式 —— 现有 warning 进 lint-baseline.xml 不阻塞，新增问题才 fail。
    // 涵盖 strings.xml 空白、plurals、API level、UseValueOf、HardcodedText 等。
    lint {
        baseline = file("lint-baseline.xml")
        warningsAsErrors = false  // 先观察基线一段时间再开严
        abortOnError = true       // baseline 之外的新 issue 阻塞
        // 关掉 release-only check（debug 也跑）和 SARIF 报告（CI 单独开）
        checkReleaseBuilds = false
        // 关注的类目
        checkAllWarnings = true
        // 噪声大的可在这里 disable，目前先空着看初次扫描结果
        disable += setOf(
            "VectorPath",          // VectorDrawable path 优化提示，本项目用 evenOdd 是有意的
            "MissingTranslation",  // 我们只 zh + 默认英语，其它 locale 暂不要求翻译
        )
    }
}

// Roborazzi 视觉回归基线放 app/snapshots/（项目内、非 build/ 子目录、入 git）。
// 默认 outputDir = app/build/outputs/roborazzi/ 被 .gitignore 排除，CI fresh
// clone 没基线 verify 必然全失败。改到 snapshots/ 后 PNG 入库，verify 有参照。
roborazzi {
    outputDir.set(layout.projectDirectory.dir("snapshots"))
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    debugImplementation(libs.androidx.ui.tooling)
    debugImplementation(libs.androidx.ui.test.manifest)

    testImplementation(libs.junit)
    testImplementation(libs.robolectric)
    testImplementation(libs.androidx.test.runner)
    testImplementation(libs.androidx.test.ext.junit)
    testImplementation(platform(libs.androidx.compose.bom))
    testImplementation(libs.androidx.ui.test.junit4)
    testImplementation(libs.roborazzi)
    testImplementation(libs.roborazzi.compose)
    testImplementation(libs.roborazzi.junit.rule)
}
