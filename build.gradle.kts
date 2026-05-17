plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.detekt)
}

// detekt：Kotlin 静态分析，全仓库跑 ./gradlew detekt。
// baseline 模式：现有 issue 进 detekt-baseline.xml 不阻塞，新增 issue 才 fail。
detekt {
    toolVersion = libs.versions.detekt.get()
    config.setFrom(files("$rootDir/config/detekt/detekt.yml"))
    baseline = file("$rootDir/config/detekt/detekt-baseline.xml")
    buildUponDefaultConfig = true
    // 只扫 app 主源码 + 测试
    source.setFrom(files("app/src/main/java", "app/src/test/java"))
    autoCorrect = false
    parallel = true
}

// VERSION 三处对齐检查：app/build.gradle.kts 的 versionName / README.md 的
// "当前状态：vX.Y.Z" 行 / RELEASE.md 提到的版本必须一致。
// 历史 review finding（v0.6-round2 F-004 / round3 F-006）反复纠正不一致。
// 跑：./gradlew checkVersionAlignment
tasks.register("checkVersionAlignment") {
    group = "verification"
    description = "校验 build.gradle.kts versionName 与 README/RELEASE 文档版本字符串一致"

    val buildFile = file("app/build.gradle.kts")
    val readmeFile = file("README.md")
    inputs.files(buildFile, readmeFile)

    doLast {
        val versionRegex = Regex("""versionName\s*=\s*"([^"]+)"""")
        val versionName = buildFile.readText().let { content ->
            versionRegex.find(content)?.groupValues?.get(1)
                ?: throw GradleException("无法从 ${buildFile.relativeTo(rootDir)} 解出 versionName")
        }

        // README 必须含 "v<versionName>" 字样（"当前状态：v0.8.1（≈ Roadmap v0.8a）"）
        val readmeText = readmeFile.readText()
        if (!readmeText.contains("v$versionName")) {
            throw GradleException(
                "README.md 未提及当前 versionName \"v$versionName\"。" +
                    "请同步更新 README 的「当前状态」行——详见 RELEASE.md §7。"
            )
        }

        logger.lifecycle("[checkVersionAlignment] OK: versionName = $versionName, README 已对齐")
    }
}

// 把 versionName check 挂到 :app:check 上（root 项目无 check task），
// 跑 ./gradlew :app:check 时自动一并验
gradle.projectsEvaluated {
    val appCheck = project(":app").tasks.findByName("check")
    appCheck?.dependsOn(tasks.named("checkVersionAlignment"))
    appCheck?.dependsOn(tasks.named("checkTargetSdkPolicy"))
}

// targetSdk 政策追踪（review v0.6-round4 F-001 教训）：Google Play 历来 8 月切换
// targetSdk 要求。本 task 把"该 SDK 何时变政策硬卡点"硬编码进 build，临近 deadline
// warn，过期 fail —— 不再靠人记。
tasks.register("checkTargetSdkPolicy") {
    group = "verification"
    description = "校验 app targetSdk 是否满足 Google Play 政策时间表"

    val buildFile = file("app/build.gradle.kts")
    inputs.files(buildFile)

    doLast {
        // Play 政策表：(targetSdk, deadline) —— deadline 之后新应用 / 大版本更新
        // 必须 >= 这个 targetSdk。来源 https://developer.android.com/google/play/requirements/target-sdk
        // 新版本到来时在此添加一行。
        val policyTable = listOf(
            34 to "2024-08-31",  // historical
            35 to "2025-08-31",  // historical
            36 to "2026-08-31",  // Android 16
            // 37 to "2027-08-31",
        )

        val targetSdkRegex = Regex("""targetSdk\s*=\s*(\d+)""")
        val current = buildFile.readText().let { content ->
            targetSdkRegex.find(content)?.groupValues?.get(1)?.toIntOrNull()
                ?: throw GradleException("无法从 ${buildFile.relativeTo(rootDir)} 解析 targetSdk")
        }

        val today = java.time.LocalDate.now()
        // 找当前 targetSdk 对应的 deadline + 下一个目标
        val currentEntry = policyTable.firstOrNull { it.first == current }
        val nextRequirement = policyTable.firstOrNull { entry ->
            val ddl = java.time.LocalDate.parse(entry.second)
            entry.first > current && ddl.isAfter(today.minusYears(1))
        }

        if (nextRequirement != null) {
            val deadline = java.time.LocalDate.parse(nextRequirement.second)
            val daysLeft = java.time.temporal.ChronoUnit.DAYS.between(today, deadline)
            when {
                daysLeft < 0 -> throw GradleException(
                    "targetSdk = $current 已不满足 Play 政策：deadline ${nextRequirement.second} " +
                        "已过 ${-daysLeft} 天。请升 targetSdk = ${nextRequirement.first}。"
                )
                daysLeft < 90 -> logger.warn(
                    "[checkTargetSdkPolicy] ⚠ targetSdk = $current 距离 deadline " +
                        "${nextRequirement.second} 还有 $daysLeft 天。下一目标 targetSdk = " +
                        "${nextRequirement.first}。请在 deadline 前升级。"
                )
                else -> logger.lifecycle(
                    "[checkTargetSdkPolicy] OK: targetSdk = $current；下一 Play 政策 " +
                        "targetSdk = ${nextRequirement.first} @ ${nextRequirement.second} " +
                        "（$daysLeft 天）"
                )
            }
        } else if (currentEntry != null) {
            logger.lifecycle(
                "[checkTargetSdkPolicy] OK: targetSdk = $current（最新已知 Play 政策值）"
            )
        } else {
            logger.warn(
                "[checkTargetSdkPolicy] 注意 targetSdk = $current 不在 policyTable 里；" +
                    "如果是更新的 SDK 请在 build.gradle.kts 顶部 policyTable 加一行"
            )
        }
    }
}
