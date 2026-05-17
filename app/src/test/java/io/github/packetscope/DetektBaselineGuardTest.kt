package io.github.packetscope

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Detekt baseline 增长守护测试（round1 TEST-001，兑现 v0.6-round6 F-001 的
 * deferred 项）。
 *
 * 跟 [LintBaselineGuardTest] 同模式：硬编码当前 issue 数上限，新提交不能
 * 让 baseline 增长。
 *
 * 反向流程：要新增 detekt issue 入 baseline，**必须先**在本测试更新上限
 * 值（commit 里要说明理由），逼迫贡献者意识到"我在引入新 detekt 债务"。
 *
 * 长期目标：随着我们清理 baseline，逐步下调上限值。
 *
 * 实现：纯文本扫 `../config/detekt/detekt-baseline.xml` 里 `<ID>` 出现
 * 次数，不解析 XML。
 */
class DetektBaselineGuardTest {

    /** 当前 baseline 允许的最大 issue 数。新增 issue 入 baseline 时**必须**
     *  降低或显式提高此值，并在 commit message 里写清原因。
     *  历史：round1 47（v0.6 → v1.0 sweep 累积值）。 */
    private val maxAllowedIssues = 47

    @Test
    fun `detekt-baseline 不允许超过 maxAllowedIssues`() {
        val baseline = File("../config/detekt/detekt-baseline.xml")
        require(baseline.exists()) {
            "detekt-baseline.xml 不存在: ${baseline.absolutePath} " +
                "(cwd=${File(".").absolutePath})"
        }
        val count = baseline.readText()
            .lineSequence()
            .count { it.trimStart().startsWith("<ID>") }
        assertTrue(
            "detekt baseline 含 $count 个 issue，超过上限 $maxAllowedIssues。" +
                "若有意提高门槛，更新 DetektBaselineGuardTest.maxAllowedIssues 并在 commit " +
                "message 写清新增 detekt 债务的具体来源。建议优先：修代码消除 issue 而非提高上限。",
            count <= maxAllowedIssues,
        )
    }
}
