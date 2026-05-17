package io.github.packetscope

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Lint baseline 增长守护测试：
 *
 * 历史问题（review v0.6-round4 F-002..F-007）：lint baseline 把过去发现的 issue
 * 静默吞，没人 review baseline 内容，**等于永远不修**。本测试硬编码当前 issue
 * 数上限，新提交不能让 baseline 增长。
 *
 * 反向流程：要新增 lint issue 入 baseline，**必须先**在本测试更新上限值（commit
 * 里要说明理由），逼迫贡献者意识到"我在引入新 lint 债务"。
 *
 * 长期目标：随着我们清理 baseline，逐步下调上限值。
 *
 * 实现：纯文本扫 `app/lint-baseline.xml` 里 `<issue` 出现次数，不解析 XML。
 */
class LintBaselineGuardTest {

    /** 当前 baseline 允许的最大 issue 数。新增 issue 入 baseline 时**必须**降低或
     *  显式提高此值，并在 commit message 里写清原因。
     *  历史：round4 60（修了 round1 入库的 10 个，AGP 8.9 新规则又加几个）。 */
    private val maxAllowedIssues = 61

    @Test
    fun `lint-baseline 不允许超过 maxAllowedIssues`() {
        val baseline = File("lint-baseline.xml")
        require(baseline.exists()) {
            "lint-baseline.xml 不存在: ${baseline.absolutePath} (cwd=${File(".").absolutePath})"
        }
        val count = baseline.readText()
            .lineSequence()
            .count { it.trimStart().startsWith("<issue") }
        assertTrue(
            "lint baseline 含 $count 个 issue，超过上限 $maxAllowedIssues。" +
                "若有意提高门槛，更新 LintBaselineGuardTest.maxAllowedIssues 并在 commit " +
                "message 写清新增 lint 债务的具体来源。建议优先：修代码消除 issue 而非提高上限。",
            count <= maxAllowedIssues,
        )
    }
}
