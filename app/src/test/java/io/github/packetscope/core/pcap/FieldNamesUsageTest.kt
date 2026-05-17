package io.github.packetscope.core.pcap

import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/**
 * 守约定测试：所有出现在 [FieldNames] 常量集合里的字段名值，**不能**在源码
 * 里被写成字符串字面量——必须用 `FieldNames.X` 引用。
 *
 * 历史问题（review v0.6-round1 F-008 / round2 F-011 / round3 F-007）：
 * 字段名字面量散落，改 FieldNames 不会自动传到产出端 / 消费端，导致单向同步
 * 无声 break。本测试反向 enforce：FieldNames 收敛的字段，整个仓库不能再写
 * 字面量。
 *
 * 新加字段名收敛：加 FieldNames 常量 → 改所有现有字面量为 FieldNames.X
 *   → 跑测试通过 → 此后任何新写的字面量都会被这条测试抓到。
 *
 * 范围：扫 `app/src/main/java/.../core/dissector/` 包下所有 .kt 文件。
 * （消费端 filter / analyzer / decrypt 等已经全部走常量，由代码 review 守。）
 */
class FieldNamesUsageTest {

    @Test
    fun `FieldNames 收敛的字段不能被写成字面量`() {
        val constants = collectFieldNamesConstants()
        val dissectorRoot = File("src/main/java/io/github/packetscope/core/dissector")
        require(dissectorRoot.exists() && dissectorRoot.isDirectory) {
            "dissector 源码目录不存在: ${dissectorRoot.absolutePath}"
        }

        val violations = mutableListOf<String>()
        // 对每个常量值，扫源码找 `"X"` 字面量
        // 仅检查 Field("X", ...) 形式的调用，避免误伤 KDoc / 错误消息等。
        val fieldRegex = Regex("""Field\(\s*"([^"]+)"\s*,""")

        dissectorRoot.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .forEach { file ->
                file.readLines().forEachIndexed { idx, line ->
                    val trimmed = line.trim()
                    if (trimmed.startsWith("//") || trimmed.startsWith("*")) return@forEachIndexed
                    fieldRegex.findAll(line).forEach { match ->
                        val name = match.groupValues[1]
                        if (name in constants) {
                            violations += "${file.relativeTo(File(".")).path}:${idx + 1}: " +
                                "Field(\"$name\", ...) 应改为 Field(FieldNames.X, ...)" +
                                "—— \"$name\" 已在 FieldNames 收敛。"
                        }
                    }
                }
            }

        if (violations.isNotEmpty()) {
            fail(
                "发现 ${violations.size} 处违反 FieldNames 收敛约定：\n" +
                    violations.joinToString("\n") { "  $it" }
            )
        }
    }

    @Test
    fun `FieldNames 常量本身非空且唯一`() {
        val constants = collectFieldNamesConstants()
        assertTrue("FieldNames 必须至少声明 1 个常量", constants.isNotEmpty())
        val duplicates = constants.groupingBy { it }.eachCount().filter { it.value > 1 }
        assertTrue("FieldNames 内有重复值: $duplicates", duplicates.isEmpty())
    }

    /** 反射读 FieldNames 所有 public const val 的值 */
    private fun collectFieldNamesConstants(): Set<String> {
        return FieldNames::class.java.declaredFields
            .filter { java.lang.reflect.Modifier.isStatic(it.modifiers) }
            .mapNotNull { f ->
                f.isAccessible = true
                f.get(null) as? String
            }
            .toSet()
    }
}
