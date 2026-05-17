# fastlane/metadata 资产说明

F-Droid metadata 走 fastlane 标准目录结构 `fastlane/metadata/android/{locale}/`。

## 文件清单 / 已就位

| 路径 | 内容 | 状态 |
| --- | --- | --- |
| `en-US/title.txt` / `zh-CN/title.txt` | "PacketScope" | ✅ |
| `en-US/short_description.txt` / `zh-CN/...` | ≤ 80 chars 双语短描述 | ✅ |
| `en-US/full_description.txt` / `zh-CN/...` | ≤ 4000 chars 双语长描述 | ✅ |
| `*/changelogs/13.txt` | versionCode=13 (v0.9.0) 双语 release notes | ✅ |

## 文件清单 / 待补（真机阶段）

| 路径 | 要求 | 备注 |
| --- | --- | --- |
| `*/images/icon.png` | 512×512 PNG | 当前为 adaptive vector，必须栅格化 |
| `*/images/phoneScreenshots/*.png` | 1-8 张，建议 3-5 张，长边 ≥ 320px | 真机 QA 阶段拍 |

## 生成 icon.png

`app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml` 是 adaptive vector
（foreground + background 两层 vector），没有 PNG 原始资源。生成 512×512
PNG 走 Android Studio Resource Manager：

1. Android Studio → 右栏 Resource Manager → 选 `ic_launcher`
2. 右键 → "Export icon to PNG"
3. 选 size = 512×512 + Density = xxxhdpi
4. 保存到 `fastlane/metadata/android/en-US/images/icon.png`
5. 复制到 `zh-CN/images/icon.png`（icon 双语相同）

无 Android Studio 的命令行方案（需要安装 `rsvg-convert` 或 ImageMagick
+ inkscape，能渲染 adaptive icon vector 的工具）：

```bash
# 用 inkscape 渲染（要先把 adaptive icon 拼成单一 SVG）
# 实际项目里更稳的是 Android Studio Export
```

## 生成 phoneScreenshots/

参考 QA_CHECKLIST.md，真机走完一遍核心流程时顺手截：

- `01-frame-list.png`
- `02-frame-detail.png`
- `03-conversations.png`
- `04-follow-stream.png`
- `05-filter-help.png`
- `06-streaming.png`

文件名按这个标准化，README 引用同名（DOC-001 已经留 docs/screenshots/
目录）。
