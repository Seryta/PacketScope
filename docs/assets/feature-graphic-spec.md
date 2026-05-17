# Play Console Feature Graphic 规格

Play Console Store listing 顶部横幅，必填项。文本读 RELEASE.md §6
「Play Console 提交准备清单」对接。

## 硬指标

- **尺寸**：1024 × 500 像素
- **格式**：PNG 或 JPG
- **大小**：≤ 1 MB（Play Console 上限）
- **方向**：横向 banner，比例 2.048:1
- **不可包含**：文本不能过小、不要堆 device frames、不要 "Best app of the year" 之类奖项
- **可包含**：app icon / 关键截图 element / 简洁标语（≤ 5 词）/ 渐变背景

## 设计建议（PacketScope 风格）

- **左 1/3**：app icon (large, foreground vector centered) + "PacketScope"
- **中 1/3**：tagline — "Wireshark on Android" 或 "PCAP viewer, offline"
- **右 1/3**：三联视图缩略（packet list 一截 + protocol tree 一截 + hex 一截 stacked）
- **配色**：Material Blue 600 (#1565C0) 主色，white text，避免高饱和度避免审核拒
- **字体**：Inter / Roboto / 系统默认无 serif

## 工作流

设计工具：Figma / Affinity Designer / Inkscape 任选。导出 1024×500 PNG
存到 `docs/assets/feature-graphic.png`，Play Console 上传时拖动。

## 不在本轮范围

- 不在本 commit 提供 PNG —— 视觉设计判断由用户决定
- 不要求 vector source（SVG / .fig）入库——大文件 + 修改成本高

## 中文 store listing

同一张 feature graphic 文字部分用英文（Play Console 全球展示）；中文
locale 的 store listing 可以用同一张 PNG，或独立设计后传 `zh-CN/featureGraphic`
（Play Console 支持 per-locale graphic）。
