# Case Study：markdown-wasm

本文档总结 `benchmarks/markdown_wasm` 中保留的真实项目案例。更完整的底层取证见
[`benchmarks/markdown_wasm/FOLD_REPORT.md`](../benchmarks/markdown_wasm/FOLD_REPORT.md)。

## 目标项目

目标：[`rsms/markdown-wasm`](https://github.com/rsms/markdown-wasm)

仓库中保留的 `benchmarks/markdown_wasm/project/` 是固定 commit 下相关 C 文件的
benchmark copy。测试重点不是重新构建官方 npm 包，而是用 native Clang/Sanitizer
构建其 C core，并检验 LLM 生成 harness 对真实 parser 入口的覆盖能力。

两个关键入口：

- `md_parse`：底层 Markdown parser，输入是 markdown bytes 和 `MD_PARSER` callback table。
- `parseUTF8`：导出 wrapper，负责调用 parser 并把结果写入共享输出 buffer。

## 发现路径

流程：

```text
SFG / FT 抽取
→ 指定 md_parse / parseUTF8 FT
→ 真实 LLM 生成 harness
→ compiler / linker / runtime gate
→ smoke fuzz
→ sanitizer finding
→ reference harness 复现
→ 源码和 wasm 行为分析
```

结论：生成 harness 的质量并不完美，尤其是 `parseUTF8` 的 callback 语义仍有偏差；
但 `md_parse` 路径足以触达真实目标缺陷，且 finding 能被手写 reference harness 复现，
因此不是 harness 自身伪造出的 crash。

## 根因

缺陷位于 vendored `md4c.c` 的 Unicode case-folding 逻辑：

```c
unsigned index;

index = md_unicode_bsearch__(codepoint, FOLD_MAP_LIST[i].map,
                             FOLD_MAP_LIST[i].map_size);
if(index >= 0) {
    const unsigned* codepoints =
        FOLD_MAP_LIST[i].data + (index * n_codepoints);
    memcpy(info->codepoints, codepoints, sizeof(unsigned) * n_codepoints);
}
```

`md_unicode_bsearch__()` 查找失败时返回 `-1`。由于 `index` 被声明为 `unsigned`，
`if(index >= 0)` 恒为真，`-1` 变为 `0xffffffff`。随后指针计算访问 fold table 前方
的内存。

这个错误不是上游 md4c 的原始写法；它来自 `markdown-wasm` fork 中一次为消除 warning
而进行的 signedness 修改。

## 跨平台行为

| 场景 | 结果 |
| --- | --- |
| native 64-bit + ASan | `md4c.c:708` 附近发生越界读并 SEGV，可作为 DoS / memory-safety finding。 |
| wasm32 官方布局 | 越界读落在相邻静态数据或 padding 内，通常不 trap。 |
| shipped wasm artifact | 产生 silent label confusion，至少 354 个 codepoint 会 alias 到无关 label。 |

这说明 native sanitizer 只暴露了问题的一面。更重要的 wasm 可见后果是语义错误：
某些普通日文字符、数字和拉丁扩展字符会错误匹配到不相关的 link label。

## 最小触发输入

64-bit native sanitizer build 下，下面输入可以触发 crash：

```text
[中]: /x
```

对应字节：

```text
5b e4 b8 ad 5d 3a 20 2f 78
```

另一类 malformed UTF-8 也可以触发：

```text
5b ac ac ac ac 5d 3a 78
```

## 语义影响

在 shipped wasm artifact 中，越界读得到的值由链接布局决定。报告中观察到的行为可简化为：

```text
folded(c) = c - 0x3000
```

因此某些本不应匹配的 label 会错误匹配。例如报告中确认存在 kana 到 `a-z` 的 alias。
这属于 fail-open label matching：如果应用把 reference definition 当作信任边界的一部分，
错误匹配方向比单纯“不匹配”更值得关注。

## 安全评估

已确认：

- 64-bit native build 存在 sanitizer 可见的越界读 / SEGV。
- shipped wasm artifact 存在 silent label matching 错误。
- finding 可以通过 reference harness 复现，不依赖生成 harness 的偶然结构。
- fork 中的 `unsigned index` 是直接根因。

尚未确认：

- 该问题在实际上游使用场景中是否能稳定变成可利用安全漏洞。
- wasm silent aliasing 是否影响具体应用的权限、过滤或链接策略。
- 除报告中枚举的 alias 外，是否还有受 build layout 影响的其他语义后果。

因此本 case study 更适合表述为：生成 harness 帮助发现了一个真实项目中的
memory-safety / semantic defect，而不是直接声称拿到了完整可利用漏洞。

## 对本项目的启示

这个 case 对 harness generation 框架有两点价值：

1. 端到端链路是有效的：真实 LLM 生成 harness、编译验证和 smoke fuzz 能触发真实目标问题。
2. 仅靠“能编译、能 crash”不够：wasm 上更重要的表现是 silent semantic bug，需要
   reference harness、差分测试和平台语义分析才能完整确认。

它也暴露了框架短板：

- FT ranking 没有默认选中最自然的 parser entry。
- callback typedef / callback table 语义仍难以自动恢复。
- runtime feedback 过于偏 crash，对 silent output mismatch 支持不足。
