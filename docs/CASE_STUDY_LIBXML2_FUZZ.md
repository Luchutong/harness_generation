# 案例：真实 libxml2 fuzz —— 流水线"已晋升"harness 的 4 类缺陷

日期：2026-09-24　靶机：`120.26.138.210`（4 核 8G）
被测 FT：`ft_xmloutputbufferwritestring_ce1ef21d7aac`
相关文档：`docs/HARNESS_PIPELINE.md`、`docs/LIMITATIONS.md`、`docs/EVALUATION.md`

---

## 0. 一句话结论

流水线把 `libxml2_xmlio_real_replayed_final_20260924_1000` 里的 replay 版 harness 判为
`status: stable_promoted` / `validation_status: passed`（compiler / intermediate / linker / runtime
四个组件全部 passed），但该 harness **原版 1 字节输入即崩、且每次执行泄漏 33,600 字节**：

> **4 处缺陷全部在 harness 侧（encoder 路径 + caller-supplied buffer 路径），没有一处是 libxml2 的 bug。**

原版直接用于 fuzz 只会产出误报，且泄漏会把 worker 拖进 OOM 重启死循环。
逐处修掉（补丁副本，原件字节未动）后，同一 harness 在 4 核机上约 30 分钟跑了 **5,789,667 次执行、0 artifacts**，
边覆盖从 **661 → 1033**、`ft` 从 1636 → 3243。

---

## 1. 环境与配置

| 项 | 值 |
|---|---|
| 靶机 | `120.26.138.210`，4 核 / 8G，Ubuntu 24.04，glibc `2.39-0ubuntu8.9`，clang 18.1.3 |
| libxml2 | `16d4a7c21ea79664f3670aafc17958c10fcab9f9` |
| meson 配置 | 与流水线 `build/` 一致：docs/python/readline/history/icu/zlib=disabled，`-Ddefault_library=static` |
| 追加 flags | `-g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined` |
| worker | 4 个，共享 corpus + `-reload=1`，supervisor 脚本自动重启 |
| fuzz 参数 | `-max_len=65536 -max_total_time=10800 -print_final_stats=1 -dict=xml.dict -rss_limit_mb=800 -timeout=25` |
| ASAN_OPTIONS | `detect_leaks=0:quarantine_size_mb=64:abort_on_error=0:handle_abort=1:allocator_may_return_null=1` |

**两个前置修正（缺一不可）：**

1. **流水线自带的 `libxml2.a` 未插桩。** `nm libxml2.a | grep -c __asan` = 0，libFuzzer 的 PC 表只有 1,742 个
   （全部来自 harness 与 `xmlIO.c` 导出单元）。重编后 `__asan=948 / __sanitizer_cov=316 / __ubsan=229`，
   **PC 表 191,853（110 倍）**，cov 335→661。不插桩的后果是双重的：库内部的堆越界/UAF 抓不到，
   且 **libFuzzer 对库内部完全失明**（搜索本身也退化）。
2. **静音 shim**（独立编译单元，`__attribute__((constructor))` 里装空 xml error handler）。
   libxml2 对每个畸形输入都往 stderr 打"出错行 + caret"，实测 78MB/分钟/worker：
   既会在 2 小时内写满盘，又把吞吐从 1638–2048 压到 558 exec/s。只改报告通道，harness 与库的控制流未动。

---

## 2. 三个阶段与两个 harness 的对比

| 阶段 | harness | 执行次数 | cov | ft | artifacts |
|---|---|---|---|---|---|
| 阶段一（`max_len=4096`） | `attempt_005`（来自 `libxml2_xmlio_stage4_rerun_v10`） | 59,906,058 | 661 | 1531 | 0 |
| 阶段二（`max_len=65536`） | 同上 | 27,916,718 | 661 | 1636 | 0 |
| v2（~30 分钟） | `real_replayed_final` 的**补丁副本** | 5,789,667 | **1033** | **3243** | 0 |

> 注：阶段一/二的执行次数为各 worker `stat::number_of_executed_units` 的累计值。

**阶段一/二的饱和证据**：`cov` 在 `#1940 INITED` 时即达 661，其后 163 万次执行零增长；`ft` 仍在涨
（1531→1636）说明**边集合已饱和、只有数据取值在变**。这是 harness 形态的限制（调用序列固定、
控制维度写死），调 fuzz 参数无解。另注意 stat 行的 `lim:` **不是**单元大小硬上限：
实测同一行 `lim: 8583` 而正在执行/入库的单元有 37,919 字节、corpus 里躺着 61,954 字节的单元。

**为什么 `attempt_005` 不会踩这些坑**（对照其源码 `src/harness.c`）：所有 encoder 参数传 `NULL`、
缓冲用 `std::vector<char>` 管理、`size` 前后一致、从不构造 caller-supplied `xmlBuffer`。
代价是控制维度全部写死，可达边集合停在 661。

`real_replayed_final` 版把行为面加宽了——7 个控制字节（encoder / compression / fd / uri / escape / len / flags）、
自造 encoder 回调、栈上 `xmlBuffer`、escape 回调——**覆盖面换来了正确性的四个洞**。

---

## 3. 四处缺陷（含最小复现）

### 3.1 ABI 错配：4 参数回调被当作 6 参数函数调用

```c
encoder.output.legacyFunc = local_escaping_cb;   /* harness.c:150，4 参数 */
encoder.flags = 0;                               /* harness.c:155 */
```

`output` 是 union（`include/libxml/encoding.h`），`legacyFunc` 与 `func` 共享槽位；
libxml2 按 **`handler->flags & XML_HANDLER_LEGACY`** 选分支（`encoding.c:1740`），
而该宏是 **`encoding.c:54` 的私有定义，任何公开头文件里都没有**：

```c
#define XML_HANDLER_STATIC (1 << 0)
#define XML_HANDLER_LEGACY (1 << 1)
```

`flags = 0` → 走新式分支，用 6 参数类型 `xmlCharEncConvFunc` 调这个 4 参数函数（`encoding.c:1759`）。
换句话说：**外部代码无法正确使用 `legacyFunc`**，唯一合法途径是 `xmlNewCharEncodingHandler()`
（它内部 `flags = XML_HANDLER_STATIC | XML_HANDLER_LEGACY`，`encoding.c:744`）。

复现（1 字节）：

```bash
printf '\x01' > /tmp/one.bin
ASAN_OPTIONS=detect_leaks=0 ./fuzzer /tmp/one.bin
```

```
../encoding.c:1759:15: runtime error: call to function local_escaping_cb(unsigned char*, int*,
  unsigned char const*, int*) through pointer to incorrect function type
  'xmlCharEncError (*)(void *, unsigned char *, int *, const unsigned char *, int *, int)'
==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 local_escaping_cb  harness.c:50:17
    #1 xmlEncOutputChunk     ../encoding.c:1759
    #2 xmlCharEncOutput      ../encoding.c:2029
    #3 xmlOutputBufferFlush  ../xmlIO.c:2667
    #4 xmlOutputBufferClose  ../xmlIO.c:1458
    #5 LLVMFuzzerTestOneInput harness.c:176
```

### 3.2 栈上 handler 被 free（被 3.1 挡在后面，未实际触发）

`flags` 缺 `XML_HANDLER_STATIC` → `xmlOutputBufferClose`（`xmlIO.c:1481`）调
`xmlCharEncCloseFunc(out->encoder)`，后者对**栈上** handler 执行 `xmlFree(handler->name)`
（`"fuzz-encoder"` 字符串字面量）＋ `xmlFree(handler)`（栈地址）。三处缺陷同源：handlers 的生命周期
约定由那两位私有 flag 决定，外部代码无从表达。

**verdict：这是 libxml2 侧的 API 卫生问题**（公开的 deprecated 成员离开私有 flag 就不可用，
且失败模式是"野调用"而不是干净的 `XML_ENC_ERR_INTERNAL`），但对本流水线而言属于生成侧约束。

### 3.3 长度截断不一致：栈越界读

`payload_len` 由**未截断**的 `payload_size` 算出（`harness.c:117`），而 `payload_z[]` 只有 4096
（`harness.c:120-126`）→ `xmlOutputBufferWrite(out_buf, payload_len, payload_z)`（`harness.c:202`）越界读。

```bash
python3 -c "open('/tmp/trunc.bin','wb').write(bytes(7)+b'A'*8000)"
ASAN_OPTIONS=detect_leaks=0 ./fuzzer /tmp/trunc.bin
```

```
==ERROR: AddressSanitizer: stack-buffer-overflow
    #0 __asan_memmove
    #1 xmlBufAdd             ../buf.c:475
    #2 xmlOutputBufferWrite  ../xmlIO.c:2413
    #3 LLVMFuzzerTestOneInput harness.c:202
```

### 3.4 每次执行泄漏 33,600 字节 → OOM

harness 手工构造**栈上** `xmlBuffer`（`harness.c:136-145`）：`content` 指向栈数组 `buffer_backing`、
`alloc = XML_BUFFER_ALLOC_IO`、`contentIO = NULL`。一旦写入量超过 4096，`xmlBufferGrow`（`buf.c:891`）
走 `xmlMalloc` 分支换出堆块、把 `content`/`contentIO` 都指向它（此后走 `xmlRealloc`），
而 harness 从不释放 —— 栈上的结构体随函数返回消失，堆块就成了每次执行一份的泄漏。

```bash
ASAN_OPTIONS=detect_leaks=1 ./fuzzer -runs=1 oom-artifact
```

```
Direct leak of 33600 byte(s) in 1 object(s) allocated from:
    #1 xmlBufferGrow  ../buf.c:897
    #2 xmlBufferAdd   ../buf.c:1005
    #3 xmlBufferWrite ../xmlIO.c:1080
    #4 xmlOutputBufferFlush ../xmlIO.c:2683
    #5 LLVMFuzzerTestOneInput harness.c:216
```

在服务器速率（~10k exec/s 聚合）下几秒就撞 `rss_limit_mb` → OOM 产物 + worker 重启死循环。
libFuzzer 的 OOM 现场：`2056587194 bytes in 94798 chunks`。

> 附带确认（非缺陷）：`xmlOutputBufferCreateBuffer` 的 `closecallback = NULL`，
> 所以库不会替调用方释放那个 `xmlBuffer`；上面的泄漏责任在 harness。

---

## 4. 为什么流水线的 smoke 校验全过

校验输入只有两个（`build/.../runtime_inputs/`）：

| 文件 | 大小 | 内容 | 后果 |
|---|---|---|---|
| `empty.bin` | 0 B | — | `size = 0`，连 ctrl 字节都读不到 |
| `minimal.bin` | 1 B | `00` | `ctrl_encoder = 0x00` → **最低位 = 0 → `encoder_ptr = nullptr`** |

即：

* **encoder 路径一次都没进**（3.1 / 3.2 的触发前提是 encoder 非 NULL）；
* `payload_size = 0` → 回调第一行 `if (avail <= 0 || have <= 0) return 0;` 直接短路，
  **连那个错配的调用点都不会被执行**；
* 没有写入 → 不触发 `xmlBufferGrow` → 3.4 的泄漏也不出现。

**只加 1 个 payload 字节就崩**：`printf '\x01\x41' > /tmp/two.bin` → 3.1 的 UBSan + ASan 报告。
此外，校验器链接的是**未插桩**的 `libxml2.a`，libxml2 侧的 UBSan 函数类型检查同样缺席。

---

## 5. 补丁副本（原件字节未动）

| # | 位置 | 原 | 改 | 理由 |
|---|---|---|---|---|
| 1 | `encoder.flags` | `0` | `1 /* XML_HANDLER_STATIC */ \| 2 /* XML_HANDLER_LEGACY */` | 让 libxml2 走 4 参数旧式分支；STATIC 同时抑制 free |
| 2 | 同上 | — | （由 #1 的 STATIC 位一并解决） | 见 3.2 |
| 3 | 写 `out_buf` 前 | — | `if (payload_len > (int)z_len) payload_len = (int)z_len;` | 长度与截断后的缓冲一致 |
| 4 | 函数末尾 | — | `if (buffer.content != buffer_backing) xmlFree(buffer.content);` | 释放库换出的堆块 |

文件：`/tmp/h_new_fixed2.c`（头部注释记录了这 4 处 diff）→ 已存档到服务器
`/root/hg_fuzz/src/harness_patched_v2.c`。**原始 harness 字节未改。**

验证：

* LSan：同一 OOM 输入 `-runs=1` → 0 泄漏（原版该输入 33,600 B）；
* 本地 240s（`max_len=8192`）：0 崩溃、0 artifacts、peak RSS 168MB 平稳，cov 1031 / ft 3233；
* 服务器 ~30 分钟（`max_len=65536`，4 worker）：5,789,667 次执行、0 artifacts、RSS 稳在 204–210MB/worker。

---

## 6. 部署要点（可复用）

* **stdout 必须丢 `/dev/null`**：harness 的 `uri_table` 含 `"-"` / `"stdout"`，约 1/4 的输入会把 payload
  打到 stdout。worker 重定向写成 `> /dev/null 2>> logs/w${i}.log`（libFuzzer 的 stat 行走 stderr，日志不受影响）。
  静音 shim + stdout 重定向后，日志量约 7MB/小时（4 worker 合计）。
* **优雅停机**：脚本读 `STOP` 文件退出循环；`touch STOP && pkill -INT -x fuzzer_silent`
  能拿到 libFuzzer 的最终统计。**不要用 `pkill -f`**（匹配完整命令行会把发起命令的 shell 一起杀掉）。
* **二进制可直接 scp**：ASan runtime 静态链接，两侧 glibc 一致（`2.39-0ubuntu8.9`）即可；
  本次 `fuzzer_silent` md5 `59136837f600605ff8e1031e0fa50383`。
* 换 harness 时**先轮转日志**（`logs/phase2_attempt005/`），并把监控端的去重游标重置，
  否则旧记录会被当成新事件重报。

---

## 7. 对流水线的建议

### 生成侧（Stage 4）

1. **禁止裸填 `xmlCharEncodingHandler`**。要自定义 encoder 就用 `xmlNewCharEncodingHandler()`；
   `legacyFunc` 在没有私有 `XML_HANDLER_LEGACY` 位时不可用，失败模式是野调用而非错误码。
2. **调用方提供的 `xmlBuffer` 必须 heap 分配并在使用后释放**。栈上 backing + `XML_BUFFER_ALLOC_IO`
   会在 grow 时被库换成堆块，责任随即落到调用方。
3. **传给 API 的长度必须与缓冲区容量一致**。任何 `strncpy`/截断之后都要同步钳住长度参数——
   这条与上一轮修的 taint 传递是同一类"派生缓冲"问题（见 `docs/` 中 taint 相关记录）。

### 校验侧（RuntimeValidator / LibFuzzerSmokeValidator）

4. **smoke 输入必须翻遍所有控制位、且带非零 payload**。当前 0 B / 1 B(`0x00`) 两个输入
   让 encoder 路径与 grow 路径**双双零执行**。最小要求：每个控制分支至少一个输入
   （本 harness 就是 7 个 ctrl 字节 × 非空 payload）。
5. **校验必须链接插桩版库**。否则 ASan 在库内部失效、UBSan 的函数类型检查缺席。
6. **加一条"泄漏 smoke"**：`detect_leaks=1` 跑若干输入。本案例 4 处缺陷里有 2 处
   （3.2 与 3.4）只在 free/泄漏维度可见，`validation_status: passed` 完全没覆盖到。

---

## 8. 复现命令

```bash
# 插桩库（与流水线同配置，仅追加插桩）
cd /home/luchitong/work/libxml2
SAN="-g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined"
CC=clang CXX=clang++ meson setup build-asan-fuzz \
  -Ddocs=disabled -Dpython=disabled -Dreadline=disabled -Dhistory=disabled \
  -Dicu=disabled -Dzlib=disabled -Ddefault_library=static \
  -Dc_args="$SAN" -Dcpp_args="$SAN"
ninja -C build-asan-fuzz libxml2.a        # 44,737,644 B, 37 成员（与原库同）

# 补丁副本的链接（原始脚本见 /root/hg_fuzz/BUILD_NOTES.md）
A=/home/luchitong/work/harness_generation/artifacts/libxml2_xmlio_real_replayed_final_20260924_1000
clang++ -x c++ -std=c++17 -g -O1 -fsanitize=fuzzer-no-link,address,undefined \
  -I/home/luchitong/work/libxml2 -I/home/luchitong/work/libxml2/build-asan-fuzz \
  -I/home/luchitong/work/libxml2/build-asan-fuzz/include -I/home/luchitong/work/libxml2/include \
  -c /tmp/h_new_fixed2.c -o /tmp/h_fixed2.o
clang++ -g -O1 -fsanitize=fuzzer,address,undefined \
  $A/build/ft_xmloutputbufferwritestring_ce1ef21d7aac/objects/build/hg_xmlio_export_static.o \
  /tmp/h_fixed2.o /tmp/silence.o /home/luchitong/work/libxml2/build-asan-fuzz/libxml2.a -lm -o /tmp/fuzzer_fixed2

# 三个最小复现
printf '\x01' > /tmp/one.bin
ASAN_OPTIONS=detect_leaks=0 /tmp/fuzzer_new /tmp/one.bin                       # 3.1（原版）
python3 -c "open('/tmp/trunc.bin','wb').write(bytes(7)+b'A'*8000)"             # 3.3
ASAN_OPTIONS=detect_leaks=0 /tmp/fuzzer_new /tmp/trunc.bin
ASAN_OPTIONS=detect_leaks=1 /tmp/fuzzer_fixed2 -runs=1 <oom-artifact>          # 3.4（对照：补丁后 0 泄漏）
```

## 9. 产物索引

| 内容 | 路径 |
|---|---|
| 原始 harness（字节未改） | `artifacts/libxml2_xmlio_real_replayed_final_20260924_1000/harnesses/ft_xmloutputbufferwritestring_ce1ef21d7aac.c` |
| 其晋升记录 | 同目录 `promotion.json`：`stable_promoted` / `validation_status: passed` / 四组件 passed |
| 上一版 harness（对照） | `artifacts/libxml2_xmlio_stage4_rerun_v10/generation/ft_xmloutputbufferwritestring_ce1ef21d7aac/stage4/attempt_005/harness.c`（md5 `8a54ffdbb7e707094887d6623146a6f8`） |
| 补丁副本 | `artifacts/libxml2_xmlio_fuzz_v2_20260924/harness/harness_patched_v2.c`（md5 `597125fa9c44cc013cc5f6518643e911`）；副本亦在服务器 `/root/hg_fuzz/src/harness_patched_v2.c`，本地工作副本 `/tmp/h_new_fixed2.c` |
| 最小复现输入 | `artifacts/libxml2_xmlio_fuzz_v2_20260924/repro/`：`one.bin`(3.1)、`two.bin`(§4)、`trunc.bin`(3.3)、`oom-…`(3.4) |
| 本地跑测日志 | `artifacts/libxml2_xmlio_fuzz_v2_20260924/logs/`（原版 OOM 现场 / 补丁后 240s 干净跑） |
| 构建与运行记录 | 服务器 `/root/hg_fuzz/BUILD_NOTES.md`（含三阶段数据与 v2 章节） |
| 日志存档 | 服务器 `/root/hg_fuzz/logs/`、阶段二存档 `logs/phase2_attempt005/` |
| corpus | 服务器 `/root/hg_fuzz/corpus`（v2 结束时 11,479 文件 / 53MB） |
| 静态库（插桩） | `/home/luchitong/work/libxml2/build-asan-fuzz/libxml2.a`（md5 `5de0527e7e71ff3be7f13360632f1659`） |
| fuzzer 二进制 | 服务器 `/root/hg_fuzz/fuzzer_silent`（md5 `59136837f600605ff8e1031e0fa50383`）；旧版留档 `fuzzer_silent.attempt005` |
