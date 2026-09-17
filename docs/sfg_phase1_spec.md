你现在需要在当前项目中实现一个参考论文
“Thinking More, Harnessing Better: Automatic Harness Generation
with Dataflow Aggregation and Workflow Decomposition”
中 SynapseFlow Phase 1 的 Structural Flow Graph（SFG）构建模块。

当前任务只实现：

1. C source code parsing
2. function metadata extraction
3. ISF / PRF / HPF candidate discovery
4. struct input/output direction analysis
5. Structural Flow Graph construction
6. JSON / DOT 输出
7. 基础测试

暂时不要实现：

- Function Triplet extraction
- Harness generation
- Stage 1~4 generation workflow
- fuzzing
- coverage feedback
- rollback

==================================================
一、目标
==================================================

给定一个 C 项目，例如：

project/
├── include/
│   └── xxx.h
└── src/
    ├── a.c
    └── b.c

执行类似：

python -m sfg_builder \
    --project ./target_project \
    --output ./artifacts/sfg

程序应该：

C Project
    ↓
tree-sitter AST parsing
    ↓
Functions
    ↓
Function Metadata
    ↓
Candidate Function Annotation
    ↓
ISF / PRF / HPF
    ↓
Struct Direction Analysis
    ↓
Structural Flow Graph
    ↓
sfg.json + sfg.dot


==================================================
二、严格遵循论文中的基本抽象
==================================================

论文中定义三类函数：

1. ISF: Input Stream Function

负责接收外部的、非结构化连续 byte stream，
并将数据送入程序内部处理。

典型形式：

int parse(
    const uint8_t *data,
    size_t size,
    Context *ctx
);

注意：

pointer 参数并不意味着一定是 ISF。

例如：

const char *filename

很可能只是文件名，而不是 fuzz byte stream。

所以：

语法分析负责筛选 candidate；
语义判断负责确认 candidate 是否是真正 ISF。


2. PRF: Process Function

负责：

- 读取
- 修改
- 转换
- 验证

一个已经初始化的 struct。

例如：

Frame get_frame(Image *image);

可以建模为：

Image
  |
get_frame
  ↓
Frame


3. HPF: Helper Function

主要负责 struct/resource 生命周期：

- create
- allocate
- init
- initialize
- reset
- cleanup
- release
- destroy
- free

例如：

void image_free(Image *image);


注意：

一个函数允许同时拥有多个 label。

例如：

parse_from_memory(...)

既可能是：

ISF

又可能完成 Context 初始化，因此同时也是：

HPF。


==================================================
三、使用 tree-sitter 解析 C 源码
==================================================

优先使用 Python + tree-sitter。

不要使用正则表达式作为主要 C parser。

递归扫描：

*.c
*.h

忽略：

.git/
build/
out/
cmake-build*/
third_party/
vendor/
external/

这些目录应做成可配置。


对于每个函数至少抽取：

{
  "name": "...",
  "file": "...",
  "start_line": ...,
  "end_line": ...,
  "return_type": "...",
  "parameters": [
    {
      "name": "...",
      "type": "...",
      "is_pointer": true,
      "is_const": false,
      "base_type": "...",
      "pointer_depth": 1
    }
  ],
  "body": "...",
  "labels": []
}

需要正确处理常见形式：

struct foo *
foo_t *
const foo_t *
void *
char *
const char *
uint8_t *
const uint8_t *
unsigned char *
T **
struct T *


typedef 需要尽可能解析，例如：

typedef struct j40_image {
    ...
} j40_image;

之后：

j40_image *

应该识别为 struct-like type。


==================================================
四、Candidate ISF Discovery
==================================================

首先使用静态语法规则进行高召回筛选。

候选函数：

至少存在一个可能表示 memory/byte stream 的 pointer 参数。

例如：

void *
char *
unsigned char *
uint8_t *
int8_t *

以及对应 const 类型。

例如：

int parse(
    const uint8_t *data,
    size_t size
);

应该进入 ISF candidate。


但是以下情况不能仅凭 pointer 类型直接判定：

const char *filename
const char *path
char *error_message
SomeStruct *ctx


因此设计：

ISFCandidateDetector

输出：

{
  "function": "parse",
  "candidate_parameters": [
    {
      "name": "data",
      "type": "const uint8_t *"
    }
  ]
}


==================================================
五、LLM Semantic Analyzer 接口
==================================================

不要把 LLM 调用逻辑硬编码进 parser。

建立独立接口，例如：

class SemanticAnalyzer:
    def classify_stream_parameter(...):
        ...

    def classify_function_role(...):
        ...

    def infer_struct_direction(...):
        ...


至少提供：

1. MockSemanticAnalyzer
2. LLMSemanticAnalyzer

这样即使没有 API key，也可以运行 AST 和 SFG 单元测试。


--------------------------------------------------
5.1 ISF 参数判断
--------------------------------------------------

对于 candidate pointer，向 LLM 提供：

- function signature
- parameter name
- parameter type
- function body
- 必要的相关 struct/type 定义

不要默认把整个项目发给 LLM。

要求返回严格 JSON：

{
  "is_byte_stream": true,
  "kind": "binary|text|filename|pathname|struct|other",
  "confidence": 0.0,
  "reason": "..."
}

核心判断标准参考论文：

目标参数是否表示：

“a contiguous sequence of bytes or contiguous text data”

排除：

- filename
- pathname
- struct object
- floating point data
- 其他明显具有特定高级语义的数据


如果：

is_byte_stream == true

则该函数可标记为 ISF。


为了之后能够实现论文中的 voting，
接口设计时允许同一个问题运行多个 prompt variant。

第一版可以：

variants = [
    "direct",
    "yes_no",
    "multiple_choice"
]

最后进行 majority voting。

不要简单重复完全一样的 prompt。


==================================================
六、PRF / HPF Candidate Discovery
==================================================

根据论文，先通过静态分析筛选：

- 有 struct 参数
- 有 struct pointer 参数
- 返回 struct
- 返回 struct pointer

的函数。

例如：

void image_free(Image *image);

Frame image_current_frame(Image *image);

Pixels frame_pixels(Frame *frame);


这些进入 struct-related candidate 集合。


之后调用 SemanticAnalyzer.classify_function_role()。

向 LLM 提供：

- function signature
- source body
- struct definitions（只提供必要部分）

返回：

{
  "is_prf": true,
  "is_hpf": false,
  "operation": "process|read|transform|init|allocate|cleanup|free|other",
  "reason": "..."
}

允许：

is_prf = true
is_hpf = true

同时成立。


==================================================
七、Struct Direction Analysis
==================================================

这是 SFG 构建最重要的部分。

目标：

确定函数：

Input Struct
    ↓
 function
    ↓
Output Struct


对于返回 struct：

Frame get_frame(Image *image);

Frame 可以直接视为 output struct candidate。


对于普通的非 pointer struct 参数：

根据 C 参数传递语义和函数使用方式记录其结构信息。


关键是：

pointer-to-struct 参数。

例如：

int parse(
    const uint8_t *data,
    size_t size,
    Image *image
);

单纯从：

Image *

无法确定它是：

INPUT
OUTPUT
BOTH


因此调用：

infer_struct_direction()

返回严格 JSON：

{
  "parameter": "image",
  "struct_type": "Image",
  "direction": "input|output|both|unknown",
  "reason": "..."
}


LLM 应根据函数 body 判断：

READ:

image->width

倾向 INPUT。


WRITE:

image->width = x;

倾向 OUTPUT。


READ + WRITE:

image->counter++;

倾向 BOTH。


但是：

不要单纯依靠字符串模式做最终判断。

可以先通过 AST 得到 read/write hints，
然后把：

- signature
- body
- AST hints

一起给 SemanticAnalyzer。


==================================================
八、定义统一的 Function Flow
==================================================

完成分析后，每个相关函数生成：

FunctionFlow

例如：

{
  "function": "j40_current_frame",
  "labels": ["PRF"],

  "input_structs": [
    "j40_image"
  ],

  "output_structs": [
    "j40_frame"
  ],

  "parameters": [...],

  "source": {
    "file": "...",
    "line": 123
  }
}


对于：

j40_from_memory(...)

可能得到：

{
  "function": "j40_from_memory",
  "labels": ["ISF", "HPF"],
  "input_structs": [],
  "output_structs": ["j40_image"]
}


对于：

j40_free(j40_image *)

可能得到：

{
  "function": "j40_free",
  "labels": ["HPF"],
  "input_structs": ["j40_image"],
  "output_structs": []
}


==================================================
九、构建 Structural Flow Graph
==================================================

严格按照论文的图抽象：

G = (V, E)


V：

每个 node 是一个唯一 struct type。

额外提供特殊节点：

"(null)"


例如：

V = {
    "(null)",
    "j40_image",
    "j40_frame",
    "j40_pixels"
}


E：

函数作为有向边。

形式：

<input_struct> --function--> <output_struct>


例如：

(null)
   |
j40_from_memory
   ↓
j40_image


j40_image
   |
j40_current_frame
   ↓
j40_frame


j40_frame
   |
j40_frame_pixels
   ↓
j40_pixels


j40_pixels
   |
j40_row
   ↓
(null)


j40_image
   |
j40_free
   ↓
(null)


边需要保留元数据：

{
  "source": "j40_image",
  "target": "j40_frame",
  "function": "j40_current_frame",
  "labels": ["PRF"],
  "file": "...",
  "line": 123
}


==================================================
十、多个 input/output struct 的处理
==================================================

论文没有完整公开所有复杂函数映射到 SFG edge 的工程实现细节。

因此这里不要假装论文已经规定了唯一方案。

第一版采取明确、保守、可调试的方法：

如果函数存在：

inputs = [A]
outputs = [B]

生成：

A -> B


如果没有 input struct，但有 output：

(null) -> B


如果有 input，没有 output：

A -> (null)


如果出现：

inputs = [A, B]
outputs = [C, D]

不要静默随意建立笛卡尔积。

将其：

1. 标记为 complex_flow
2. 保存原始 FunctionFlow
3. 第一版可以生成候选边，但必须：
   - 设置 inferred=true
   - 保留 inference_reason
4. 日志中明确 warning

目标是首先保证模型可解释和可调试。


==================================================
十一、数据模型
==================================================

建议使用 dataclass 或 pydantic：

ParameterInfo

FunctionInfo

StructInfo

FunctionAnnotation

FunctionFlow

SFGNode

SFGEdge

StructuralFlowGraph


代码模块尽量解耦，例如：

src/
  sfg/
    __init__.py

    parser/
      c_parser.py
      type_resolver.py
      models.py

    analysis/
      candidate_detector.py
      function_classifier.py
      direction_analyzer.py

    llm/
      base.py
      mock.py
      client.py
      prompts.py
      voting.py

    graph/
      models.py
      builder.py
      serializer.py
      dot.py

    cli.py


如果当前仓库已有合理结构，
优先适配现有结构，
不要为了匹配上述目录强行大规模重构。


==================================================
十二、SFG JSON 输出
==================================================

生成：

artifacts/sfg/sfg.json


格式示例：

{
  "nodes": [
    {
      "id": "(null)",
      "kind": "null"
    },
    {
      "id": "j40_image",
      "kind": "struct"
    },
    {
      "id": "j40_frame",
      "kind": "struct"
    }
  ],

  "edges": [
    {
      "source": "(null)",
      "target": "j40_image",
      "function": "j40_from_memory",
      "labels": ["ISF", "HPF"]
    },
    {
      "source": "j40_image",
      "target": "j40_frame",
      "function": "j40_current_frame",
      "labels": ["PRF"]
    }
  ],

  "functions": [...]
}


==================================================
十三、生成 Graphviz DOT
==================================================

同时生成：

sfg.dot


例如：

digraph SFG {
    "(null)" -> "j40_image"
        [label="j40_from_memory [ISF,HPF]"];

    "j40_image" -> "j40_frame"
        [label="j40_current_frame [PRF]"];

    "j40_frame" -> "j40_pixels"
        [label="j40_frame_pixels [PRF]"];

    "j40_pixels" -> "(null)"
        [label="j40_row [PRF]"];
}


如果系统安装 graphviz，
可以额外支持：

--render

生成：

sfg.svg

但 graphviz 不应成为核心模块的硬依赖。


==================================================
十四、保留分析过程，方便后续科研实验
==================================================

不要只保存最终 SFG。

同时保存：

functions.json
candidates.json
annotations.json
flows.json
sfg.json


这样未来可以检查错误究竟来自：

source parsing
    ↓
candidate detection
    ↓
LLM annotation
    ↓
direction inference
    ↓
graph construction


每一个 LLM decision 都记录：

{
  "function": "...",
  "task": "struct_direction",
  "prompt_version": "...",
  "response": {...},
  "confidence": ...
}


这对后续做：

ablation
error analysis
prompt optimization

非常重要。


==================================================
十五、测试
==================================================

创建一个最小 C fixture：

typedef struct {
    int state;
} Parser;

typedef struct {
    int value;
} Node;

int parser_from_memory(
    Parser *parser,
    const unsigned char *data,
    unsigned long size)
{
    parser->state = data[0];
    return 0;
}

Node parser_next(Parser *parser)
{
    Node n;
    n.value = parser->state;
    return n;
}

void node_process(Node *node)
{
    node->value++;
}

void parser_free(Parser *parser)
{
}


使用 MockSemanticAnalyzer 时，
期望 SFG 至少可以验证：

(null)
    |
parser_from_memory
    ↓
Parser


Parser
    |
parser_next
    ↓
Node


Node
    |
node_process
    ↓
(null)


Parser
    |
parser_free
    ↓
(null)


同时验证：

parser_from_memory labels:
["ISF", "HPF"]

parser_next:
["PRF"]

node_process:
["PRF"]

parser_free:
["HPF"]


==================================================
十六、开发步骤
==================================================

不要一次性写完整系统。

按照以下顺序实施：

Milestone 1
- 检查当前项目结构和已有依赖
- 给出设计方案
- 不修改无关代码

Milestone 2
- tree-sitter C parser
- FunctionInfo / ParameterInfo
- typedef / struct 基础解析

Milestone 3
- candidate discovery
- 输出 candidates.json

Milestone 4
- SemanticAnalyzer interface
- MockSemanticAnalyzer
- prompt templates

Milestone 5
- ISF / PRF / HPF annotation
- struct direction analysis

Milestone 6
- FunctionFlow
- SFG builder

Milestone 7
- JSON / DOT
- CLI

Milestone 8
- tests
- README


每完成一个 milestone：

1. 运行测试
2. 展示修改文件
3. 展示关键输出
4. 说明当前已实现内容
5. 再继续下一步


==================================================
十七、重要约束
==================================================

1. 不要把整个项目源码直接发送给 LLM。

2. 静态分析能够确定的信息不要交给 LLM 猜。

3. LLM 只解决：
   - pointer 是否为 byte stream
   - function semantic role
   - ambiguous struct pointer direction

4. 所有 LLM 返回必须使用结构化 JSON。

5. LLM 错误、超时、非法 JSON 都不能导致整个 pipeline 崩溃。

6. 每个判断必须可以追溯到：
   function
   file
   line
   prompt
   response

7. 不要在第一版加入 Function Triplet。

8. 不要在第一版加入 Harness Generator。

9. 不要为了“看起来完整”虚构论文没有描述的算法。

10. 遇到论文没有规定的工程细节：
    采用最简单、保守、可解释的实现，
    并在代码注释和 README 中标记：
    "engineering choice, not specified by SynapseFlow paper"


==================================================
十八、最终验收
==================================================

完成后我应该能够：

python -m sfg_builder --project tests/fixtures/simple_project \
    --output artifacts/simple

并看到：

artifacts/simple/
├── functions.json
├── candidates.json
├── annotations.json
├── flows.json
├── sfg.json
└── sfg.dot


最终终端输出类似：

Parsed functions: 4
Struct types: 2

ISF:
  parser_from_memory

PRF:
  parser_next
  node_process

HPF:
  parser_from_memory
  parser_free

SFG:
  (null) --parser_from_memory--> Parser
  Parser --parser_next--> Node
  Node --node_process--> (null)
  Parser --parser_free--> (null)


在真正开始修改代码之前：

先阅读当前仓库结构，
告诉我：

1. 你发现了哪些已有模块
2. 准备新增/修改哪些文件
3. 数据模型如何设计
4. tree-sitter 如何集成
5. SemanticAnalyzer 如何隔离
6. SFG 如何表示

然后再开始实现。