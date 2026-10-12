"""Read-only bounded Clang analysis of explicit compilation database entries."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import signal
import subprocess
import time

from ..records import write_json
from ..semantic_discovery.models import canonical, digest

VERSION = "clang-build-context-v1"
DOCUMENTS = ("compile_context", "symbols", "callable_targets", "type_layouts")


class BuildAnalysisError(ValueError):
    pass


@dataclass(frozen=True)
class AnalysisBudget:
    max_translation_units: int = 32
    max_dependencies: int = 512
    max_file_bytes: int = 8 * 1024 * 1024
    max_ast_bytes: int = 64 * 1024 * 1024
    max_ast_stream_bytes: int = 256 * 1024 * 1024
    max_aux_bytes: int = 2 * 1024 * 1024
    timeout_seconds: int = 20

    def __post_init__(self):
        for name, value in asdict(self).items():
            if type(value) is not int or value < 1:
                raise BuildAnalysisError(f"{name} must be a positive integer")
        if self.max_translation_units > 64 or self.timeout_seconds > 30:
            raise BuildAnalysisError("analysis exceeds finite TU/time bounds")
        if (self.max_dependencies > 1024 or self.max_file_bytes > 16 * 1024 * 1024
                or self.max_ast_bytes > 64 * 1024 * 1024 or self.max_aux_bytes > 4 * 1024 * 1024
                or self.max_ast_stream_bytes > 512 * 1024 * 1024):
            raise BuildAnalysisError("analysis exceeds finite I/O bounds")


def file_digest(path, maximum=None):
    result, count = hashlib.sha256(), 0
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(256 * 1024), b""):
            count += len(chunk)
            if maximum is not None and count > maximum:
                raise BuildAnalysisError("source_dependency_file_limit")
            result.update(chunk)
    return result.hexdigest()


class _JsonCompactor:
    """Preserve every JSON value while dropping pretty-print whitespace.

    Clang's indent-heavy AST output can be much larger than the parsed facts.
    Strings, including escaped quotes and whitespace, remain byte-for-byte
    intact across pipe read boundaries. Both raw and retained output are bounded.
    """
    _string = re.compile(rb'"(?:[^"\\]|\\.)*"')
    _whitespace = b" \t\r\n"

    def __init__(self, maximum):
        self.pending = b""
        self.maximum = maximum

    def feed(self, content):
        content, self.pending = self.pending + content, b""
        output, cursor = [], 0
        while cursor < len(content):
            quote = content.find(b'"', cursor)
            if quote < 0:
                output.append(content[cursor:].translate(None, self._whitespace))
                break
            output.append(content[cursor:quote].translate(None, self._whitespace))
            match = self._string.match(content, quote)
            if match is None:
                self.pending = content[quote:]
                if len(self.pending) > self.maximum:
                    raise BuildAnalysisError("clang_output_limit")
                break
            output.append(match[0])
            cursor = match.end()
        return b"".join(output)

    def finish(self):
        if self.pending:
            raise BuildAnalysisError("clang_invalid_json_output")


def _run(arguments, directory, budget, maximum, *, compact_json=False, input_bytes=None):
    """No shell, no inherited compiler injection env, no unbounded capture."""
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
    if input_bytes is not None and (not isinstance(input_bytes, bytes) or len(input_bytes) > 4096):
        raise BuildAnalysisError("clang_probe_input_limit")
    process = subprocess.Popen(arguments, cwd=directory, env=environment,
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    chunks = {"stdout": [], "stderr": []}
    sizes = {"stdout": 0, "stderr": 0}
    raw_stdout_size = 0
    compactor = _JsonCompactor(maximum) if compact_json else None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    started = time.monotonic()
    try:
        if input_bytes is not None:
            process.stdin.write(input_bytes)
            process.stdin.close()
        while selector.get_map():
            if time.monotonic() - started > budget.timeout_seconds:
                raise BuildAnalysisError("clang_timeout")
            for key, _ in selector.select(timeout=0.1):
                content = os.read(key.fileobj.fileno(), 65536)
                if not content:
                    selector.unregister(key.fileobj)
                    continue
                name = key.data
                if name == "stdout" and compactor is not None:
                    raw_stdout_size += len(content)
                    if raw_stdout_size > budget.max_ast_stream_bytes:
                        raise BuildAnalysisError("clang_ast_stream_limit")
                    content = compactor.feed(content)
                sizes[name] += len(content)
                if sizes[name] > (maximum if name == "stdout" else budget.max_aux_bytes):
                    raise BuildAnalysisError("clang_output_limit")
                chunks[name].append(content)
        if compactor is not None:
            compactor.finish()
        code = process.wait(timeout=1)
        return code, b"".join(chunks["stdout"]).decode("utf-8"), b"".join(chunks["stderr"]).decode("utf-8")
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()


_PAIRED = {"-I", "-isystem", "-iquote", "-idirafter", "-include", "-imacros", "-D", "-U", "-x",
    "-isysroot", "--sysroot", "-target", "--target", "-std", "-resource-dir"}
_SAFE = {"-g", "-g0", "-g1", "-g2", "-g3", "-O0", "-O1", "-O2", "-O3", "-Os", "-Oz", "-Og",
    "-pthread", "-pedantic", "-pedantic-errors", "-ansi", "-nostdinc", "-nostdinc++", "-fPIC", "-fpic",
    "-fPIE", "-fpie", "-fno-builtin", "-fshort-enums", "-fshort-wchar", "-fsigned-char", "-funsigned-char",
    "-fms-extensions", "-fms-compatibility", "-fdeclspec", "-fno-strict-aliasing", "-fstrict-aliasing",
    "-fno-common", "-fcommon", "-fwrapv", "-fno-wrapv", "-fno-omit-frame-pointer", "-fomit-frame-pointer",
    "-m32", "-m64", "-msoft-float", "-mhard-float", "-ffreestanding", "-fno-freestanding", "-fno-exceptions"}
_SAFE_PREFIXES = ("-std=", "--target=", "--sysroot=", "-march=", "-mcpu=", "-mtune=", "-mabi=",
    "-mfpu=", "-mfloat-abi=", "-fvisibility=", "-fpack-struct=", "-fms-compatibility-version=",
    "-fno-builtin-", "-fsanitize=", "-fno-sanitize=", "-fsanitize-coverage=", "-fno-sanitize-coverage=",
    "-fno-sanitize-recover=", "-fsanitize-recover=", "-D", "-U", "-I")
_REMOVE_PAIRED = {"-o", "-MF", "-MT", "-MQ", "-MJ"}
_REMOVE = {"-c", "-S", "-E", "-M", "-MM", "-MD", "-MMD", "-MP", "-MG", "-fsyntax-only"}


def load_commands(project, path, budget):
    project, path = Path(project).resolve(), Path(path).resolve()
    raw = path.read_bytes()
    if len(raw) > 4 * 1024 * 1024:
        raise BuildAnalysisError("compile_database_size_limit")
    records = json.loads(raw)
    if not isinstance(records, list) or not 1 <= len(records) <= budget.max_translation_units:
        raise BuildAnalysisError("compile_database_translation_unit_limit")
    entries = []
    for record in records:
        if not isinstance(record, dict) or not {"directory", "file"} <= record.keys():
            raise BuildAnalysisError("invalid_compile_database_entry")
        directory = Path(record["directory"])
        directory = directory.resolve() if directory.is_absolute() else (path.parent / directory).resolve()
        if not directory.is_dir():
            raise BuildAnalysisError("compile_directory_unavailable")
        filename = Path(record["file"])
        filename = filename.resolve() if filename.is_absolute() else (directory / filename).resolve()
        try:
            relative = filename.relative_to(project).as_posix()
        except ValueError as error:
            raise BuildAnalysisError("translation_unit_outside_project") from error
        if filename.suffix not in {".c", ".cc", ".cpp", ".cxx"} or not filename.is_file():
            raise BuildAnalysisError("invalid_translation_unit")
        arguments = record.get("arguments")
        if arguments is None and isinstance(record.get("command"), str):
            arguments = shlex.split(record["command"])
        if (not isinstance(arguments, list) or not 1 <= len(arguments) <= 256
                or any(not isinstance(a, str) or not a or len(a) > 8192 or "\x00" in a for a in arguments)):
            raise BuildAnalysisError("invalid_compile_arguments")
        # A compilation database is data, never an authorization to execute
        # its original compiler, wrapper, environment assignment or shell.
        compiler_name = Path(arguments[0]).name
        if not re.fullmatch(r"(?:clang(?:\+\+)?|gcc|g\+\+|cc|c\+\+)(?:-[0-9.]+)?", compiler_name):
            raise BuildAnalysisError("unsupported_compile_driver")
        flags, removed, input_seen = [], [], False
        cursor = 1
        while cursor < len(arguments):
            value = arguments[cursor]
            if value.startswith("@") or value in {"--", "-Xclang", "-mllvm", "-Xpreprocessor", "-Xassembler", "-Xlinker"}:
                raise BuildAnalysisError("unsafe_compile_argument:" + value)
            if value.startswith(("-Wp,", "-Wa,", "-Wl,")):
                raise BuildAnalysisError("unsafe_compile_argument:" + value)
            if value in _REMOVE_PAIRED:
                if cursor + 1 >= len(arguments):
                    raise BuildAnalysisError("missing_compile_argument_value")
                removed.extend(arguments[cursor:cursor + 2]); cursor += 2; continue
            if value in _REMOVE or value.startswith(("-o", "-MF", "-MT", "-MQ", "-MJ")):
                removed.append(value); cursor += 1; continue
            if value in _PAIRED:
                if cursor + 1 >= len(arguments) or arguments[cursor + 1].startswith("-"):
                    raise BuildAnalysisError("missing_compile_argument_value")
                flags.extend(arguments[cursor:cursor + 2]); cursor += 2; continue
            if value in _SAFE or value.startswith(_SAFE_PREFIXES) or re.fullmatch(r"-W[A-Za-z0-9_=+-]+", value):
                flags.append(value); cursor += 1; continue
            if value.startswith("-"):
                raise BuildAnalysisError("unsupported_compile_argument:" + value)
            candidate = Path(value)
            candidate = candidate.resolve() if candidate.is_absolute() else (directory / candidate).resolve()
            if candidate != filename or input_seen:
                raise BuildAnalysisError("unexpected_compile_input")
            input_seen = True; cursor += 1
        if not input_seen:
            raise BuildAnalysisError("compile_input_missing")
        identity = {"source": relative, "directory": str(directory), "arguments": flags,
                    "original_arguments": arguments, "removed_output_arguments": removed}
        identity["tu_id"] = "tu_" + digest(identity)[:24]
        entries.append(identity)
    unique = {entry["tu_id"]: entry for entry in entries}
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
            "entries": [unique[key] for key in sorted(unique)]}


def _walk(node):
    yield node
    for child in node.get("inner", []):
        yield from _walk(child)


def _expand_type(value, macros):
    for _ in range(8):
        expanded = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\b", lambda m: macros.get(m[0], m[0]), value)
        if expanded == value:
            break
        value = expanded
    return " ".join(value.split())


def _calling_convention(value):
    conventions = [name for name in ("cdecl", "stdcall", "fastcall", "vectorcall", "ms_abi", "sysv_abi")
        if re.search(r"\b" + name + r"\b", value)]
    return conventions[0] if len(conventions) == 1 else "c" if not conventions else "unknown"


def _canonical_type(value, macros, typedefs):
    value = _expand_type(value, macros)
    for _ in range(8):
        def replace(match):
            before = value[:match.start()].rstrip()
            if before.endswith(("struct", "enum", "union")):
                return match[0]
            return typedefs.get(match[0], match[0])
        result = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\b", replace, value)
        if result == value:
            break
        value = result
    return " ".join(value.split())


def _location(node, current_file, project, raw_sources):
    location = node.get("loc", {})
    location = location.get("expansionLoc", location.get("spellingLoc", location))
    file = location.get("file", current_file)
    if not file:
        return None, current_file
    path = Path(file).resolve()
    try:
        source = path.relative_to(project).as_posix()
    except ValueError:
        source = str(path)
    offset = location.get("offset")
    line = location.get("line")
    if line is None and type(offset) is int and source in raw_sources:
        line = raw_sources[source][:offset].count(b"\n") + 1
    return {"source": source, "line": line, "offset": offset,
            "macro_expanded": "expansionLoc" in node.get("loc", {})}, str(path)


def _layouts(text):
    layouts, current = {}, None
    for line in text.splitlines():
        match = re.match(r"\s*0\s*\| (struct|union) (.+)$", line)
        if match:
            current = {"name": match[2], "tag": match[1], "fields": []}
            continue
        if current is None:
            continue
        size = re.search(r"\[sizeof=(\d+), align=(\d+)\]", line)
        if size:
            current.update(size_bits=int(size[1]) * 8, align_bits=int(size[2]) * 8)
            layouts[(current["tag"], current["name"])] = current
            current = None
            continue
        field = re.match(r"\s*(\d+)\s*\|   (\S.*)$", line)
        if field:
            current["fields"].append({"offset_bits": int(field[1]) * 8, "display": field[2]})
    return layouts


def _identity(document, snapshot):
    if snapshot is not None:
        return snapshot.source_fingerprint, snapshot.functions_fingerprint
    # Use the existing artifact projection, including its record ordering and
    # serialization. Raw parser order differs from HG ID order for e.g. line
    # 12 vs 112, and non-ASCII bodies use artifact_fingerprint's own encoding.
    # Source/parameter content is retained; only declared record sets are sorted.
    from ..sfg_adapter import SFGArtifacts, SFGGraphView
    from ..minimal_ft.models import ProjectSnapshot
    artifacts = SFGArtifacts(graph=SFGGraphView((), ()), project=document.get("project", ""),
        files=tuple(document["files"]), functions=tuple(document["functions"]),
        structs=tuple(document.get("structs", [])), function_warnings=tuple(document.get("warnings", [])),
        callback_typedefs=tuple(document.get("callback_typedefs", [])), annotations=(), flows=(), embedded_flows=(),
        source_hashes=document.get("source_hashes", {}), source_schema_versions={"functions": document["schema_version"]})
    projected = ProjectSnapshot.from_artifacts(artifacts)
    return projected.source_fingerprint, projected.functions_fingerprint


def _allocation_probe_flags(arguments):
    """Allocator guarantees use canonical target types, not project macros."""
    removed_paired = {"-D", "-U", "-I", "-isystem", "-iquote", "-idirafter", "-include", "-imacros", "-resource-dir", "-x"}
    flags, cursor, language = [], 0, None
    while cursor < len(arguments):
        flag = arguments[cursor]
        if flag in removed_paired:
            if flag == "-x":
                language = arguments[cursor + 1]
            cursor += 2
            continue
        if flag.startswith(("-D", "-U", "-I")):
            cursor += 1
            continue
        flags.append(flag)
        cursor += 1
    return flags, language


def analyze_build(project, compile_commands, functions_document, *, clang=None, budget=None, snapshot=None):
    project, budget = Path(project).resolve(), budget or AnalysisBudget()
    compiler = Path(clang or shutil.which("clang") or "")
    if not compiler.is_absolute() or not compiler.is_file():
        raise BuildAnalysisError("clang_unavailable")
    compiler = compiler.resolve()
    compiler_sha = file_digest(compiler)
    version_code, version, _ = _run([str(compiler), "--version"], project, budget, budget.max_aux_bytes)
    if version_code or "clang version" not in version:
        raise BuildAnalysisError("configured_tool_is_not_clang")
    database = load_commands(project, compile_commands, budget)
    clang_invocations = [{"stage": "compiler_identity", "arguments": [str(compiler), "--version"], "returncode": 0}]
    resource_arguments = [str(compiler), "-print-resource-dir"]
    resource_code, resource_text, _ = _run(resource_arguments, project, budget, budget.max_aux_bytes)
    clang_invocations.append({"stage": "compiler_resources", "arguments": resource_arguments, "returncode": resource_code})
    resource_dir = Path(resource_text.strip()).resolve() if resource_code == 0 and resource_text.strip() else None
    alignment_header = resource_dir / "include" / "__stddef_max_align_t.h" if resource_dir else None
    if alignment_header is not None and not alignment_header.is_file():
        alignment_header = None
    source_fp, functions_fp = _identity(functions_document, snapshot)
    raw_sources = {}
    for source, expected in functions_document.get("source_hashes", {}).items():
        path = (project / source).resolve()
        if not path.is_relative_to(project) or file_digest(path, budget.max_file_bytes) != expected:
            raise BuildAnalysisError("tree_sitter_source_snapshot_stale:" + source)
        raw_sources[source] = path.read_bytes()
    units, symbols, records, all_dependencies, dependency_links = [], [], [], {}, {}
    if alignment_header is not None:
        all_dependencies[str(alignment_header)] = file_digest(alignment_header, budget.max_file_bytes)
        dependency_links[str(alignment_header)] = str(alignment_header.resolve())
    function_rows = functions_document["functions"]
    for entry in database["entries"]:
        arguments = [str(compiler), *entry["arguments"], str(project / entry["source"])]
        code, dependencies, error = _run([*arguments, "-M", "-MT", "__hg_dependencies__"], entry["directory"], budget, budget.max_aux_bytes)
        if code:
            raise BuildAnalysisError("clang_dependency_analysis_failed:" + error[:1200])
        clang_invocations.append({"stage": "dependencies", "tu_id": entry["tu_id"],
            "arguments": [*arguments, "-M", "-MT", "__hg_dependencies__"], "returncode": code})
        dependency_paths = shlex.split(dependencies.replace("\\\n", " ").partition(":")[2])
        if not 1 <= len(dependency_paths) <= budget.max_dependencies:
            raise BuildAnalysisError("clang_dependency_limit")
        dep_rows = []
        for filename in sorted(set(dependency_paths)):
            requested = Path(filename)
            requested = Path(os.path.abspath(requested if requested.is_absolute() else Path(entry["directory"]) / requested))
            path = requested.resolve()
            dependency_links[str(requested)] = str(path)
            sha = file_digest(path, budget.max_file_bytes)
            if str(path) in all_dependencies and all_dependencies[str(path)] != sha:
                raise BuildAnalysisError("source_changed_during_analysis")
            all_dependencies[str(path)] = sha
            dep_rows.append({"path": str(path), "requested_path": str(requested), "sha256": sha, "project_owned": path.is_relative_to(project)})
            if path.is_relative_to(project):
                source = path.relative_to(project).as_posix()
                raw_sources.setdefault(source, path.read_bytes())
        code, macro_text, error = _run([*arguments, "-E", "-dM"], entry["directory"], budget, budget.max_aux_bytes)
        if code:
            raise BuildAnalysisError("clang_macro_analysis_failed:" + error[:1200])
        clang_invocations.append({"stage": "macros", "tu_id": entry["tu_id"],
            "arguments": [*arguments, "-E", "-dM"], "returncode": code})
        macros = {}
        for line in macro_text.splitlines():
            match = re.match(r"#define ([A-Za-z_][A-Za-z0-9_]*)(?: (.*))?$", line)
            if match:
                macros[match[1]] = match[2] or ""
        allocation_alignment = {"verified": False, "align_bits": None, "basis": "canonical_clang_max_align_t",
            "blockers": [], "header": str(alignment_header) if alignment_header else None}
        shadowed_alignment_headers = [row["path"] for row in dep_rows
            if Path(row["path"]).name in {"stddef.h", "__stddef_max_align_t.h"}
            and (resource_dir is None or not Path(row["path"]).is_relative_to(resource_dir))]
        if alignment_header is None:
            allocation_alignment["blockers"].append("canonical_max_align_t_header_unavailable")
        elif shadowed_alignment_headers:
            allocation_alignment["blockers"].append("stddef_header_shadowed")
            allocation_alignment["shadowed_headers"] = shadowed_alignment_headers
        else:
            probe_flags, explicit_language = _allocation_probe_flags(entry["arguments"])
            language = explicit_language or ("c++" if Path(entry["source"]).suffix != ".c" else "c")
            operator = "alignof" if language == "c++" else "_Alignof"
            probe_name = "__hg_standard_allocation_alignment_probe"
            probe_source = ("#include " + json.dumps(str(alignment_header)) + "\n"
                + f"enum {{ {probe_name} = {operator}(max_align_t) }};\n").encode()
            probe_arguments = [str(compiler), *probe_flags, "-x", language, "-", "-fsyntax-only",
                "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=" + probe_name]
            probe_code, probe_ast, probe_error = _run(probe_arguments, entry["directory"], budget,
                budget.max_aux_bytes, compact_json=True, input_bytes=probe_source)
            clang_invocations.append({"stage": "standard_allocation_alignment", "tu_id": entry["tu_id"],
                "arguments": probe_arguments, "stdin_sha256": hashlib.sha256(probe_source).hexdigest(), "returncode": probe_code})
            allocation_alignment["probe_arguments"] = probe_arguments
            allocation_alignment["canonical_header_sha256"] = all_dependencies[str(alignment_header)]
            if probe_code:
                allocation_alignment["blockers"].append("canonical_max_align_t_probe_failed")
                allocation_alignment["diagnostics"] = probe_error[:4096]
            else:
                try:
                    constants = [int(node["value"]) for node in _walk(json.loads(probe_ast))
                        if node.get("kind") == "ConstantExpr" and str(node.get("value", "")).isdigit()]
                except (ValueError, TypeError, KeyError):
                    constants = []
                if len(constants) == 1 and 0 < constants[0] <= 4096:
                    allocation_alignment.update(verified=True, align_bits=constants[0] * 8)
                else:
                    allocation_alignment["blockers"].append("canonical_max_align_t_value_unknown")
        code, ast_text, diagnostics = _run([*arguments, "-fsyntax-only", "-Xclang", "-ast-dump=json"],
            entry["directory"], budget, budget.max_ast_bytes, compact_json=True)
        if code:
            raise BuildAnalysisError("clang_translation_unit_failed:" + diagnostics[:1200])
        clang_invocations.append({"stage": "ast", "tu_id": entry["tu_id"],
            "arguments": [*arguments, "-fsyntax-only", "-Xclang", "-ast-dump=json"], "returncode": code})
        ast = json.loads(ast_text)
        ignored_conventions = set(re.findall(r"'([A-Za-z0-9_]+)' calling convention is not supported", diagnostics))
        typedef_nodes = [n for n in _walk(ast) if n.get("kind") == "TypedefDecl" and n.get("name")]
        typedefs = {n["name"]: n.get("type", {}).get("desugaredQualType", n.get("type", {}).get("qualType", ""))
            for n in typedef_nodes}
        typedef_layout_overrides = {}
        layout_attributes = {"AlignedAttr", "AlignValueAttr", "MaxFieldAlignmentAttr", "PackedAttr"}
        for node in typedef_nodes:
            attributes = sorted({child["kind"] for child in node.get("inner", []) if child.get("kind") in layout_attributes})
            if attributes:
                typedef_layout_overrides[node["name"]] = {"name": node["name"], "attributes": attributes,
                    "canonical_type": _canonical_type(typedefs[node["name"]], macros, typedefs),
                    "status": "typedef_layout_unknown"}
        # An alias of an attributed typedef retains the underlying typedef's
        # alignment even when desugaredQualType only reports the record tag.
        for _ in range(8):
            changed = False
            for node in typedef_nodes:
                inherited = sorted(set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", node.get("type", {}).get("qualType", "")))
                    & typedef_layout_overrides.keys())
                if inherited and node["name"] not in typedef_layout_overrides:
                    typedef_layout_overrides[node["name"]] = {"name": node["name"], "attributes": [],
                        "inherited_from": inherited, "canonical_type": _canonical_type(typedefs[node["name"]], macros, typedefs),
                        "status": "typedef_layout_unknown"}
                    changed = True
            if not changed:
                break
        code, layout_text, layout_error = _run([*arguments, "-fsyntax-only", "-Xclang", "-fdump-record-layouts-complete"],
            entry["directory"], budget, budget.max_aux_bytes)
        if code:
            raise BuildAnalysisError("clang_record_layout_failed:" + layout_error[:1200])
        clang_invocations.append({"stage": "record_layouts", "tu_id": entry["tu_id"],
            "arguments": [*arguments, "-fsyntax-only", "-Xclang", "-fdump-record-layouts-complete"], "returncode": code})
        layout_map = _layouts(layout_text)
        current_file = str(project / entry["source"])
        unit_symbols, unit_records = [], []
        target_abi = {name: value for name, value in macros.items() if name.startswith("__SIZEOF_")
            or name in {"__CHAR_BIT__", "__BYTE_ORDER__", "__ORDER_LITTLE_ENDIAN__", "__ORDER_BIG_ENDIAN__",
                "__x86_64__", "__i386__", "__aarch64__", "__arm__", "__ARM_PCS_VFP", "__ARM_FP",
                "_WIN32", "_WIN64", "__APPLE__", "__LP64__"}}
        for node in _walk(ast):
            location, current_file = _location(node, current_file, project, raw_sources)
            if node.get("kind") == "FunctionDecl" and node.get("name") and location and type(location.get("offset")) is int:
                name, source = node["name"], location["source"]
                defined = any(child.get("kind") == "CompoundStmt" for child in node.get("inner", []))
                matches = [f for f in function_rows if f["name"] == name and f["file"] == source
                    and f["start_line"] <= (location.get("line") or 0) <= f["end_line"] and bool(f.get("defined")) == defined]
                canonical_type = _canonical_type(node.get("type", {}).get("desugaredQualType", node.get("type", {}).get("qualType", "")), macros, typedefs)
                parameters = [{"name": child.get("name", ""), "canonical_type": _canonical_type(
                    child.get("type", {}).get("desugaredQualType", child.get("type", {}).get("qualType", "")), macros, typedefs)}
                    for child in node.get("inner", []) if child.get("kind") == "ParmVarDecl"]
                body_macros = {}
                for compound in (child for child in node.get("inner", []) if child.get("kind") == "CompoundStmt"):
                    for statement in _walk(compound):
                        for boundary in statement.get("range", {}).values():
                            expansion = boundary.get("expansionLoc") if isinstance(boundary, dict) else None
                            if not expansion or source not in raw_sources:
                                continue
                            offset = expansion.get("offset")
                            if type(offset) is not int:
                                continue
                            token = raw_sources[source][offset:offset + expansion.get("tokLen", 0)].decode("utf-8", errors="replace")
                            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
                                continue
                            observation = {"name": token, "offset": offset, "ast_kind": statement.get("kind"),
                                "referenced_name": statement.get("referencedDecl", {}).get("name"),
                                "value": statement.get("value"), "cast_kind": statement.get("castKind")}
                            body_macros[canonical(observation)] = observation
                row = {"tu_id": entry["tu_id"], "name": name, "source": source, "location": location,
                    "function_id": matches[0]["id"] if len(matches) == 1 else None,
                    "defined": defined, "linkage": "internal" if node.get("storageClass") == "static" else "external",
                    "canonical_type": canonical_type, "return_type": re.sub(r"__attribute__\s*\(\(.*?\)\)", "", canonical_type).split("(", 1)[0].strip(),
                    "parameters": parameters, "calling_convention": _calling_convention(canonical_type),
                    "variadic": bool(node.get("variadic")), "project_owned": source in raw_sources,
                    "symbol_identity": node.get("mangledName", name), "target_abi": target_abi,
                    "compile_arguments": entry["arguments"],
                    "body_macro_expansions": [body_macros[key] for key in sorted(body_macros)]}
                parameter_typedef_tokens = {token for child in node.get("inner", []) if child.get("kind") == "ParmVarDecl"
                    for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", child.get("type", {}).get("qualType", ""))}
                parameter_typedef_tokens.update(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", node.get("type", {}).get("qualType", "")))
                row["typedef_layout_unknown"] = bool(parameter_typedef_tokens & typedef_layout_overrides.keys())
                if row["calling_convention"] in ignored_conventions:
                    row["calling_convention"] = "unknown"
                row["symbol_id"] = "symbol_" + digest(row)[:24]
                unit_symbols.append(row)
            if node.get("kind") == "RecordDecl" and node.get("completeDefinition") and node.get("name") and location:
                name, tag = node["name"], node.get("tagUsed", "struct")
                fields = []
                for child in node.get("inner", []):
                    if child.get("kind") != "FieldDecl":
                        continue
                    canonical_type = _canonical_type(child.get("type", {}).get("desugaredQualType", child.get("type", {}).get("qualType", "")), macros, typedefs)
                    fields.append({"name": child.get("name", ""), "canonical_type": canonical_type,
                        "calling_convention": _calling_convention(canonical_type), "bitfield": bool(child.get("isBitfield")),
                        "callback": bool(re.search(r"\(\s*\*\s*\)\s*\(", canonical_type))})
                    if fields[-1]["calling_convention"] in ignored_conventions:
                        fields[-1]["calling_convention"] = "unknown"
                layout = layout_map.get((tag, name))
                complete = layout is not None and len(layout["fields"]) == len(fields) and not any(f["bitfield"] for f in fields)
                if complete:
                    for field_row, position in zip(fields, layout["fields"]):
                        field_row["offset_bits"] = position["offset_bits"]
                record = {"tu_id": entry["tu_id"], "name": name, "tag": tag, "source": location["source"],
                    "location": location, "fields": fields, "size_bits": layout.get("size_bits") if layout else None,
                    "align_bits": layout.get("align_bits") if layout else None, "layout_complete": complete}
                record["layout_id"] = "layout_" + digest(record)[:24]
                unit_records.append(record)
        units.append({**entry, "dependencies": dep_rows, "dependency_digest": digest(dep_rows),
            "standard_allocation_alignment": allocation_alignment,
            "typedef_layout_overrides": dict(sorted(typedef_layout_overrides.items())),
            "macros": dict(sorted(macros.items())), "macro_digest": digest(macros),
            "syntax_status": "accepted", "diagnostics": diagnostics[:4096],
            "primitive_sizes": {name.removeprefix("__SIZEOF_").removesuffix("__").lower(): int(value)
                for name, value in macros.items() if name.startswith("__SIZEOF_") and name.endswith("__") and value.isdigit()}})
        symbols.extend(unit_symbols); records.extend(unit_records)
    # Hash each dependency again: compiler processes must not observe one file
    # version while the publication claims a different version.
    for filename, expected in all_dependencies.items():
        if file_digest(filename, budget.max_file_bytes) != expected:
            raise BuildAnalysisError("source_changed_during_analysis")
    context_identity = {"schema_version": 1, "policy_version": VERSION, "project_root": str(project),
        "source_fingerprint": source_fp, "functions_fingerprint": functions_fp,
        "functions_document_digest": digest(functions_document), "compile_database": database,
        "compiler": {"path": str(compiler), "sha256": compiler_sha, "version": version.strip(),
            "resource_dir": str(resource_dir) if resource_dir else None},
        "execution_policy": "bounded-clang-no-shell-clean-environment-v1", "budget": asdict(budget),
        "translation_units": units, "dependency_hashes": dict(sorted(all_dependencies.items())),
        "dependency_links": dict(sorted(dependency_links.items())),
        "tree_sitter_source_hashes": dict(functions_document.get("source_hashes", {})),
        "execution_accounting": {"model_calls": 0, "provider_requests": 0, "provider_events": [],
            "clang_subprocess_calls": len(clang_invocations), "clang_invocations": clang_invocations}}
    configuration_digest = digest({"database": database, "compiler": context_identity["compiler"],
        "execution_policy": context_identity["execution_policy"], "budget": asdict(budget)})
    context = {**context_identity, "configuration_digest": configuration_digest,
        "dependency_digest": digest(context_identity["dependency_hashes"]), "analysis_complete": True}
    symbols_document = {"schema_version": 1, "policy_version": VERSION, "configuration_digest": configuration_digest,
        "source_fingerprint": source_fp, "functions_fingerprint": functions_fp,
        "symbols": sorted({r["symbol_id"]: r for r in symbols}.values(), key=lambda r: r["symbol_id"])}
    targets = []
    for function in function_rows:
        definitions = [s for s in symbols if s["function_id"] == function["id"] and s["defined"]]
        signatures = {canonical({key: s[key] for key in ("canonical_type", "parameters", "calling_convention", "linkage", "target_abi", "body_macro_expansions", "compile_arguments", "typedef_layout_unknown")}) for s in definitions}
        status = ("not_in_build" if not definitions else "ambiguous" if len(signatures) > 1 else
            "internal_linkage" if definitions[0]["linkage"] != "external" else
            "unknown" if definitions[0]["symbol_identity"] != definitions[0]["name"] else "callable")
        targets.append({"function_id": function["id"], "name": function["name"], "source": function["file"],
            "status": status, "symbol_ids": sorted(s["symbol_id"] for s in definitions), "link_verified": False})
    targets_document = {"schema_version": 1, "policy_version": VERSION, "configuration_digest": configuration_digest,
        "source_fingerprint": source_fp, "functions_fingerprint": functions_fp, "targets": targets}
    layouts_document = {"schema_version": 1, "policy_version": VERSION, "configuration_digest": configuration_digest,
        "source_fingerprint": source_fp, "functions_fingerprint": functions_fp,
        "layouts": sorted({r["layout_id"]: r for r in records}.values(), key=lambda r: r["layout_id"])}
    documents = {"symbols": symbols_document, "callable_targets": targets_document, "type_layouts": layouts_document}
    context["document_digests"] = {name: digest(value) for name, value in documents.items()}
    context["analysis_digest"] = digest(context)
    return {"compile_context": context, **documents}


def write_analysis(output, documents):
    output = Path(output)
    for name in ("symbols", "callable_targets", "type_layouts", "compile_context"):
        write_json(output / (name + ".json"), documents[name], sort_keys=True, allow_nan=False)
