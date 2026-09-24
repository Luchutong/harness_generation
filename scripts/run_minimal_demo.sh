#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-$ROOT/.venv/bin/python}"
ENV_FILE="${ENV_FILE:-$ROOT/.env}"
OUTPUT_DIR="${1:-$ROOT/artifacts/demo_real_json_$(date +%Y%m%d-%H%M%S)}"

if [[ -e "$OUTPUT_DIR" ]]; then
  echo "Output path already exists: $OUTPUT_DIR" >&2
  exit 2
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing LLM environment file: $ENV_FILE" >&2
  echo "Create it from .env.example or set ENV_FILE=/path/to/.env" >&2
  exit 2
fi

if [[ ! -x "$PYTHON_BIN" ]]; then
  python3 -m venv "$ROOT/.venv"
  PYTHON_BIN="$ROOT/.venv/bin/python"
  "$PYTHON_BIN" -m pip install -e "$ROOT"
fi

if ! command -v clang >/dev/null 2>&1; then
  echo "clang is required for build validation" >&2
  exit 2
fi

if ! command -v clang++ >/dev/null 2>&1; then
  echo "clang++ is required for harness build validation" >&2
  exit 2
fi

set -a
. "$ENV_FILE"
set +a

missing=()
for key in LLM_BASE_URL LLM_API_KEY LLM_MODEL; do
  if [[ -z "${!key:-}" ]]; then
    missing+=("$key")
  fi
done
if (( ${#missing[@]} )); then
  echo "Missing LLM variables in $ENV_FILE: ${missing[*]}" >&2
  exit 2
fi

cd "$ROOT"

export DEEPSEEK_API_KEY="$LLM_API_KEY"
SEMANTIC_ENDPOINT="${LLM_BASE_URL%/}"
if [[ "$SEMANTIC_ENDPOINT" != */chat/completions ]]; then
  SEMANTIC_ENDPOINT="$SEMANTIC_ENDPOINT/chat/completions"
fi

"$PYTHON_BIN" -m sfg_builder \
  --project benchmarks/json_parser/project \
  --output "$OUTPUT_DIR" \
  --semantic-analyzer llm \
  --paper-minimal \
  --model "$LLM_MODEL" \
  --endpoint "$SEMANTIC_ENDPOINT" \
  --thinking disabled

"$PYTHON_BIN" - "$OUTPUT_DIR/annotations.json" <<'PY'
import json
from pathlib import Path
import sys

annotations = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["annotations"]
decisions = [decision for item in annotations for decision in item.get("decisions", [])]
if not decisions or any(decision.get("status") != "ok" for decision in decisions):
    raise SystemExit("SFG semantic analysis was incomplete; see annotations.json")
PY

"$PYTHON_BIN" -m harness_generation triplets \
  --artifacts "$OUTPUT_DIR" \
  --individual \
  --paper-minimal

"$PYTHON_BIN" -m harness_generation triplets rank \
  --artifacts "$OUTPUT_DIR" \
  --max-ft 1 \
  --max-calls 20 \
  --max-structural-units 2 \
  --output "$OUTPUT_DIR/ft_selection.json"

"$PYTHON_BIN" - "$OUTPUT_DIR/ft_selection.json" <<'PY'
import json
from pathlib import Path
import sys

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
selected = manifest["selection"]
ranked = {item["triplet_id"]: item for item in manifest["ranking"]}
if len(selected) != 1:
    raise SystemExit("Minimal demo requires exactly one selected FT")
units = ranked[selected[0]["triplet_id"]]["structural_units"]
if not 1 <= units <= 2:
    raise SystemExit("Minimal demo requires one or two Stage 2 units for a single Stage 3 merge")
PY

"$PYTHON_BIN" -m harness_generation generate-all \
  --artifacts "$OUTPUT_DIR" \
  --selection "$OUTPUT_DIR/ft_selection.json" \
  --project-root benchmarks/json_parser/project \
  --target-build benchmarks/json_parser/target_build.json

echo
echo "Demo artifacts: $OUTPUT_DIR"
echo "Generated harnesses:"
find "$OUTPUT_DIR/harnesses" -maxdepth 1 -type f -name '*.c' -print | sort
