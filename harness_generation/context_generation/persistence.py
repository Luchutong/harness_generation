"""Authenticate frozen artifacts without depending on legacy triplet catalogs."""
from copy import deepcopy
import re

from ..entry_candidates import CandidateCatalog
from ..harness_context.completeness import HarnessContextCompletenessValidator
from ..harness_context.models import ContextBudget, MiningState
from ..harness_context.persistence import context_directory, load_context_documents
from ..minimal_ft.models import ProjectSnapshot
from ..minimal_ft.persistence import _load_json, _owned, load_slice_input, build_configuration
from ..minimal_ft.validation import MinimalFTValidator
from ..semantic_discovery.models import digest
from ..semantic_discovery.tools import RepositoryIndex
from ..sfg_adapter import load_sfg_artifacts


def load_frozen_inputs(store, ft_id):
    snapshot = ProjectSnapshot.from_artifacts(load_sfg_artifacts(store.root))
    index = RepositoryIndex(snapshot.artifacts, CandidateCatalog((), snapshot.source_fingerprint), functions_path=store.functions)
    # Authenticate indexed live sources even if mining needed no source-range
    # query. Phase 1 bodies alone do not establish that today's build matches.
    for filename in sorted(index.files):
        path = index.owned_path(filename)
        with path.open("rb") as stream:
            data = stream.read(2 * 1024 * 1024 + 1)
        if len(data) > 2 * 1024 * 1024:
            raise ValueError("indexed source exceeds validation limit")
        text = data.decode("utf-8")
        normalized = re.sub(r"\s+", "", text)
        for function in snapshot.artifacts.functions:
            if function["file"] == filename and function.get("defined") and (
                    function.get("body", "") not in text or re.sub(r"\s+", "", function["signature"].rstrip(";")) not in normalized):
                raise ValueError("live source differs from the frozen function snapshot")
        for struct in (*snapshot.artifacts.structs, *snapshot.artifacts.callback_typedefs):
            # Phase 1 normalizes declaration whitespace, unlike body text.
            if struct["file"] == filename and re.sub(r"\s+", "", struct["declaration"]) not in normalized:
                raise ValueError("live source differs from the frozen type snapshot")
    directory = store.minimal_ft_run(ft_id)
    ft = _load_json(_owned(directory / "minimal_ft.json", store.root))
    metadata = _load_json(_owned(directory / "metadata.json", store.root))
    config = metadata["configuration"]
    source = load_slice_input(store, ft["candidate_id"])
    projected = deepcopy(ft)
    # The frozen diagnostic stays immutable. Its legacy catalog is not an
    # executable dependency of this chain; validate the actual FT projection.
    projected.pop("legacy_comparison", None)
    if (ft["ft_id"] != ft_id or metadata["minimal_ft_digest"] != digest(ft)
            or metadata["configuration_fingerprint"] != digest(config)
            or config != build_configuration(source, snapshot, config["legacy_inputs"], compare_legacy=config["compare_legacy"])
            or MinimalFTValidator().validate(projected, source, snapshot)):
        raise ValueError("invalid or stale frozen Minimal FT")
    root = context_directory(store, ft_id)
    marker = _load_json(_owned(root / "metadata.json", store.root))
    config = marker["configuration"]
    if (config["minimal_ft_digest"] != digest(ft) or config["minimal_ft_metadata_digest"] != digest(metadata)
            or config["source_fingerprint"] != snapshot.source_fingerprint
            or config["functions_fingerprint"] != snapshot.functions_fingerprint):
        raise ValueError("frozen Context belongs to another FT or snapshot")
    documents = load_context_documents(store, ft_id, config, index)
    if not documents:
        raise ValueError("Context publication or live-source validation failed")
    state = MiningState(ContextBudget(**config["budget"]))
    state.evidence = {row["evidence_id"]: row for row in documents["evidence"]["records"]}
    state.discoveries = marker["discoveries"]
    context, closure, report = (documents[key] for key in ("harness_context", "api_closure", "completeness"))
    actual = HarnessContextCompletenessValidator().validate(context, closure, ft, snapshot,
        documents["requirements"]["requirements"], documents["resolutions"]["resolutions"], state)
    if actual != report or actual["generation_allowed"] is not True or context["frozen"] is not True:
        raise ValueError("generation blocked: Context is not frozen and complete under current validators")
    return ft, context, closure, snapshot, report, index
