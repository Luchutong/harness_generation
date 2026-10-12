"""Bind compiler metadata in model transcripts to independently replayed inputs."""
from pathlib import Path

from ..source_analysis import BuildAwareIndex


def analysis_configuration(index, directory):
    if index is None and directory is None:
        return None
    if not isinstance(index, BuildAwareIndex) or directory is None:
        raise ValueError("compiler metadata requires authenticated index and artifact directory")
    return {"directory": str(Path(directory).resolve()), "identity_digest": index.identity_digest,
            "configuration_digest": index.configuration_digest,
            "source_fingerprint": index.source_fingerprint,
            "functions_fingerprint": index.functions_fingerprint}


def replay_analysis(configuration, snapshot):
    if configuration is None:
        return None
    if not isinstance(configuration, dict) or set(configuration) != {
            "directory", "identity_digest", "configuration_digest", "source_fingerprint", "functions_fingerprint"}:
        raise ValueError("invalid compiler metadata transcript identity")
    index = BuildAwareIndex.load(configuration["directory"], snapshot)
    if analysis_configuration(index, configuration["directory"]) != configuration:
        raise ValueError("compiler metadata transcript identity changed")
    return index
