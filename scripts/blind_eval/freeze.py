"""Create a new immutable production identity before selecting blind inputs."""
import argparse
from dataclasses import asdict
from datetime import datetime,timezone
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import tarfile

from .identity import ROOT,fingerprint
from harness_generation.semantic_discovery.provider_config import load_environment_file,agent_configuration
from harness_generation.semantic_discovery.models import ValidationBudget
from harness_generation.harness_context.models import ContextBudget


COMPONENTS={
    'semantic_discovery.models':('SCHEMA_VERSION','POLICY_VERSION'),
    'semantic_slicing.models':('SLICE_POLICY_VERSION',),
    'minimal_ft.models':('SCHEMA_VERSION','POLICY_VERSION'),
    'harness_context.models':('POLICY_VERSION','REQUIREMENT_VERSION','PROMPT_VERSION','TOOL_VERSION','SCHEMA_VERSION'),
    'harness_context.construction':('VERSION',),
    'harness_context.resource_identity':('VERSION',),
    'harness_context.input_contracts':('VERSION',),
    'harness_context.ordering':('VERSION',),
    'context_generation.builder':('PLAN_POLICY',),
    'context_generation.stage4':('PROMPT_VERSION',),
    'context_generation.validation':('CODE_VALIDATOR_VERSION',),
    'context_generation.build':('BUILD_POLICY_VERSION',),
}


def create(directory,env_file):
    destination=directory.resolve()/'freeze';destination.mkdir(parents=True,exist_ok=False)
    load_environment_file(env_file)
    git=lambda *args:subprocess.check_output(['git',*args],cwd=ROOT,text=True)
    sources=sorted([*(ROOT/'harness_generation').rglob('*.py'),*(ROOT/'sfg_builder').rglob('*.py')])
    digest=lambda paths:{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    versions={name:{attr:getattr(importlib.import_module('harness_generation.'+name),attr) for attr in attrs}
              for name,attrs in COMPONENTS.items()}
    manifest={'schema_version':1,'frozen_at':datetime.now(timezone.utc).isoformat(),
        'git_commit':git('rev-parse','HEAD').strip(),'branch':git('branch','--show-current').strip(),
        'dirty_status':git('status','--short').splitlines(),'source_fingerprint':fingerprint(),
        'source_files':digest(sources),'root_runtime_dependencies':digest(sorted(ROOT.glob('*.py'))),
        'versions':versions,'provider':agent_configuration('openai-compatible').to_dict(),
        'budgets':{'validation':asdict(ValidationBudget()),'context':asdict(ContextBudget())},
        'code_max_tokens':8192,'code_temperature':0.2,'agent_temperature':'provider default','seed':'unspecified',
        'model_changes_allowed':False,'semantic_changes_allowed':False,
        'real_projects_selected':False,'ground_truth_available_to_pipeline':False}
    (destination/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (destination/'tracked.patch').write_text(git('diff','--','harness_generation','sfg_builder'))
    with tarfile.open(destination/'implementation.tar.gz','w:gz') as archive:
        for file in [*sources,*sorted(ROOT.glob('*.py'))]:archive.add(file,arcname=str(file.relative_to(ROOT)))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--env-file',type=Path,default=ROOT/'.env');args=parser.parse_args();create(args.output,args.env_file)
