"""Pin original upstream source slices before any model run; no target edits."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess

ROOT=Path(__file__).resolve().parent
UPSTREAM=ROOT.parents[1]/'artifacts/blind_generalization_20260929/upstream'


def truth(name,core,support,resources,inputs,ownership,callbacks,ordering,extra=None):
    return {'schema_version':1,'annotation_kind':'independent_manual_contract','id':name,
        'core_apis':core,'required_support':support,'resources':resources,'input_binding':inputs,
        'ownership':ownership,'callback':callbacks,'ordering':[{'before':a,'after':b} for a,b in ordering],
        'invocation_counts':{},'mandatory_constraints':extra or {},
        'adjudication':'public documented API contracts + pinned source; necessary-contract checks, not exhaustive correctness'}


def res(label,creator,cleanup,uses):
    return {'id':label,'origin':{'api':creator,'kind':'return','parameter':None},
        'consumers':[{'api':api,'parameter':p} for api,p in uses],'cleanup':cleanup,'ownership':'owned','scope':'per_input'}


def inp(api,p,n=None,source='fuzz_data',via=None):
    return {'api':api,'parameter':p,'size_parameter':n,'source':source,'via_api':via}


def own(api,p=None,returned=False,kind='borrowed',release=None):
    return {'api':api,'parameter':p,'return_value':returned,'ownership':kind,'release_api':release}


def main():
    selection=json.loads((ROOT/'real_selection.json').read_text());cases=[]
    for selected in selection['projects']:
        name,project=selected['id'],selected['project'];up=UPSTREAM/project
        sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=up,text=True).strip()
        dest=ROOT/'real'/name;source=dest/'source';source.mkdir(parents=True,exist_ok=False)
        selected['commit_sha']=sha
        if project=='inih':
            originals=['ini.c','ini.h','LICENSE.txt'];sources=['ini.c'];headers=['ini.h'];includes=[];flags=['-std=c11']
            for f in originals:shutil.copy2(up/f,source/f)
        elif project=='http-parser':
            originals=['http_parser.c','http_parser.h','LICENSE-MIT'];sources=['http_parser.c'];headers=['http_parser.h'];includes=[];flags=['-std=c11']
            for f in originals:shutil.copy2(up/f,source/f)
        elif project=='cJSON':
            originals=['cJSON.c','cJSON.h','LICENSE'];sources=['cJSON.c'];headers=['cJSON.h'];includes=[];flags=['-std=c11']
            for f in originals:shutil.copy2(up/f,source/f)
        else:
            originals=[];sources=[];headers=['api/yajl_parse.h'];includes=['.'];flags=['-std=c11','-DYAJL_BUILD']
            for path in sorted((up/'src').glob('*')):
                if path.suffix in {'.c','.h'}:
                    shutil.copy2(path,source/path.name);originals.append(str(path.relative_to(up)))
                    if path.suffix=='.c':sources.append(path.name)
            (source/'api').mkdir()
            (source/'yajl').symlink_to('api',target_is_directory=True)
            for path in sorted((up/'src/api').glob('*.h')):
                shutil.copy2(path,source/'api'/path.name);originals.append(str(path.relative_to(up)))
            template=(up/'src/api/yajl_version.h.cmake').read_text()
            for k,v in (('YAJL_MAJOR','2'),('YAJL_MINOR','1'),('YAJL_MICRO','1')):template=template.replace('${'+k+'}',v)
            (source/'api/yajl_version.h').write_text(template)
        spec={**selected,'set':'blind_real','source_dir':f'real/{name}/source','anchor':selected['target_api'],
              'sources':sources,'headers':headers,'include_paths':includes,'compiler_flags':flags,'link_flags':['-lm'],
              'analysis_scope':'original library implementation/header slice; examples/tests excluded uniformly',
              'source_hashes':{f:hashlib.sha256((up/f).read_bytes()).hexdigest() for f in originals}}
        cases.append(spec)
        if name=='inih_string':
            annotation=truth(name,['ini_parse_string'],[],[],[inp('ini_parse_string','string')],
                [own('ini_parse_string','string'),own('ini_parse_string','user')],
                [{'api':'ini_parse_string','parameter':'handler','kind':'notification','return_policy':'positive_to_continue'}],[],
                {'nul_terminated_input':True,'zero_handler_return_aborts_parse_validly':True})
        elif name=='inih_stream':
            annotation=truth(name,['ini_parse_stream'],[],[],[inp('ini_parse_stream','stream',source='callback')],
                [own('ini_parse_stream','stream'),own('ini_parse_stream','user')],
                [{'api':'ini_parse_stream','parameter':'reader','kind':'input_reader','return_policy':'line_or_null_at_eof','fuzz_input_required':True},
                 {'api':'ini_parse_stream','parameter':'handler','kind':'notification','return_policy':'positive_to_continue'}],[],
                {'input_reader_cannot_be_zero_stub':True,'zero_handler_return_aborts_parse_validly':True})
        elif name=='http_parser_feed':
            annotation=truth(name,['http_parser_execute'],['http_parser_init'],[],[inp('http_parser_execute','data','len')],
                [own('http_parser_execute','parser'),own('http_parser_execute','settings')],[],[('http_parser_init','http_parser_execute')],
                {'mandatory_initialization':{'api':'http_parser_execute','parameter':'parser','initializer':'http_parser_init'},
                 'callback_settings_storage':'zero_initialize_then_optional_callbacks','parser_mode':'valid_http_parser_type'})
        elif name=='cjson_owned':
            annotation=truth(name,['cJSON_ParseWithLength'],['cJSON_Delete'],[res('tree','cJSON_ParseWithLength','cJSON_Delete',[])],
                [inp('cJSON_ParseWithLength','value','buffer_length')],
                [own('cJSON_ParseWithLength','value'),own('cJSON_ParseWithLength',returned=True,kind='owned',release='cJSON_Delete')],[],
                [('cJSON_ParseWithLength','cJSON_Delete')])
        else:
            annotation=truth(name,['yajl_parse'],['yajl_alloc','yajl_free'],[res('handle','yajl_alloc','yajl_free',[('yajl_parse','hand')])],
                [inp('yajl_parse','jsonText','jsonTextLen')],
                [own('yajl_alloc',returned=True,kind='owned',release='yajl_free'),own('yajl_parse','hand'),own('yajl_parse','jsonText')],[],
                [('yajl_alloc','yajl_parse'),('yajl_parse','yajl_free')],{'opaque_requires_creator':True,'null_optional_callbacks_allowed':True})
        (dest/'ground_truth.json').write_text(json.dumps(annotation,indent=2)+'\n')
    (ROOT/'real_manifest.json').write_text(json.dumps({'schema_version':1,'set':'blind_real','cases':cases},indent=2)+'\n')
    (ROOT/'real_selection.json').write_text(json.dumps(selection,indent=2)+'\n')


if __name__=='__main__':main()
