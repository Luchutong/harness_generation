"""Pinned, original library sources and independent contracts, before native calls."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parent
REPO=ROOT.parents[2]
UPSTREAM=REPO/'artifacts/blind_generalization_v2_20260929/upstream'


def main():
    selection=json.loads((ROOT/'real_selection.json').read_text());cases=[]
    for record in selection['cases']:
        case=dict(record);key={'tomlc99_owned_string':'tomlc99','expat_opaque_feed':'expat','libcsv_callback':'libcsv','mpack_stream_tree':'mpack'}[case['id']]
        original=UPSTREAM/key;source=ROOT/'real'/case['id']/'source';source.mkdir(parents=True,exist_ok=False)
        def copy(file,destination=None):
            target=source/(destination or file);target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(original/file,target)
        if key=='tomlc99':
            for name in ('toml.c','toml.h','LICENSE'):copy(name)
            files=['toml.c'];headers=['toml.h'];flags=['-std=c11']
            core=['toml_parse'];support=['toml_free'];resources=[{'id':'table','origin':{'api':'toml_parse','kind':'return','parameter':None},'consumers':[{'api':'toml_free','parameter':'tab'}],'cleanup':'toml_free','ownership':'owned','scope':'per_input'}]
            bindings=[{'api':'toml_parse','parameter':'conf','source':'fuzz_data','size_parameter':None,'via_api':None}]
            ownership=[{'api':'toml_parse','parameter':None,'return_value':True,'ownership':'owned','release_api':'toml_free'},{'api':'toml_parse','parameter':'conf','return_value':False,'ownership':'borrowed','release_api':None}]
            callbacks=[];ordering=[('toml_parse','toml_free')];constraints={'nul_terminated_input':True}
            ref='static void run(const unsigned char*b,size_t n){char*s=malloc(n+1);if(!s)return;memcpy(s,b,n);s[n]=0;char err[128];toml_table_t*t=toml_parse(s,err,sizeof(err));if(t)toml_free(t);free(s);}'
        elif key=='expat':
            for p in sorted((original/'expat/lib').iterdir()):
                if p.suffix in ('.c','.h'):copy(str(p.relative_to(original)),p.name)
            copy('expat/COPYING','LICENSE')
            shutil.copy2(REPO/'artifacts/blind_generalization_v2_20260929/expat_build/expat_config.h',source/'expat_config.h')
            files=['xmlparse.c','xmlrole.c','xmltok.c','random_arc4random.c','random_arc4random_buf.c','random_getentropy.c','random_getrandom.c'];headers=['expat.h'];flags=['-std=c11','-DHAVE_EXPAT_CONFIG_H','-D_GNU_SOURCE']
            core=['XML_Parse'];support=['XML_ParserCreate','XML_ParserFree'];resources=[{'id':'parser','origin':{'api':'XML_ParserCreate','kind':'return','parameter':None,'alternatives':['XML_ParserCreateNS','XML_ParserCreate_MM']},'consumers':[{'api':'XML_Parse','parameter':'parser'},{'api':'XML_ParserFree','parameter':'parser'}],'cleanup':'XML_ParserFree','ownership':'owned','scope':'per_input'}]
            bindings=[{'api':'XML_Parse','parameter':'s','source':'fuzz_data','size_parameter':'len','via_api':None}]
            ownership=[{'api':'XML_ParserCreate','api_alternatives':['XML_ParserCreateNS','XML_ParserCreate_MM'],'parameter':None,'return_value':True,'ownership':'owned','release_api':'XML_ParserFree'},{'api':'XML_Parse','parameter':'parser','return_value':False,'ownership':'borrowed','release_api':None}]
            callbacks=[];ordering=[('XML_ParserCreate','XML_Parse'),('XML_Parse','XML_ParserFree')];constraints={'creator_only':True,'length_int_bounded':True,'final_flag_valid_boolean':True}
            ref='static void run(const unsigned char*b,size_t n){XML_Parser p=XML_ParserCreate(NULL);if(p){XML_Parse(p,(const char*)b,(int)n,1);XML_ParserFree(p);}}'
        elif key=='libcsv':
            for name in ('libcsv.c','csv.h','COPYING'):copy(name)
            files=['libcsv.c'];headers=['csv.h'];flags=['-std=c11'];core=['csv_parse'];support=['csv_init','csv_free'];resources=[]
            bindings=[{'api':'csv_parse','parameter':'s','source':'fuzz_data','size_parameter':'len','via_api':None}]
            ownership=[{'api':'csv_parse','parameter':'s','return_value':False,'ownership':'borrowed','release_api':None},{'api':'csv_parse','parameter':'p','return_value':False,'ownership':'borrowed','release_api':None}]
            callbacks=[{'api':'csv_parse','parameter':'cb1','kind':'notification','return_policy':'void'},{'api':'csv_parse','parameter':'cb2','kind':'notification','return_policy':'void'}]
            ordering=[('csv_init','csv_parse'),('csv_parse','csv_free')];constraints={'parser_init_required':True}
            ref='static void field(void*s,size_t n,void*u){(void)s;(void)n;(void)u;}static void row(int c,void*u){(void)c;(void)u;}static void run(const unsigned char*b,size_t n){struct csv_parser p;if(!csv_init(&p,0)){csv_parse(&p,b,n,field,row,NULL);csv_free(&p);}}'
        else:
            for p in sorted((original/'src/mpack').iterdir()):
                if p.suffix in ('.c','.h'):copy(str(p.relative_to(original)),'mpack/'+p.name)
            copy('LICENSE');files=['mpack/'+p.name for p in sorted((original/'src/mpack').glob('*.c'))];headers=['mpack/mpack.h'];flags=['-std=c11']
            core=['mpack_tree_parse'];support=['mpack_tree_destroy'];resources=[]
            bindings=[];ownership=[{'api':'mpack_tree_parse','parameter':'tree','return_value':False,'ownership':'borrowed','release_api':None}];callbacks=[]
            ordering=[('mpack_tree_parse','mpack_tree_destroy')];constraints={'initializer_alternatives':{'consumer':'mpack_tree_parse','apis':['mpack_tree_init_data','mpack_tree_init_pool','mpack_tree_init_stream','mpack_tree_init']},'input_transport_needs_audit':True}
            ref='static void run(const unsigned char*b,size_t n){mpack_tree_t t;mpack_tree_init_data(&t,(const char*)b,n);mpack_tree_parse(&t);mpack_tree_destroy(&t);}'
        case.update(commit_sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=original,text=True).strip(),set='blind_real',source_dir=f"real/{case['id']}/source",anchor=case['target_api'],sources=files,headers=headers,include_paths=['.'],compiler_flags=flags,link_flags=['-lm'],analysis_scope='original library sources/headers only; excludes examples, tests, fuzzers',source_hashes={str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(source.rglob('*')) if p.is_file()})
        truth={'schema_version':1,'annotation_kind':'independent_manual_contract','id':case['id'],'core_apis':core,'required_support':support,'resources':resources,'input_binding':bindings,'ownership':ownership,'callback':callbacks,'ordering':[{'before':a,'after':b} for a,b in ordering],'invocation_counts':{},'mandatory_constraints':constraints,'adjudication':'pinned public API/source contracts; valid factory alternatives predeclared; runtime does not replace independent semantics'}
        (source.parent/'ground_truth.json').write_text(json.dumps(truth,indent=2)+'\n')
        (source.parent/'reference.c').write_text('#include "source/'+headers[0]+'"\n#include <stdlib.h>\n#include <string.h>\n'+ref+'\nint main(void){unsigned char b[256];for(size_t i=0;i<256;i++)b[i]=(unsigned char)i;for(size_t n=0;n<=256;n++)run(b,n);return 0;}\n')
        cases.append(case)
    (ROOT/'real_manifest.json').write_text(json.dumps({'schema_version':1,'set':'blind_real','cases':cases},indent=2)+'\n')


if __name__=='__main__':main()
