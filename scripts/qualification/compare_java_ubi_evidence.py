#!/usr/bin/env python3
"""Bind diagnostic Noble/UBI observations; never approve a production base."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import java_runtime_rpm as rpm
from java_runtime_dependencies import private_publication,check_private_parent
from scan_container_images import _json,_path,file_identity,verify_files

BASES=dict(noble='sha256:07fa0356cf354c5252947575f42ed42aa6fd921f36438b7bc77ad81c31c537dd',
    ubi='sha256:25c83f52d080115d99d80eaeda67a5221b07b7066ae8248fdd37f6e1c6469aef')
UBI8_BASE='sha256:c851eaf99ddf32811fdf8a216c2609cd0e55317ab8c46ecbaa3ea8298532f055'
NATIVE_CHECKS=frozenset(('elf_platform_matches','java_identity_matches','release_identity_matches','required_files_present',
    'symlinks_contained','linkage_resolved','package_inventory_complete','native_providers_verified','runtime_features_passed'))
FALSE_FLAGS=('release_ready','native_binary_coverage','coverage_complete')


def require(value):
    if not value:raise ValueError('java_ubi_comparison_unverified')


def sha(raw):return hashlib.sha256(raw).hexdigest()


def tree_digest(value):
    from inspect_java_runtime import relative,ROOT
    rows=[];seen=set();files=value.get('files');links=value.get('symlinks');counts=value.get('counts')
    require(type(files) is list and type(links) is list and 0<len(files)+len(links)<=4096 and type(counts) is dict
        and counts.get('regular_files')==len(files) and counts.get('symlinks')==len(links))
    total=0
    for row in files:
        require(type(row) is dict and set(row)=={'path','sha256','size'} and type(row['sha256']) is str and rpm.SHA.fullmatch(row['sha256'])
            and type(row['size']) is int and 0<=row['size']<=512*1024*1024)
        name=relative(row['path']);require(name not in seen);seen.add(name);total+=row['size']
        rows.append(dict(kind='file',**row))
    require(total<=1024*1024*1024)
    for row in links:
        require(type(row) is dict and set(row)=={'path','target','target_sha256','within_jre'} and row['within_jre'] is True
            and type(row['target']) is str and 0<len(row['target'])<=512 and re.fullmatch(r'[A-Za-z0-9._+@/:-]+',row['target'])
            and row['target_sha256']==sha(row['target'].encode()))
        name=relative(row['path']);require(name not in seen);seen.add(name)
        target=posixpath.normpath(row['target'] if row['target'].startswith('/') else ROOT+'/'+posixpath.dirname(name)+'/'+row['target'])
        require(target.startswith(ROOT+'/'));rows.append(dict(path=name,kind='symlink',target=row['target']))
    rows.sort(key=lambda row:row['path']);digest=sha(json.dumps(rows,sort_keys=True,separators=(',',':')).encode())
    require(value.get('jre_tree_sha256')==digest);return digest


def supporting_records(value,platform,profile=rpm.PROFILE):
    stages=value['stages'];architecture=platform.split('/')[1]
    cpu=value.get('cpu_scope');expected_cpu=rpm.initial_report(architecture,profile=profile)['cpu_scope']
    require(type(cpu) is dict and cpu==expected_cpu and all(type(cpu[key]) is type(expected_cpu[key]) for key in expected_cpu))
    if stages['identity']['complete']:
        row=value.get('platform_observation')
        require(type(row) is dict and row.get('schema')==1 and type(row.get('schema')) is int
            and row.get('native_identity_verified') is True and type(row.get('verified')) is bool)
        rpm.parse_identity({key:row.get(key) for key in ('uids','gids','pid1_elf','self_elf',
            'java_vendor','java_version','java_runtime_version','os_arch')},architecture)
        if value['final_identity_verified']:
            require(row['verified'] and row.get('host_os')=='linux' and row.get('daemon_os')=='linux'
                and row.get('host_machine')==('x86_64' if architecture=='amd64' else 'aarch64') and row.get('daemon_architecture')==architecture)
    if stages['rpm_database_hashes']['complete']:rpm.parse_database(value.get('rpm_database_hashes'))
    if stages['rpm_inventory']['complete']:
        info=value.get('package_inventory');packages=value.get('packages')
        require(type(info) is dict and set(info)=={'schema','manager','count','query_sha256','query_bytes'}
            and type(info['schema']) is int and info['schema']==1 and info['manager']=='rpm'
            and type(info['count']) is int and 0<info['count']<=1024 and type(info['query_bytes']) is int and 0<info['query_bytes']<=2*1024*1024
            and type(info['query_sha256']) is str and rpm.SHA.fullmatch(info['query_sha256'])
            and type(packages) is list and len(packages)==info['count'])
        rows=[]
        for row in packages:
            require(type(row) is dict and set(row)=={'name','epoch','version','release','architecture','source_rpm','license','metadata_only'}
                and type(row['epoch']) is int and type(row['metadata_only']) is bool
                and all(type(row[key]) is str for key in ('name','version','release','architecture'))
                and all(row[key] is None or type(row[key]) is str for key in ('source_rpm','license')))
            rows.append('\t'.join((row['name'],str(row['epoch']),row['version'],row['release'],row['architecture'],
                row['source_rpm'] if row['source_rpm'] is not None else '(none)',row['license'] if row['license'] is not None else '(none)'))+'\n')
        require(rpm.parse_packages(''.join(rows),architecture)==packages)
    if stages['native_linkage']['complete']:
        require(stages['jre_tree']['complete'])
        files={row['path']:row for row in value.get('files',[])};elfs=value.get('elfs')
        require(type(elfs) is list and 0<len(elfs)<=256 and len(elfs)==value.get('counts',{}).get('elf_files'))
        seen=set()
        for row in elfs:
            require(type(row) is dict and row.get('path') in files and row['path'] not in seen and row.get('sha256')==files[row['path']]['sha256']
                and type(row.get('exit_code')) is int and 0<=row['exit_code']<=255 and type(row.get('loader_output_valid')) is bool
                and type(row.get('missing')) is list and type(row.get('dependencies')) is list and len(row['dependencies'])<=512)
            seen.add(row['path'])
            for dep in row['dependencies']:
                require(type(dep) is dict and dep.get('resolution') in ('virtual','os','bundled_jre'))
                if dep['resolution']=='os' and stages['native_providers']['complete']:
                    require(type(dep.get('sha256')) is str and rpm.SHA.fullmatch(dep['sha256']) and type(dep.get('providers')) is list
                        and dep['providers'] and all(owner in value['packages'] and owner['metadata_only'] is False for owner in dep['providers']))
    require(not stages['native_providers']['complete'] or stages['native_linkage']['complete'] and stages['rpm_inventory']['complete'])


def native(value,image,platform,ubi,profile=rpm.PROFILE):
    require(type(value) is dict and type(value.get('schema')) is int and value['schema']==(4 if ubi else 2)
        and value.get('evidence_class')=='owned_java_runtime_inventory' and value.get('image_id')==image and value.get('platform')==platform
        and all(value.get(key) is False for key in FALSE_FLAGS)
        and all(type(value.get(key)) is bool for key in ('inventory_complete','native_checks_passed','cleanup')))
    checks=value.get('checks',{})
    require(type(checks) is dict and set(checks)<=NATIVE_CHECKS and all(type(flag) is bool for flag in checks.values()))
    if value['inventory_complete']:require(set(checks)==NATIVE_CHECKS)
    features=value.get('features')
    if ubi:
        require(value.get('package_profile')==profile and type(value.get('measurement_complete')) is bool
            and type(value.get('final_identity_verified')) is bool and type(value.get('stages')) is dict
            and set(value['stages'])==set(rpm.STAGES)
            and all(value.get(key) is False for key in ('external_approval','legal_approval','complete_resolved_graph')))
        for row in value['stages'].values():
            require(type(row) is dict and set(row)=={'attempted','complete','reason','transport_exit_code'})
            require(row==rpm.status(row['attempted'],row['complete'],row['reason'],row['transport_exit_code']))
        if features is not None:
            _,expected=rpm.parse_feature_result(features)
            require(value['stages']['features']==expected)
        else:require(not value['stages']['features']['complete'])
        supporting_records(value,platform,profile)
        expected=copy.deepcopy(value);rpm.finalize(expected)
        require(all(value[key] is expected[key] for key in ('inventory_complete','measurement_complete','native_checks_passed')))
        complete=value['measurement_complete'];tree_complete=value['stages']['jre_tree']['complete']
        if profile==rpm.UBI8_PROFILE and (tree_complete or value.get('os') is not None):
            operating=value.get('os')
            require(type(operating) is dict and operating.get('id') in ('rhel','ubi')
                and operating.get('version')=='8.10' and operating.get('architecture')==platform.split('/')[1])
    else:
        if features is not None:
            require(type(features) is dict and set(features)=={'schema','checks','passed','exit_code'} and type(features['schema']) is int
                and features['schema']==1 and type(features['checks']) is dict and set(features['checks'])==rpm.CHECKS
                and all(type(flag) is bool for flag in features['checks'].values()) and type(features['passed']) is bool
                and features['passed'] is all(features['checks'].values()) and type(features['exit_code']) is int
                and features['exit_code'] in (0,1,2) and (features['exit_code']==0 if features['passed'] else features['exit_code'] in (1,2)))
        complete=value['inventory_complete'] and value['cleanup'] and features is not None and features['exit_code'] in (0,1)
        require(not value['inventory_complete'] or features is not None and features['exit_code'] in (0,1))
        features_passed=features is not None and features['passed']
        require(checks.get('runtime_features_passed',False) is features_passed)
        require(value['native_checks_passed'] is (complete and bool(checks) and all(checks.values()) and features_passed))
        tree_complete=value['inventory_complete']
    digest=tree_digest(value) if tree_complete else None
    return dict(collection_complete=complete,native_checks_passed=value['native_checks_passed'],features=features),digest


def compare_reports(documents,images,platform,*,profile=rpm.PROFILE,base_index=None,jre_source_index=None):
    # Pins describe this fixed recipe; they are not independent image ancestry.
    require(profile in rpm.PROFILES)
    if profile==rpm.UBI8_PROFILE:
        require(base_index==UBI8_BASE and jre_source_index==BASES['noble'])
    else:
        require(base_index in (None,BASES['ubi']) and jre_source_index in (None,BASES['noble']))
    require(type(images) is dict and set(images)=={'noble','ubi'} and len(set(images.values()))==2
        and all(type(image) is str and re.fullmatch(r'sha256:[0-9a-f]{64}',image) for image in images.values())
        and platform in ('linux/amd64','linux/arm64') and type(documents) is dict and set(documents)=={'noble','ubi','diagnostic'}
        and all(type(raw) is bytes and 0<len(raw)<=2*1024*1024 for raw in documents.values()))
    values={key:_json(raw) for key,raw in documents.items()};observed={};digests=[]
    for role in ('noble','ubi'):
        result,digest=native(values[role],images[role],platform,role=='ubi',profile);observed[role]=result;digests.append(digest)
    scan=values['diagnostic']
    require(type(scan) is dict and type(scan.get('schema')) is int and scan['schema']==1
        and scan.get('evidence_class')=='diagnostic_image_vulnerability_comparison' and scan.get('platform')==platform
        and type(scan.get('measurement_complete')) is bool and type(scan.get('images')) is list and len(scan['images'])==2
        and all(scan.get(key) is False for key in (*FALSE_FLAGS,'external_approval','complete_resolved_graph')))
    counts={}
    for row,role in zip(scan['images'],('noble','ubi')):
        require(type(row) is dict and row.get('image_id')==images[role] and type(row.get('vulnerabilities')) is int
            and 0<=row['vulnerabilities']<=100000 and type(row.get('finding_details_complete')) is bool
            and type(row.get('zero_findings_interpretable')) is bool)
        # Neither RPM diagnostic has a reviewed distribution-specific feed control.
        if role=='ubi':require(row['zero_findings_interpretable'] is False)
        counts[role]=row['vulnerabilities']
    require(type(scan.get('vulnerabilities')) is int and scan['vulnerabilities']==sum(counts.values()))
    require(not scan['measurement_complete'] or all(row['finding_details_complete'] and
        (row['vulnerabilities']>0 or row['zero_findings_interpretable']) for row in scan['images']))
    complete=all(row['collection_complete'] for row in observed.values()) and scan['measurement_complete']
    result=dict(schema=1,evidence_class='same_image_ubi_runtime_diagnostic',platform=platform,image_ids=images.copy(),
        sha256={key:sha(raw) for key,raw in documents.items()},base_index_pins=BASES.copy(),artifact_bindings_verified=True,
        collection_complete=complete,whole_jre_identity_matches=digests[0] is not None and digests[0]==digests[1],
        reported_native_results=observed,reported_findings=counts,ubi_feed_status='unverified',
        release_ready=False,external_approval=False,native_binary_coverage=False,coverage_complete=False,
        complete_resolved_graph=False,cpu_baseline_approved=False,legal_approval=False,
        limitations=['selected fixed CI host only; UBI10 x86-64-v3 cannot replace the current Noble CPU scope',
            'original reports and complete tree records are bound; full scanner/native semantics are not independently repeated',
            'Debian13 calibration does not verify Red Hat10 feed coverage; zero UBI findings are unverified',
            'no production deployment, native vulnerability closure, external or legal approval'])
    if profile==rpm.UBI8_PROFILE:
        result.update(evidence_class='same_image_ubi8_copy_jre_runtime_diagnostic',package_profile=profile,
            base_index_pins=dict(noble=BASES['noble'],ubi=UBI8_BASE),jre_source_index_pin=BASES['noble'],
            recipe_pin_scope='fixed_recipe_inputs_not_independent_image_ancestry',
            limitations=['selected fixed CI host only; copied-JRE minimum CPU, GLIBC and host-kernel compatibility remain unverified',
                'whole vendor JRE records including classes.jsa, legal, security and symlinks participate in equality',
                'original reports are bound; full scanner/native semantics are not independently repeated',
                'Debian13 calibration does not verify UBI8 feed coverage; zero UBI8 findings are unverified',
                'no production deployment, native vulnerability closure, external or legal approval'])
    return result


class Parser(argparse.ArgumentParser):
    def error(self,message):raise ValueError('java_ubi_comparison_unverified')


def main(argv=None):
    parser=Parser(description=__doc__)
    for name in ('input','output','noble-image','ubi-image','platform'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--ubi-profile',choices=rpm.PROFILES,default=rpm.PROFILE)
    parser.add_argument('--ubi-base-index')
    parser.add_argument('--jre-source-index')
    try:
        args=parser.parse_args(argv);root=_path(args.input,directory=True);output=_path(args.output,new=True)
        parent=output.parent.stat();require(parent.st_uid==os.getuid() and not parent.st_mode&0o022)
        paths=dict(noble=root/'native/noble/java-runtime.json',ubi=root/'native/ubi/java-runtime.json',diagnostic=root/'scan/diagnostic.json')
        documents={};pins={}
        for key,path in paths.items():
            pin,raw=file_identity(path,2*1024*1024,keep=True);documents[key]=raw;pins[path]=(2*1024*1024,pin)
        value=compare_reports(documents,dict(noble=args.noble_image,ubi=args.ubi_image),args.platform,
            profile=args.ubi_profile,base_index=args.ubi_base_index,jre_source_index=args.jre_source_index)
        rpm_info=_json(documents['ubi']).get('package_inventory')
        if rpm_info is not None:
            path=root/'native/ubi/rpm-inventory.tsv';pin,raw=file_identity(path,2*1024*1024,keep=True)
            require(pin['sha256']==rpm_info['query_sha256'] and len(raw)==rpm_info['query_bytes'])
            packages=rpm.parse_packages(raw.decode(),args.platform.split('/')[1]);ubi=_json(documents['ubi'])
            require(len(packages)==rpm_info['count'] and ('packages' not in ubi or packages==ubi['packages']))
            pins[path]=(2*1024*1024,pin);value['rpm_query_sha256']=pin['sha256']
        sources=Path(__file__).resolve().parent;source_pins={}
        names=('inspect_java_runtime.py','java_runtime_rpm.py','java-runtime-probe.Dockerfile','java/AppGuardRuntimeProbe.java','java/AppGuardRuntimeInventory.java')
        if args.ubi_profile==rpm.UBI8_PROFILE:
            names+=('compare_java_ubi_evidence.py','../../.github/workflows/java-ubi8-copy-jre.yml')
        for name in names:
            # Normalize these fixed source names without following symlinks;
            # file_identity still rejects symlink components and file changes.
            path=Path(os.path.normpath(sources/name))
            pin=file_identity(path,512*1024);pins[path]=(512*1024,pin);source_pins[name]=pin['sha256']
        value['collector_source_sha256']=source_pins
        raw=(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode();require(len(raw)<=32768)
        with private_publication(output) as publication:
            publication.write('comparison.json',raw);verify_files(pins);check_private_parent(publication)
            publication.publish();verify_files(pins);check_private_parent(publication)
        print(json.dumps({key:value[key] for key in ('artifact_bindings_verified','collection_complete','release_ready')},sort_keys=True))
        return 2 if not value['collection_complete'] else 0 if value['whole_jre_identity_matches'] and all(row['native_checks_passed'] for row in value['reported_native_results'].values()) and not sum(value['reported_findings'].values()) else 1
    except (Exception,KeyboardInterrupt):
        print('{"artifact_bindings_verified":false,"collection_complete":false,"release_ready":false}')
        return 2


if __name__=='__main__':raise SystemExit(main())
