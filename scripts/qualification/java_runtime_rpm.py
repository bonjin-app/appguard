"""Explicit, diagnostic-only RPM profiles. No production/feed approval."""
import hashlib
import json
import posixpath
import re

from scan_container_images import _json

PROFILE = 'rpm-ubi10-v1'
UBI8_PROFILE = 'rpm-ubi8-copy-jre-v1'
PROFILES = (PROFILE, UBI8_PROFILE)
STAGES = ('identity', 'features', 'jre_tree', 'rpm_database_hashes', 'rpm_inventory', 'native_linkage', 'native_providers')
REASONS = frozenset(('not_attempted','measured','tool_unavailable','read_unavailable','query_failed',
    'protocol_unverified','prerequisite_incomplete','identity_unverified','resource_unverified',
    'timeout','cancelled','budget_exhausted','output_limit'))
CHECKS = frozenset(('crypto_p256','aes_gcm','pkcs12_roundtrip','jsse_default_trust','mtls_loopback',
    'utf8_io','locale_data','timezone_data','localhost_nss','headless_font'))
SHA = re.compile(r'[0-9a-f]{64}\Z')
TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+~:%-]{0,199}\Z')
ROOT = '/opt/java/openjdk'
JAVA = ROOT+'/bin/java'
CLASSPATH = '/opt/appguard/java-runtime-probe'
FLAGS = ('-Xms8m','-Xmx64m','-XX:ActiveProcessorCount=1','-XX:-UsePerfData',
    '-Djava.io.tmpdir=/tmp','-Duser.home=/tmp','-Djava.awt.headless=true','-cp',CLASSPATH,'AppGuardRuntimeInventory')
IDLE = ('-Xms8m','-Xmx8m',*FLAGS[2:], 'idle')
ALLOWED_ENV = frozenset(('PATH','JAVA_HOME','JAVA_VERSION','LANG','LANGUAGE','LC_ALL','LC_CTYPE','TZ','container'))


class StopCollection(InterruptedError):
    def __init__(self, reason):
        require(reason in REASONS)
        super().__init__('java_stage_unverified')
        self.reason=reason


def require(value):
    if not value: raise ValueError('java_rpm_inventory_unverified')


def status(attempted=False, complete=False, reason='not_attempted', code=None):
    require(type(attempted) is bool and type(complete) is bool and reason in REASONS
        and (code is None or type(code) is int and -128 <= code <= 255)
        and (attempted or code is None) and (reason != 'not_attempted' or not attempted)
        and complete == (reason == 'measured') and (not complete or attempted and code == 0))
    return dict(attempted=attempted,complete=complete,reason=reason,transport_exit_code=code)


def initial_report(architecture, *, profile=PROFILE):
    require(architecture in ('amd64','arm64') and profile in PROFILES)
    cpu=dict(architecture=architecture,scope='observed_ci_host_only',
        required_baseline='x86-64-v3' if architecture == 'amd64' else 'ARMv8.0-A',
        noble_baseline_preserved=False,host_instruction_baseline_verified=False,cpu_baseline_approved=False)
    if profile == UBI8_PROFILE:
        cpu.update(required_baseline='copied_jre_minimum_unverified',
            declared_base_scope='RHEL8_generic_declared_OS_floor_only',
            provenance='Pinned UBI8 architecture/version and declared RHEL8 OS floor; no copied-JRE ISA or GLIBC measurement',
            copied_jre_minimum_cpu_verified=False,copied_jre_minimum_glibc_verified=False)
    return dict(package_profile=profile, measurement_complete=False, final_identity_verified=False,
        stages={name:status() for name in STAGES}, features=None, package_inventory=None,
        platform_observation=None, cpu_scope=cpu,
        external_approval=False, legal_approval=False, complete_resolved_graph=False)


def validate_environment(rows):
    require(type(rows) is list and len(rows) <= 32)
    seen=set()
    for row in rows:
        require(type(row) is str and len(row) <= 4096 and all(ord(c) >= 32 and ord(c) != 127 for c in row))
        key,sep,value=row.partition('=')
        require(sep and key in ALLOWED_ENV and key not in seen);seen.add(key)
        if key == 'JAVA_HOME':require(value == ROOT)


def parse_envelope(raw):
    require(type(raw) is str and 0 < len(raw.encode()) <= 8*1024*1024 and raw.endswith('\n'))
    row=_json(raw.encode())
    require(type(row) is dict and set(row)=={'schema','complete','reason','data'} and type(row['schema']) is int
        and row['schema']==1 and type(row['complete']) is bool and row['reason'] in REASONS
        and row['reason'] != 'not_attempted' and (row['complete'] == (row['reason']=='measured')))
    return row


def parse_feature_result(row):
    require(type(row) is dict and set(row)=={'schema','checks','checks_passed','result_code','passed'}
        and type(row['schema']) is int and row['schema']==2 and type(row['checks']) is dict
        and set(row['checks'])==CHECKS and type(row['result_code']) is int and row['result_code'] in (0,1,2)
        and type(row['checks_passed']) is bool and type(row['passed']) is bool)
    for value in row['checks'].values():
        require(type(value) is dict and set(value)=={'attempted','passed'} and type(value['attempted']) is bool
            and (type(value['passed']) is bool if value['attempted'] else value['passed'] is None))
    entered=all(value['attempted'] for value in row['checks'].values())
    passed=entered and all(value['passed'] for value in row['checks'].values())
    complete=entered and row['result_code'] in (0,1)
    require(row['checks_passed'] is passed and row['passed'] is (complete and passed)
        and (row['result_code']==2 or entered and (passed == (row['result_code']==0))))
    return row,status(True,complete,'measured' if complete else 'resource_unverified',0)


def parse_packages(raw, architecture):
    require(type(raw) is str and 0 < len(raw.encode()) <= 2*1024*1024 and raw.endswith('\n')
        and '\r' not in raw and '\x00' not in raw and architecture in ('amd64','arm64'))
    rows=raw.splitlines();require(0 < len(rows) <= 1024)
    result=[];seen=set()
    for row in rows:
        fields=row.split('\t');require(len(fields)==7)
        name,epoch,version,release,arch,source,license_text=fields
        require(all(TOKEN.fullmatch(value) for value in (name,version,release))
            and re.fullmatch(r'[0-9]{1,10}',epoch) and int(epoch)<=2147483647)
        pseudo=name=='gpg-pubkey'
        require(arch in (('x86_64' if architecture=='amd64' else 'aarch64'),'noarch') or pseudo and arch=='(none)')
        require(TOKEN.fullmatch(source) and source.endswith('.src.rpm') or pseudo and source=='(none)')
        require(0 < len(license_text.encode()) <= 1024 and all(ord(c)>=32 and ord(c)!=127 for c in license_text))
        key=(name,int(epoch),version,release,arch);require(key not in seen);seen.add(key)
        result.append(dict(name=name,epoch=int(epoch),version=version,release=release,architecture=arch,
            source_rpm=None if source=='(none)' else source,license=None if license_text=='(none)' else license_text,
            metadata_only=pseudo))
    return sorted(result,key=lambda row:(row['name'],row['epoch'],row['version'],row['release'],row['architecture']))


def path(value):
    require(type(value) is str and len(value)<=512 and re.fullmatch(r'/[A-Za-z0-9._+@/:-]+',value)
        and '..' not in value.split('/') and posixpath.normpath(value)==value
        and any(value.startswith(root+'/') for root in ('/lib','/lib64','/usr/lib','/usr/lib64','/usr/local/lib',ROOT)))
    return value


def parse_identity(data, architecture):
    require(type(data) is dict and set(data)=={'uids','gids','pid1_elf','self_elf','java_vendor','java_version','java_runtime_version','os_arch'}
        and all(type(data[key]) is list and len(data[key])==4 and all(type(n) is int and n==10001 for n in data[key]) for key in ('uids','gids')))
    for key in ('pid1_elf','self_elf'):
        header=data[key];require(type(header) is str and re.fullmatch(r'[0-9a-f]{40}',header))
        raw=bytes.fromhex(header)
        require(raw[:6]==b'\x7fELF\x02\x01' and int.from_bytes(raw[16:18],'little') in (2,3)
            and int.from_bytes(raw[18:20],'little')==(62 if architecture=='amd64' else 183))
    require(data['java_vendor']=='Eclipse Adoptium' and data['java_version']=='17.0.20.1'
        and data['java_runtime_version']=='17.0.20.1+1' and data['os_arch']==('amd64' if architecture=='amd64' else 'aarch64'))
    return dict(data,schema=1,native_identity_verified=True,verified=False)


def parse_database(data):
    require(type(data) is list and 0<len(data)<=8)
    tags={'usr-rpmdb.sqlite','usr-rpmdb.sqlite-wal','usr-rpmdb.sqlite-shm',
        'var-rpmdb.sqlite','var-rpmdb.sqlite-wal','var-rpmdb.sqlite-shm','var-Packages','usr-Packages'}
    seen=set()
    for row in data:
        require(type(row) is dict and set(row)=={'tag','sha256','size'} and row['tag'] in tags and row['tag'] not in seen
            and type(row['sha256']) is str and SHA.fullmatch(row['sha256']) and type(row['size']) is int and 0<=row['size']<=64*1024*1024)
        seen.add(row['tag'])
    require(any(tag in seen for tag in ('usr-rpmdb.sqlite','var-rpmdb.sqlite','var-Packages','usr-Packages')))
    return data


def finalize(report):
    stages=report['stages']
    report['inventory_complete']=all(stages[name]['complete'] for name in STAGES if name!='features')
    report['measurement_complete']=report['inventory_complete'] and stages['features']['complete'] and report.get('final_identity_verified') is True and report.get('cleanup') is True
    report['native_checks_passed']=report['measurement_complete'] and bool(report.get('checks')) and all(report['checks'].values()) and type(report.get('features')) is dict and report['features'].get('passed') is True
    report['reason']='native_requirements_met' if report['native_checks_passed'] else 'native_requirements_unmet' if report['measurement_complete'] else 'inventory_unverified'


def collect(report, execute, architecture, tree_parser, ldd_parser, library_path, *, profile=PROFILE):
    """Store validated observations immediately; no disk I/O or retries here."""
    require(profile in PROFILES and report.get('package_profile')==profile)
    def stage(name, mode, args=(), timeout=60):
        report['stages'][name]=status(True,False,'protocol_unverified')
        try:
            row=parse_envelope(execute([JAVA,*FLAGS,mode,*args],timeout))
            report['stages'][name]=status(True,row['complete'],row['reason'],0)
            # A helper could not confirm settlement: do not start another exec.
            if row['reason'] in ('timeout','resource_unverified','cancelled'):raise InterruptedError('java_stage_unverified')
            return row['data'] if row['complete'] else None
        except StopCollection as error:
            report['stages'][name]=status(True,False,error.reason)
            raise
        except InterruptedError:raise
        except (Exception,KeyboardInterrupt) as error:
            category=getattr(error,'category',None)
            if isinstance(error,KeyboardInterrupt) or category=='timeout':
                report['stages'][name]=status(True,False,'cancelled' if isinstance(error,KeyboardInterrupt) else 'timeout',getattr(error,'exit_code',None))
                raise
            report['stages'][name]=status(True,False,'protocol_unverified',getattr(error,'exit_code',None))
            return None
    identity=stage('identity','identity')
    try:report['platform_observation']=parse_identity(identity,architecture)
    except (ValueError,TypeError):
        report['stages']['identity']=status(True,False,'identity_unverified',0);raise ValueError('java_identity_unverified') from None
    value=stage('features','features',timeout=120)
    if value is not None:
        try:report['features'],report['stages']['features']=parse_feature_result(value)
        except ValueError:report['stages']['features']=status(True,False,'protocol_unverified',0)
    elif report['stages']['features']['complete']:report['stages']['features']=status(True,False,'protocol_unverified',0)
    if report['stages']['features']['reason']=='resource_unverified':
        raise StopCollection('resource_unverified')
    raw=stage('jre_tree','tree',timeout=180);tree=None
    if raw is not None:
        try:
            tree=tree_parser(raw,architecture,tree_only=True);report.update(tree)
            require(report['os']['id'] in ('rhel','ubi') and
                (report['os']['version']=='8.10' if profile==UBI8_PROFILE else report['os']['version'].split('.')[0]=='10'))
        except (ValueError,KeyError,TypeError):report['stages']['jre_tree']=status(True,False,'protocol_unverified',0);tree=None
    elif report['stages']['jre_tree']['complete']:report['stages']['jre_tree']=status(True,False,'protocol_unverified',0)
    value=stage('rpm_database_hashes','database-hashes')
    if value is not None:
        try:report['rpm_database_hashes']=parse_database(value)
        except ValueError:report['stages']['rpm_database_hashes']=status(True,False,'protocol_unverified',0)
    elif report['stages']['rpm_database_hashes']['complete']:report['stages']['rpm_database_hashes']=status(True,False,'protocol_unverified',0)
    value=stage('rpm_inventory','rpm')
    if value is not None:
        try:
            require(type(value) is dict and set(value)=={'rows','count'} and type(value['count']) is int)
            raw=value['rows']
            packages=parse_packages(raw,architecture);report['packages']=packages
            require(value['count']==len(packages))
            report['package_inventory']=dict(schema=1,manager='rpm',count=len(packages),query_sha256=hashlib.sha256(raw.encode()).hexdigest(),query_bytes=len(raw.encode()))
            report['_rpm_raw']=raw.encode()
            report.setdefault('checks',{})['package_inventory_complete']=True
            if 'counts' in report:report['counts']['os_packages']=len(packages)
        except ValueError:report['stages']['rpm_inventory']=status(True,False,'protocol_unverified',0)
    elif report['stages']['rpm_inventory']['complete']:report['stages']['rpm_inventory']=status(True,False,'protocol_unverified',0)
    paths=set()
    if tree is not None:
        value=stage('native_linkage','linkage',[row['path'] for row in tree['elfs']],timeout=120)
        if value is not None:
            try:
                require(type(value) is list and len(value)==len(tree['elfs']))
                by_name={row['path']:row for row in value};require(len(by_name)==len(value) and set(by_name)=={row['path'] for row in tree['elfs']})
                for elf in report['elfs']:
                    row=by_name[elf['path']];require(set(row)=={'path','code','lines'} and type(row['code']) is int and 0<=row['code']<=255
                        and type(row['lines']) is list and all(type(line) is str and len(line)<=4096 for line in row['lines']))
                    deps,missing,valid=ldd_parser(row['lines'],row['code'],tree.resolved_files,extra_roots=('/usr/lib64',))
                    elf.update(exit_code=row['code'],dependencies=deps,missing=missing,loader_output_valid=valid)
                    for line in row['lines']:
                        found=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-fA-F]{1,16}\)\s*',line)
                        if found:
                            canonical=path(library_path(found[1],extra_roots=('/usr/lib64',)))
                            if not canonical.startswith(ROOT+'/'):paths.add(canonical)
                report['checks']['linkage_resolved']=all(row['loader_output_valid'] and not row['missing'] for row in report['elfs'])
                report['counts']['missing_dependencies']=sum(len(row['missing']) for row in report['elfs'])
            except (ValueError,KeyError,TypeError):report['stages']['native_linkage']=status(True,False,'protocol_unverified',0)
        elif report['stages']['native_linkage']['complete']:report['stages']['native_linkage']=status(True,False,'protocol_unverified',0)
    else:report['stages']['native_linkage']=status(False,False,'prerequisite_incomplete')
    if report['stages']['native_linkage']['complete'] and report['stages']['rpm_inventory']['complete']:
        value=stage('native_providers','providers',sorted(paths),timeout=120)
        if value is not None:
            try:
                require(type(value) is list and len(value)==len(paths))
                rows={path(row['path']):row for row in value};require(set(rows)==paths and len(rows)==len(value))
                providers={}
                for key,row in rows.items():
                    require(set(row)=={'path','real','sha256','owners'} and SHA.fullmatch(row['sha256']));path(row['real'])
                    owners=parse_packages(row['owners'],architecture)
                    require(all(owner in report['packages'] and not owner['metadata_only'] for owner in owners))
                    providers[hashlib.sha256(key.encode()).hexdigest()]=dict(sha256=row['sha256'],providers=owners)
                for elf in report['elfs']:
                    for dep in elf['dependencies']:
                        if dep['resolution']=='os':dep.update(providers[dep['path_sha256']])
                report['checks']['native_providers_verified']=True
            except (ValueError,KeyError,TypeError):report['stages']['native_providers']=status(True,False,'protocol_unverified',0)
        elif report['stages']['native_providers']['complete']:report['stages']['native_providers']=status(True,False,'protocol_unverified',0)
    else:report['stages']['native_providers']=status(False,False,'prerequisite_incomplete')
    report.setdefault('checks',{})['runtime_features_passed']=report['features'] is not None and report['features']['passed']


def truncate(report):
    for key in ('files','symlinks','packages','elfs','jre_tree_sha256'):report.pop(key,None)
    for name in ('jre_tree','rpm_inventory','native_linkage','native_providers'):
        old=report['stages'][name];report['stages'][name]=status(old['attempted'],False,'output_limit',old['transport_exit_code'])
    finalize(report);report['reason']='output_limit'
