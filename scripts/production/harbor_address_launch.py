"""One-shot launch/unit contract. Rendering a unit never installs or starts it."""
import hashlib
import math
import os
from pathlib import PurePosixPath
import re
import time

from harbor_address_compose import PinnedCompose, protected_path, remaining, require
from harbor_address_evidence import inspect_evidence
from harbor_address_host import ProductionReadOnly
from harbor_address_package import load_package
from harbor_address_sequence import fingerprint
from harbor_address_session import ProtectedSession, SOURCE_MODULES, legacy_bindings
from harbor_recovery_host import absolute, metadata_spec

FIELDS={'package_path','package_sha256','package_context','journal_path','journal_context',
        'evidence_path','evidence_context','private_path','private_context'}
BUDGETS={'prepare_seconds','mutation_seconds','collection_seconds','termination_seconds'}
UNIT_PROPERTIES=('Id,LoadState,Type,User,Group,ActiveState,SubState,MainPID,InvocationID,NRestarts,'
    'FragmentPath,DropInPaths,NeedDaemonReload,ControlGroup,Restart,KillMode,SendSIGKILL,'
    'KillSignal,FinalKillSignal,RuntimeMaxUSec,RuntimeRandomizedExtraUSec,TimeoutStopUSec,'
    'ExecMainStartTimestampMonotonic,WorkingDirectory,UMask,EnvironmentFiles')

def label(value):
    return type(value) is str and re.fullmatch('[A-Za-z0-9_:.,-]+',value)
def sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}',value)
def file_pin(value):
    require(type(value) is dict and set(value)=={'path','spec'} and absolute(value['path']),'LAUNCH_FILE')
    metadata_spec(value['spec'],file=True)
    require(value['spec']['gid']==0,'LAUNCH_GROUP')

def validate(launch):
    require(type(launch) is dict and set(launch)=={'schema','source','interpreter','bootstrap','session','budgets','supervisor'}
        and launch['schema']=='fds.harbor.address-launch.v1','LAUNCH_SCHEMA')
    source=launch['source']
    require(type(source) is dict and set(source)=={'directory','revision','files'} and absolute(source['directory']) and
        re.fullmatch('[0-9a-f]{40}',source['revision']) and
        set(source['files'])==set(SOURCE_MODULES)|{'harbor_address_launch'},'LAUNCH_SOURCE')
    for pin in source['files'].values():
        metadata_spec(pin,file=True);require(pin['gid']==0,'LAUNCH_GROUP')
    for key in ('interpreter','bootstrap'):file_pin(launch[key])
    require(launch['interpreter']['spec']['mode']&0o100,'LAUNCH_INTERPRETER')
    session=launch['session']
    require(type(session) is dict and set(session)==FIELDS and sha(session['package_sha256']),'LAUNCH_SESSION')
    for k,v in session.items():
        if k.endswith('_path'):require(absolute(v),'LAUNCH_PATH')
        if k.endswith('_context'):require(label(v),'LAUNCH_CONTEXT')
    paths=[session[k] for k in ('package_path','journal_path','evidence_path','private_path')]
    require(all(a!=b and PurePosixPath(a) not in PurePosixPath(b).parents for i,a in enumerate(paths)
                for j,b in enumerate(paths) if i!=j),'LAUNCH_OVERLAP')
    budgets=launch['budgets']
    # Technical parser bound only; no default or operational budget is chosen.
    require(type(budgets) is dict and set(budgets)==BUDGETS and
            all(type(v) is int and 0<v<=86400 for v in budgets.values()) and
            sum(budgets.values())<=86400,'LAUNCH_BUDGETS')
    sup=launch['supervisor']
    require(type(sup) is dict and set(sup)=={'unit','context'} and label(sup['context']) and
            re.fullmatch(r'fds-harbor-address-[a-z0-9][a-z0-9-]{0,63}\.service',sup['unit']),'LAUNCH_SUPERVISOR')
    return launch

def unit_text(launch,*,launch_path,launch_sha256,launch_context):
    validate(launch)
    require(absolute(launch_path) and sha(launch_sha256) and label(launch_context),'LAUNCH_EXTERNAL_PIN')
    budgets=launch['budgets']
    maximum=sum(budgets[k] for k in BUDGETS if k!='termination_seconds')
    argv=[launch['interpreter']['path'],'-I','-S','-B',launch['bootstrap']['path'],'apply',
          '--launch',launch_path,'--sha256',launch_sha256,'--context',launch_context,
          '--timeout',str(budgets['prepare_seconds']),'--execute']
    # All variable tokens were restricted above: no percent/dollar/newline or
    # systemd shell interpretation, expansion or environment-derived argument.
    return '\n'.join(('[Unit]','Description=One-shot reviewed Harbor address change',
        'After=docker.service fds-harbor-ac04-guard.service',
        '[Service]','Type=exec','User=root','Group=root','WorkingDirectory=/','UMask=0077',
        'Restart=no','RemainAfterExit=no','KillMode=control-group','KillSignal=SIGTERM',
        'FinalKillSignal=SIGKILL','SendSIGKILL=yes','RuntimeRandomizedExtraSec=0',
        'RuntimeMaxSec='+str(maximum),'TimeoutStopSec='+str(budgets['termination_seconds']),
        'StandardInput=null','StandardOutput=journal','StandardError=journal',
        'ExecStart='+' '.join(argv),''))

def microseconds(value):
    require(type(value) is str and value not in ('infinity',''),'SUPERVISOR_DURATION')
    if value=='0':return 0
    parts=value.split();total=0
    units={'us':1,'ms':1000,'s':1000000,'min':60000000,'h':3600000000,'d':86400000000}
    for part in parts:
        match=re.fullmatch(r'([0-9]+(?:\.[0-9]{1,6})?)(us|ms|s|min|h|d)',part)
        require(match is not None,'SUPERVISOR_DURATION')
        # Decimal text converted without floating point rounding.
        whole,_,frac=match[1].partition('.')
        scaled=(int(whole)*1000000+int(frac.ljust(6,'0')))*units[match[2]]
        require(scaled%1000000==0,'SUPERVISOR_DURATION')
        total+=scaled//1000000
    return total

class UnitGuard:
    def __init__(self,launch,*,launch_path,launch_sha256,launch_context,systemctl,io=None,clock=time.monotonic):
        self.launch=validate(launch);self.path=launch_path;self.sha=launch_sha256;self.context=launch_context
        self.systemctl,self.io,self.clock=systemctl,io or ProductionReadOnly(clock=clock),clock
        self.text=unit_text(launch,launch_path=launch_path,launch_sha256=launch_sha256,launch_context=launch_context)
        self.generation=None
    def _inspect(self,deadline,*,installed):
        remaining(deadline,self.clock)
        unit=self.launch['supervisor']['unit'];fragment='/run/systemd/system/'+unit
        self.io.pinned(self.path,{'sha256':self.sha,'mode':0o600,'gid':0,'selinux':self.context},'file',deadline)
        self.io.pinned(fragment,{'sha256':hashlib.sha256(self.text.encode()).hexdigest(),'mode':0o644,'gid':0,
                               'selinux':self.launch['supervisor']['context']},'file',deadline)
        # An inactive unit has no invocation/cgroup to attest. All configuration
        # checks are shared with apply; only the required lifecycle state differs.
        props=[k for k in UNIT_PROPERTIES.split(',') if not (installed and k in ('InvocationID','ControlGroup'))]
        rc,raw=self.io.command(self.systemctl,['show',unit,'--no-pager','--property='+','.join(props)],deadline)
        require(rc==0,'SUPERVISOR_QUERY')
        row={}
        for line in raw.decode('utf-8').splitlines():
            k,v=line.split('=',1);require(k not in row,'SUPERVISOR_DUPLICATE');row[k]=v
        # systemctl omits an empty EnvironmentFiles a(sb) array, even with --all.
        # Only normalize this field, after pinning the exact unit without any
        # EnvironmentFile directive. Nonempty values, drop-ins and stale reloads
        # are still rejected below; other missing properties remain errors.
        row.setdefault('EnvironmentFiles','')
        require(set(row)==set(props),'SUPERVISOR_PROPERTIES')
        wanted={'Id':unit,'LoadState':'loaded','Type':'exec','User':'root','Group':'root',
            'ActiveState':'inactive' if installed else 'active','SubState':'dead' if installed else 'running',
            'MainPID':'0' if installed else str(os.getpid()),'NRestarts':'0',
            'FragmentPath':fragment,'DropInPaths':'','NeedDaemonReload':'no',
            'Restart':'no','KillMode':'control-group','SendSIGKILL':'yes',
            'WorkingDirectory':'/','UMask':'0077','EnvironmentFiles':''}
        if not installed:wanted['ControlGroup']='/system.slice/'+unit
        require(all(row[k]==v for k,v in wanted.items()),'SUPERVISOR_CHANGED')
        require(row['KillSignal'] in ('15','SIGTERM') and row['FinalKillSignal'] in ('9','SIGKILL'),'SUPERVISOR_SIGNAL')
        budgets=self.launch['budgets'];maximum=sum(budgets[k] for k in BUDGETS if k!='termination_seconds')
        require(microseconds(row['RuntimeMaxUSec'])==maximum*1000000 and
                microseconds(row['RuntimeRandomizedExtraUSec'])==0 and
                microseconds(row['TimeoutStopUSec'])==budgets['termination_seconds']*1000000,'SUPERVISOR_BUDGET')
        remaining(deadline,self.clock)
        return row
    def verify_installed(self,deadline):
        row=self._inspect(deadline,installed=True)
        require(row['ExecMainStartTimestampMonotonic']=='0','SUPERVISOR_ALREADY_STARTED')
        return {'installed_configuration':'MATCHED','lifecycle':'NEVER_STARTED',
                'running_identity':'NOT_TESTED'}
    def verify(self,deadline):
        row=self._inspect(deadline,installed=False)
        require(re.fullmatch('[0-9a-f]{32}',row['InvocationID']) and row['InvocationID']!='0'*32 and
                re.fullmatch('[0-9]+',row['ExecMainStartTimestampMonotonic']),'SUPERVISOR_GENERATION')
        start=int(row['ExecMainStartTimestampMonotonic'])/1000000
        require(0<start<=self.clock(),'SUPERVISOR_TIME')
        # cgroup v2 ensures detached Compose process groups remain supervised.
        require(self.io.cgroup()==['0::'+row['ControlGroup']],'SUPERVISOR_CGROUP')
        current=(row['InvocationID'],start,os.getpid())
        require(self.generation in (None,current),'SUPERVISOR_GENERATION_CHANGED');self.generation=current
        remaining(deadline,self.clock)
        budgets=self.launch['budgets']
        prepare=start+budgets['prepare_seconds'];mutation=prepare+budgets['mutation_seconds']
        return prepare,mutation,mutation+budgets['collection_seconds']

class GuardedHost:
    def __init__(self,original,guard):self.original,self.guard=original,guard
    def __call__(self,deadline):
        self.guard.verify(deadline)
        result=self.original(deadline)
        self.guard.verify(deadline)
        return result

def runtime_inputs(launch,deadline,*,bootstrap_path,interpreter_path,io):
    validate(launch)
    require(launch['bootstrap']['path']==bootstrap_path and launch['interpreter']['path']==interpreter_path,'LAUNCH_RUNNING_CODE')
    for key in ('bootstrap','interpreter'):io.pinned(launch[key]['path'],launch[key]['spec'],'file',deadline)
    args=launch['session']
    values=load_package(args['package_path'],manifest_sha256=args['package_sha256'],context=args['package_context'].encode(),deadline=deadline)
    pins=values['host-policy.json']['pinned_files']
    required={launch[key]['path']:launch[key]['spec'] for key in ('bootstrap','interpreter')}
    required.update({launch['source']['directory']+'/'+name+'.py':value for name,value in launch['source']['files'].items()})
    require(all(pins.get(path)==value for path,value in required.items()),'LAUNCH_PACKAGE_SOURCE')
    return values

def operate(launch,*,operation,launch_path,launch_sha256,launch_context,deadline,execute,
            bootstrap_path,interpreter_path,clock=time.monotonic):
    validate(launch);remaining(deadline,clock)
    require(operation in ('verify','preflight','ready','unit','apply','inspect') and execute==(operation=='apply'),'LAUNCH_OPERATION')
    if operation=='unit':
        return 0,unit_text(launch,launch_path=launch_path,launch_sha256=launch_sha256,launch_context=launch_context)
    if operation=='verify':
        return 0,dict(stage='SOURCE_LAUNCH_VERIFIED',revision=launch['source']['revision'],runtime='NOT_RUN',runtime_acceptance=False)
    io=ProductionReadOnly(clock=clock)
    values=runtime_inputs(launch,deadline,bootstrap_path=bootstrap_path,interpreter_path=interpreter_path,io=io)
    args={k:v.encode() if k.endswith('_context') else v for k,v in launch['session'].items()}
    if operation=='inspect':
        result=inspect_evidence(args['evidence_path'],context=args['evidence_context'],
                plan_sha256=fingerprint(values['plan.json']),deadline=deadline,clock=clock)
        return (0 if result['valid'] else 2),dict(result,stage='EVIDENCE_READ',runtime_acceptance=False)
    guard=None
    if operation in ('apply','ready'):
        guard=UnitGuard(launch,launch_path=launch_path,launch_sha256=launch_sha256,launch_context=launch_context,
                        systemctl=values['host-policy.json']['tools']['systemctl'],io=io,clock=clock)
    if operation=='ready':guard.verify_installed(deadline)
    if operation=='apply':
        prepare,mutation,collection=guard.verify(deadline);deadline=min(deadline,prepare)
        remaining(deadline,clock)
    session=ProtectedSession(**args,preparation_deadline=deadline,clock=clock)
    if operation in ('preflight','ready'):
        backend=session.sequence._backend
        backend._prewrite(deadline)
        tool=values['host-policy.json']['tools']['compose']
        process=PinnedCompose(binary=tool['path'],binary_sha256=tool['sha256'],binary_context=tool['selinux'].encode(),
            private_directory=args['private_path'],private_context=args['private_context'],clock=clock,
            legacy_bindings=legacy_bindings(values),bind_sources=values['host-policy.json'].get('bind_sources'))
        require(process.call('render',values['model.json'],deadline=deadline)==0,'LAUNCH_RENDER')
        backend._prewrite(deadline)
        supervisor=guard.verify_installed(deadline) if guard else {'installed_configuration':'NOT_TESTED','running_identity':'NOT_TESTED'}
        return 0,dict(stage='INSTALLED_READY_READ_ONLY' if guard else 'PREFLIGHT_READ_ONLY',
            render=process.receipts[-1],supervisor=supervisor,runtime='READ_ONLY',runtime_acceptance=False)
    session.sequence._backend.host=GuardedHost(session.sequence._backend.host,guard)
    guard.verify(deadline)
    result=session.run(mutation_deadline=mutation,collection_deadline=collection)
    sequence=result['sequence']
    status=sequence['status'] if sequence else 'UNKNOWN'
    ok=result['evidence_sealed'] and status=='ADDRESS_APPLIED_HEALTHY_REVIEW_REQUIRED'
    return (0 if ok else 2),dict(stage=status,evidence_sealed=result['evidence_sealed'],reason=result['reason'],
        collection_complete=result['collection']['complete'] if result['collection'] else False,
        daemon_effects_may_continue=result['daemon_effects_may_continue'],
        runtime_acceptance=False,autostart_tested=False)
