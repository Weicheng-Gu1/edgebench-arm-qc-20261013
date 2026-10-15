"""Unmodified OCI stream validator algorithm; no QAP results borrowed. Origin SHA ac71127d22ddbbbf8351c1c47d0ee74bb0f7b26110e07a5f2d568bb338a06752"""
import hashlib,json,tarfile
from pathlib import Path
class HashingReader:
    def __init__(self,stream):self.stream=stream;self.hasher=hashlib.sha256();self.bytes=0
    def read(self,size=-1):
        data=self.stream.read(size);self.hasher.update(data);self.bytes+=len(data);return data

def validate_OCI_stream(stream):
    reader=HashingReader(stream);members={};index=None;layout=None
    with tarfile.open(fileobj=reader,mode='r|')as tar:
        for member in tar:
            name=member.name.removeprefix('./');p=Path(name)
            assert not p.is_absolute()and'..'not in p.parts,name
            if member.isdir():continue
            assert member.isfile()and name not in members,('nonregular/duplicate',name)
            h=hashlib.sha256();size=0;small=bytearray()if member.size<=8*1024**2 else None
            with tar.extractfile(member)as blob:
                while chunk:=blob.read(8*1024**2):
                    h.update(chunk);size+=len(chunk)
                    if small is not None:small.extend(chunk)
            assert size==member.size
            digest=h.hexdigest()
            if name.startswith('blobs/sha256/'):assert name=='blobs/sha256/'+digest,('blob SHA mismatch',name)
            parsed=None
            if small is not None:
                try:parsed=json.loads(small)
                except(UnicodeDecodeError,json.JSONDecodeError):pass
            members[name]={'bytes':size,'sha256':digest,'json':parsed}
            if name=='index.json':index=parsed
            if name=='oci-layout':layout=parsed
    while reader.read(8*1024**2):pass
    assert layout=={'imageLayoutVersion':'1.0.0'}
    assert isinstance(index,dict)and index.get('schemaVersion')==2
    checked={};platforms=[];configs=[]
    def visit(desc):
        digest=desc['digest'];assert digest.startswith('sha256:')
        member=members['blobs/sha256/'+digest[7:]]
        assert member['bytes']==desc['size']and member['sha256']==digest[7:]
        if digest in checked:return
        media=desc.get('mediaType','');checked[digest]={'bytes':member['bytes'],'mediaType':media}
        if media.endswith(('index.v1+json','manifest.list.v2+json')):
            for child in member['json']['manifests']:visit(child)
        elif media.endswith(('manifest.v1+json','manifest.v2+json')):
            manifest=member['json'];visit(manifest['config'])
            for child in manifest['layers']:visit(child)
            config=members['blobs/sha256/'+manifest['config']['digest'][7:]]['json']
            actual=config['os']+'/'+config['architecture'];platforms.append(actual)
            configs.append({'platform':actual,'config':config,'manifest_digest':digest,'manifest':manifest})
            if 'platform'in desc:assert desc['platform']['os']+'/'+desc['platform']['architecture']==actual
    for desc in index['manifests']:visit(desc)
    assert sorted(platforms)==['linux/amd64','linux/arm64'],platforms
    assert set(name for name in members if name.startswith('blobs/sha256/'))=={'blobs/sha256/'+d[7:]for d in checked},'unreferenced OCI blob'
    return {'index':index,'oci_layout':layout,'all_blob_SHA_and_descriptor_size_verified':True,
            'checked_descriptors':checked,'actual_platforms':platforms,'image_configs':configs,
            'actual_exported_OCI_tar_bytes':reader.bytes,'actual_exported_OCI_tar_SHA256':reader.hasher.hexdigest(),
            'OCI_large_payload_stored_or_uploaded':False,'stored_OCI_payload_bytes':0}

