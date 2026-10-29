"""Quote pinned upstream message/assembly tools for source paths with spaces."""
import difflib
import hashlib
import json
import re

INPUTS={
    'Sandboxie/msgs/Parse.vcxproj':('6ef66c5f8422644823c3bd2df8c44004bb00e8c4c42126f5800f35ce62c09053',0),
    'Sandboxie/core/drv/SboxDrv.vcxproj':('c0fdfb45d403ce1a12640f86a8aaf8e0c4342d130927f1424a949aeecfabac1e',12),
    'Sandboxie/core/dll/SboxDll.vcxproj':('5d0a6379c6e77ae63869cc0173faab1a88033033ec7c165d398585947bc1e75e',22),
    'Sandboxie/core/low/LowLevel.vcxproj':('6c8f36975dd95e0cab111949260955d9619a5447c9b1372fc06dca015c59b3c9',4),
}


def prepare(source,output):
    if output.exists():raise RuntimeError('Preserve previous build-path preparation')
    # Validate every source before emitting any partial layer.
    texts={}
    for name,(digest,count) in INPUTS.items():
        raw=(source/name).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=digest:raise RuntimeError('Unreviewed build project: '+name)
        texts[name]=raw.decode('utf-8-sig').replace('\r\n','\n')
    patch=[];files={}
    for name,before in texts.items():
        if name.endswith('/Parse.vcxproj'):
            old=r'mc /h $(MSBuildProjectDirectory)\$(Configuration) /r $(MSBuildProjectDirectory)\$(Configuration) -u $(MSBuildProjectDirectory)\msgs.mc'
            new=r'mc /h "$(MSBuildProjectDirectory)\$(Configuration)" /r "$(MSBuildProjectDirectory)\$(Configuration)" -u "$(MSBuildProjectDirectory)\msgs.mc"'
            if before.count(old)!=1:raise RuntimeError('Unreviewed message compiler command')
            after=before.replace(old,new)
        else:
            commands=re.findall(r'<Command(?:\s[^>]*)?>(.*?)</Command>',before,re.S)
            count=INPUTS[name][1]
            if before.count('%(FullPath)')!=count or sum(c.count('%(FullPath)') for c in commands)!=count:
                raise RuntimeError('Unreviewed assembly/archive command')
            after=before.replace('%(FullPath)','"%(FullPath)"')
            for path in (r'$(Configuration)\%(Filename).obj',r'$(Platform)\$(Configuration)\%(Filename).obj'):
                after=after.replace('-Fo'+path,'-Fo"'+path+'"')
            path=r'$(SolutionDir)Bin\$(PlatformName)\$(Configuration)\NtCRT.lib'
            after=after.replace('/out:'+path,'/out:"'+path+'"')
        for label,value in [('original',before),('prepared',after)]:
            target=output/label/name;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(value.encode('utf-8'))
        patch.extend(difflib.unified_diff(before.splitlines(True),after.splitlines(True),'a/'+name,'b/'+name))
        files[name]=dict(upstream_sha256=INPUTS[name][0],prepared_sha256=hashlib.sha256(after.encode()).hexdigest())
    (output/'build-paths.patch').write_bytes(''.join(patch).encode('utf-8'))
    (output/'manifest.json').write_text(json.dumps(dict(schema=1,files=files,installed=False),indent=2),encoding='utf-8')
