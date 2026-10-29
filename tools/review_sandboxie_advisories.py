"""Record public upstream advisories; do not equate patched version metadata with a security audit."""
from datetime import datetime, timezone
import json
from pathlib import Path
import urllib.request

ROOT=Path(__file__).resolve().parents[1]


def main():
    url='https://api.github.com/repos/sandboxie-plus/Sandboxie/security-advisories?per_page=100'
    request=urllib.request.Request(url,headers={'User-Agent':'ClaudeReset-local-source-review','Accept':'application/vnd.github+json'})
    with urllib.request.urlopen(request,timeout=30) as response:
        if response.headers.get('Link'): raise RuntimeError('Advisories pagination requires review')
        data=json.load(response)
    if not isinstance(data,list):raise RuntimeError('Unexpected advisory response')
    records=[]
    for item in data:
        records.append({key:item.get(key) for key in ('ghsa_id','cve_id','html_url','summary','severity','published_at','updated_at','vulnerabilities')})
    dest=ROOT/'work/release-execution-2026-10-26'
    report={'schema':1,'utc':datetime.now(timezone.utc).isoformat(),'source':url,'reviewed_base':'v1.18.8',
            'advisories':records,'all_applicability_reviewed':False,'absence_of_unknown_vulnerabilities_claimed':False}
    (dest/'upstream-advisories.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({'advisories':len(records),'entries':[{'id':r['ghsa_id'],'versions':r['vulnerabilities']} for r in records]}))


if __name__=='__main__':main()
