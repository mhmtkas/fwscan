import json,urllib.request,time,sys,statistics
sys.path.insert(0,"<redacted-scratch-path>")
from purls import from_status, purl, source_of
import re

def qb(purls, timeout=120):
    body=json.dumps({"queries":[{"package":{"purl":p}} for p in purls]}).encode()
    req=urllib.request.Request("https://api.osv.dev/v1/querybatch",data=body,
        headers={"Content-Type":"application/json"})
    t=time.time()
    with urllib.request.urlopen(req,timeout=timeout) as r:
        d=json.load(r); hdr=dict(r.headers)
    return d, time.time()-t, len(body), hdr

real=[]
pairs=[]
for fx,cn in [("debian-bookworm-slim","bookworm"),("debian-bullseye-20220125-slim","bullseye")]:
    d=from_status(f"spike/fixtures/{fx}/var/lib/dpkg/status",cn)
    real+=list(d.values()); pairs+=list(d.keys())

# scale out: same source/version pairs against further Debian releases
scaled=list(real)+[purl(n,v,c) for c in ("trixie","forky") for n,v in pairs]

for label,batch in [("real 2 fixtures", real), ("scaled 3x", scaled)]:
    res,el,nbytes,hdr=qb(batch)
    results=res["results"]
    withv=sum(1 for r in results if r.get("vulns"))
    total=sum(len(r.get("vulns",[])) for r in results)
    paged=sum(1 for r in results if r.get("next_page_token"))
    print(f"{label:<18} n={len(batch):<4} req={nbytes/1024:.1f}KB  {el:.2f}s  "
          f"results={len(results)}  with-vulns={withv}  vulns={total}  paginated={paged}")
    for k in ("X-Ratelimit-Limit","X-Ratelimit-Remaining","Retry-After","Ratelimit-Remaining"):
        if k in hdr: print(f"    header {k}: {hdr[k]}")

print("\n=== repeat latency, n=%d, 5 runs ===" % len(scaled))
lat=[]
for i in range(5):
    _,el,_,_=qb(scaled); lat.append(el); print(f"  run {i+1}: {el:.2f}s")
print(f"  median {statistics.median(lat):.2f}s  min {min(lat):.2f}s  max {max(lat):.2f}s")
print("  rate-limit errors: none" )
