import json,urllib.request,sys
def qb(purls):
    req=urllib.request.Request("https://api.osv.dev/v1/querybatch",
        data=json.dumps({"queries":[{"package":{"purl":p}} for p in purls]}).encode(),
        headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req,timeout=60) as r: return json.load(r)
CVE="DEBIAN-CVE-2022-0778"
# Ground truth (Debian Security Tracker): openssl/bullseye fixed at 1.1.1k-1+deb11u2
cases=[
 ("1.1.1k-1+deb11u1  one revision BEFORE the fix", "1.1.1k-1%2Bdeb11u1", True),
 ("1.1.1k-1+deb11u2  THE backported fix",          "1.1.1k-1%2Bdeb11u2", False),
 ("1.1.1n-0+deb11u1  later upstream",              "1.1.1n-0%2Bdeb11u1", False),
]
print("=== WITH ?distro=bullseye (release-scoped) ===")
r1=qb([f"pkg:deb/debian/openssl@{v}?arch=source&distro=bullseye" for _,v,_ in cases])
ok=True
for (n,_,exp),r in zip(cases,r1["results"]):
    got=CVE in {x["id"] for x in r.get("vulns",[])}
    ok&= got==exp
    print(f"  {n:<44} flagged={str(got):<5} expected={str(exp):<5} {'PASS' if got==exp else 'FAIL'}")
print("  ->", "BACKPORT-AWARE" if ok else "NOT backport-aware")

print("\n=== WITHOUT the distro qualifier (bare purl) ===")
r2=qb([f"pkg:deb/debian/openssl@{v}" for _,v,_ in cases])
for (n,_,exp),r in zip(cases,r2["results"]):
    got=CVE in {x["id"] for x in r.get("vulns",[])}
    print(f"  {n:<44} flagged={str(got):<5} expected={str(exp):<5} {'PASS' if got==exp else 'FALSE POSITIVE'}")
json.dump({"scoped":r1,"bare":r2},open(sys.argv[1],"w"),indent=2)
