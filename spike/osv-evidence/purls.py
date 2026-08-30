"""Derive OSV query purls from a dpkg status file, per the T0.3 rule."""
import re,urllib.parse
def source_of(fields):
    """Return (source_name, source_version) for a stanza.

    Source: name (version)  -> that name and that version; the two differ for
                               binNMUs and for binaries carrying an epoch the
                               source does not have (bsdutils vs util-linux).
    Source: name            -> that name, binary Version.
    absent                  -> binary Package, binary Version.
    """
    pkg, ver = fields.get("Package"), fields.get("Version","")
    src = fields.get("Source")
    if not src: return pkg, ver
    m = re.match(r'^(\S+)\s*\((.+)\)\s*$', src)
    if m: return m.group(1), m.group(2)
    return src.strip(), ver

def purl(name, version, codename):
    # purl spec: the version is percent-encoded; '+' and ':' must be escaped or
    # they are read as purl syntax.
    v = urllib.parse.quote(version, safe='')
    return f"pkg:deb/debian/{name}@{v}?arch=source&distro={codename}"

def from_status(path, codename):
    out={}
    for st in open(path,encoding='utf-8',errors='replace').read().split("\n\n"):
        f=dict(re.findall(r'^(Package|Source|Version|Status): (.+)$',st,re.M))
        if not f.get("Package") or f.get("Status")!="install ok installed": continue
        n,v=source_of(f)
        out.setdefault((n,v), purl(n,v,codename))   # dedupe: many binaries, one source
    return out
