#!/usr/bin/env bash
# Fetch a rootfs layer straight from the Docker Hub registry (no daemon) and
# extract it. Args: <tag> <outdir>; REPO_OVERRIDE picks a repository other than
# library/debian, which is how scripts/real-image-matrix.sh reaches Ubuntu,
# Alpine and the rpm-based images.
set -euo pipefail
TAG="$1"; OUT="$2"; REPO="${REPO_OVERRIDE:-library/debian}"; ARCH="amd64"
TOKEN=$(curl -sf "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${REPO}:pull" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
AH="Authorization: Bearer $TOKEN"
ACC='Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'
mkdir -p "$OUT"
curl -sf -H "$AH" -H "$ACC" "https://registry-1.docker.io/v2/${REPO}/manifests/${TAG}" -o "$OUT/index.json"
MDIG=$(python3 - "$OUT/index.json" "$ARCH" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
if "manifests" in d:
    for m in d["manifests"]:
        p=m.get("platform",{})
        if p.get("architecture")==sys.argv[2] and p.get("os")=="linux":
            print(m["digest"]); break
else:
    print("")
PY
)
if [ -n "$MDIG" ]; then
  curl -sf -H "$AH" -H "$ACC" "https://registry-1.docker.io/v2/${REPO}/manifests/${MDIG}" -o "$OUT/manifest.json"
else
  MDIG="(single-arch manifest)"; cp "$OUT/index.json" "$OUT/manifest.json"
fi
LDIG=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["layers"][0]["digest"])' "$OUT/manifest.json")
NLAYERS=$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["layers"]))' "$OUT/manifest.json")
curl -sfL -H "$AH" "https://registry-1.docker.io/v2/${REPO}/blobs/${LDIG}" -o "$OUT/layer.tar.gz"
# verify the blob against the digest the registry advertised
ACTUAL="sha256:$(shasum -a 256 "$OUT/layer.tar.gz" | awk '{print $1}')"
[ "$ACTUAL" = "$LDIG" ] || { echo "DIGEST MISMATCH: $ACTUAL != $LDIG" >&2; exit 1; }
mkdir -p "$OUT/rootfs"
tar -xzf "$OUT/layer.tar.gz" -C "$OUT/rootfs" ./var/lib/dpkg/status ./etc/os-release ./etc/debian_version 2>/dev/null
echo "tag=$TAG"
echo "manifest_digest=$MDIG"
echo "layer_digest=$LDIG"
echo "layers=$NLAYERS"
echo "layer_sha256_verified=yes"
