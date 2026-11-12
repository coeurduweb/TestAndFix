#!/usr/bin/env python3
"""Validate the marker stream produced by in-container.sh for one image.

usage: check_results.py IMAGE OUTPUT_FILE   (exit 0 = pass)
"""
import json
import sys

image, path = sys.argv[1], sys.argv[2]
lines = open(path, errors="replace").read().splitlines()

expect, info, runs = set(), [], {}
cur = None
for ln in lines:
    if ln.startswith("@@ EXPECT "):
        expect.add(ln[10:].strip())
    elif ln.startswith("@@ INFO "):
        info.append(ln[8:])
    elif ln.startswith("@@ RUN "):
        cur = ln[7:].strip()
        runs[cur] = {"json": None, "rc": None}
    elif ln.startswith("@@ RC ") and cur:
        runs[cur]["rc"] = int(ln[6:])
    elif cur and ln.startswith("{"):
        try:
            runs[cur]["json"] = json.loads(ln)
        except ValueError as e:
            runs[cur]["json"] = "INVALID: %s" % e
if "@@ END" not in lines:
    print("FAIL %s: container script did not finish" % image)
    sys.exit(1)

problems = []


def status(j):
    return {a["target"]: a["status"] for a in j["actions"]}


def need(cond, msg):
    if not cond:
        problems.append(msg)


for label, r in runs.items():
    j = r["json"]
    if label in ("bad-option", "exclusive"):
        need(r["rc"] == 2, "%s: rc=%s, want 2" % (label, r["rc"]))
        continue
    need(isinstance(j, dict), "%s: no valid JSON (%s)" % (label, j))
    if not isinstance(j, dict):
        continue
    for k in ("host", "distro", "kernel", "actions", "page_cache", "ok"):
        need(k in j, "%s: missing key %s" % (label, k))
    need(r["rc"] == 0, "%s: rc=%s, want 0 (ok=%s, failed=%s)" % (
        label, r["rc"], j.get("ok"),
        [a for a in j["actions"] if a["status"] == "failed"] +
        ([j["page_cache"]] if j["page_cache"]["status"] == "failed" else [])))
    st = status(j)
    is_dry = "dry" in label
    dns_run = label not in ("pc-dry", "real-pc")
    pc_run = label not in ("dns-dry", "real-dns")
    if dns_run:
        for t in expect:
            want = "skipped" if is_dry else "flushed"
            need(st.get(t) == want, "%s: %s is %r, want %r" % (label, t, st.get(t), want))
        for t, s in st.items():
            if t not in expect:
                need(s == "absent", "%s: unexpected %s=%s" % (label, t, s))
    else:
        need(st == {}, "%s: DNS actions present in page-cache-only run" % label)
    pc = j["page_cache"]
    if pc_run:
        need(pc["status"] in (("skipped",) if is_dry else ("flushed", "skipped")),
             "%s: page_cache status %s" % (label, pc["status"]))
        need(isinstance(pc["before_kb"], int), "%s: before_kb not an int" % label)
    else:
        need(pc["status"] == "skipped" and pc["before_kb"] is None, "%s: page cache touched" % label)

# every shell must agree with the plain `sh` dry-run
ref = runs.get("dry:sh", {}).get("json")
for label, r in runs.items():
    if label.startswith("dry:") and isinstance(r["json"], dict) and isinstance(ref, dict):
        need(status(r["json"]) == status(ref), "%s: statuses differ from dry:sh" % label)

pcs = runs.get("real:sh", {}).get("json", {}).get("page_cache", {}).get("status", "?") if isinstance(runs.get("real:sh", {}).get("json"), dict) else "?"
summary = "expect=%s runs=%d page_cache=%s" % (",".join(sorted(expect)) or "-", len(runs), pcs)
if problems:
    print("FAIL %s: %s" % (image, summary))
    for p in problems:
        print("   - " + p)
    sys.exit(1)
print("PASS %s: %s" % (image, summary))
