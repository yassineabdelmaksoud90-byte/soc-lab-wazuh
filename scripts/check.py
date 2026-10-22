import csv, json, sys, glob, gzip
from collections import Counter
from datetime import datetime, timedelta, timezone

fmt = "%Y-%m-%d %H:%M:%S"
rows = list(csv.DictReader(open(sys.argv[1])))
for r in rows:
    r["s"] = datetime.strptime(r["start_utc"], fmt).replace(tzinfo=timezone.utc) - timedelta(seconds=2)
    r["e"] = datetime.strptime(r["end_utc"], fmt).replace(tzinfo=timezone.utc) + timedelta(seconds=20)
    r["names"] = Counter()
    r["tagged"] = False

files = glob.glob("/var/ossec/logs/alerts/*/*/ossec-alerts-*.json*")
files.append("/var/ossec/logs/alerts/alerts.json")
print("files read:", len(files))

for path in files:
    opener = gzip.open if path.endswith(".gz") else open
    for line in opener(path, "rt"):
        try:
            a = json.loads(line)
        except ValueError:
            continue
        if a.get("agent", {}).get("name") != "win-victim":
            continue
        ts = datetime.strptime(a["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z")
        for r in rows:
            if r["s"] <= ts <= r["e"]:
                ru = a["rule"]
                r["names"]["rule %s (level %s): %s" % (ru["id"], ru["level"], ru.get("description","(no description)"))] += 1
                parent = r["technique"].split(".")[0]
                for m in ru.get("mitre", {}).get("id", []):
                    if m == r["technique"] or m.split(".")[0] == parent:
                        r["tagged"] = True

for r in rows:
    sysm = int(r["sysmon_events"])
    total = sum(r["names"].values())
    if r["tagged"]:
        st = "DETECTED"
    elif total:
        st = "CHECK NAMES"
    elif sysm > 0:
        st = "LOGGED ONLY"
    else:
        st = "NOT LOGGED"
    print("\n%s  sysmon=%d  alarms=%d  -> %s" % (r["technique"], sysm, total, st))
    for k, n in r["names"].most_common(4):
        print("   %3d x %s" % (n, k))
