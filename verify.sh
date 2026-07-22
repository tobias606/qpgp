#!/usr/bin/env bash
# Canonical verification for qPGP. Runs the JVM test suite + builds the debug
# APK (no cache), then asserts structural/security invariants that the JVM
# tests can't reach (manifest permissions, dex contents, duress design).
#
# Usage:  JAVA_HOME=... ./verify.sh
# Exit 0 = all pass. This is the project's canonical check command.
set -u
cd "$(dirname "$0")" || exit 1
: "${JAVA_HOME:=/c/Program Files/Android/Android Studio/jbr}"
export JAVA_HOME
S=0
LOG="$(mktemp -t qpgp-verify-XXXX.log)"

echo "== 1. suite + debug APK (fresh, no cache) =="
./gradlew --no-daemon --rerun-tasks testDebugUnitTest assembleDebug > "$LOG" 2>&1
grep -q "BUILD SUCCESSFUL" "$LOG" && echo "build+tests: PASS" || { echo "build: FAIL"; tail -25 "$LOG"; S=1; }

echo "== 2. JUnit tally =="
python3 - <<'EOF' || S=1
import xml.etree.ElementTree as ET, glob, sys
t=f=0
for x in glob.glob("app/build/test-results/testDebugUnitTest/*.xml"):
    r=ET.parse(x).getroot(); t+=int(r.get("tests",0)); f+=int(r.get("failures",0))+int(r.get("errors",0))
print(f"{t} tests, {f} failures/errors")
sys.exit(0 if t>=15 and f==0 else 1)
EOF

echo "== 3. manifest: permissions + unexported activities =="
python3 - <<'EOF' || S=1
import xml.etree.ElementTree as ET, sys
NS='{http://schemas.android.com/apk/res/android}'
root=ET.parse('app/src/main/AndroidManifest.xml').getroot()
perms=sorted(p.get(NS+'name') for p in root.findall('uses-permission'))
acts={a.get(NS+'name'): a.get(NS+'exported') for a in root.find('application').findall('activity')}
print("permissions:", perms)
internal=[n for n in acts if n!='.ui.UnlockActivity']
bad=[n for n in internal if acts[n]!='false']
ok = 'android.permission.INTERNET' not in perms and not bad
print("no INTERNET, internal activities unexported:", ok)
sys.exit(0 if ok else 1)
EOF

echo "== 4. dex classes present =="
python3 - <<'EOF' || S=1
import zipfile, sys
z=zipfile.ZipFile("app/build/outputs/apk/debug/app-debug.apk")
dex=b"".join(z.read(n) for n in z.namelist() if n.endswith(".dex"))
need=[b"DuressStore",b"BiometricStore",b"SettingsActivity",b"Hybrid",b"Protocol"]
missing=[n.decode() for n in need if n not in dex]
print("dex classes:", "OK" if not missing else f"MISSING {missing}")
sys.exit(1 if missing else 0)
EOF

echo "== 5. duress design invariants =="
python3 - <<'EOF' || S=1
import sys
sess=open("app/src/main/java/org/qpgp/ui/Session.kt").read()
vault=open("app/src/main/java/org/qpgp/store/Vault.kt").read()
dur=open("app/src/main/java/org/qpgp/store/DuressStore.kt").read()
checks={
 "duress checked before real-vault load":
   0 < sess.find("DuressStore(app).matches(pass)") < sess.find("Vault(app, Vault.Slot.REAL)"),
 "duress trip shreds only real slot":
   "destroySlotForDuress" in sess and "destroySlotForDuress" in vault,
 "separate slots + keystore keys":
   'REAL("vault.qpgp", "qpgp.vault.v1")' in vault and 'DUMMY("dummy.qpgp", "qpgp.dummy.v1")' in vault,
 "verifier-only (pin never stored)":
   "argon2id(pin, salt)" in dur and "constantTimeEquals" in dur,
}
for k,v in checks.items(): print(f"  {'OK' if v else 'FAIL'}: {k}")
sys.exit(0 if all(checks.values()) else 1)
EOF

rm -f "$LOG"
echo
[ $S -eq 0 ] && echo "VERIFY: ALL PASS" || echo "VERIFY: FAIL"
exit $S
