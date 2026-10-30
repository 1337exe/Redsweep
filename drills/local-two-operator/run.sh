#!/usr/bin/env bash
# Two-operator drill on this machine. Everything stays on 127.0.0.x and inside one folder.
# Usage: ./run.sh [WORKDIR] [--system]    --system also adds and removes one local user (needs root; use a throwaway machine).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
W="${1:-/tmp/lowtide-drill}"; SYSTEM=0; [ "${2:-}" = "--system" ] && SYSTEM=1
[ "$W" = "--system" ] && { W=/tmp/lowtide-drill; SYSTEM=1; }
rm -rf "$W"; mkdir -p "$W/app" "$W/files"; cd "$W"
export LOWTIDE_HOME="$W/.lowtide"
A() { LOWTIDE_OPERATOR=alpha lowtide "$@"; }   # red operator 1
B() { LOWTIDE_OPERATOR=bravo lowtide "$@"; }   # red operator 2: does the read-backs
C() { LOWTIDE_OPERATOR=casey lowtide "$@"; }   # Control Team
id_of() { grep -oE "$1-[0-9a-f]{5}" | head -1; }
step() { printf '\n=== %s\n' "$*"; }
PIDS=""; trap 'kill $PIDS 2>/dev/null; [ $SYSTEM = 1 ] && userdel drillsvc 2>/dev/null' EXIT

step "setup: engagement, scope, two operators and a Control Team"
A init --name DRILL-1 --client "Local drill" >/dev/null
cat > "$LOWTIDE_HOME/scope.json" <<JSON
{"engagement":"DRILL-1","window":{"start":"2026-01-01T00:00:00Z","end":"2027-12-31T23:59:59Z"},
 "in_scope":{"hosts":["127.0.0.0/24"],"cloud_projects":[],"accounts":[]},"out_of_scope":["127.0.0.99"],
 "forbidden_actions":["denial-of-service"],"roles":{"control_team":["casey"],"red_lead":["alpha"]},"tripwires":["external_party"]}
JSON
cat > "$LOWTIDE_HOME/config.json" <<JSON
{"name":"DRILL-1","client":"Local drill","strict_scope":true,"require_second_operator":true,"min_verify_strength":"auto","assumption_stop_after":2,"sitrep_requires_log":true}
JSON
printf 'mode=standard\nlimit=100\n' > app/app.ini; : > app/users.txt; echo "hello" > files/notes.txt
python3 "$HERE/app.py" "$W/app" 127.0.0.11 18080 & PIDS="$PIDS $!"
python3 "$HERE/blue_watch.py" "$W/blue-timeline.csv" "$W/app" $([ $SYSTEM = 1 ] && echo --system) & PIDS="$PIDS $!"
sleep 1.5
A scope check 127.0.0.99 || true
A wrap --host 127.0.0.99 -- true; echo "(refused: out of scope, exit $?)"

step "alpha: look at the app, then make three recorded changes"
A wrap --host 127.0.0.11 --class network-logon -- curl -s http://127.0.0.11:18080/config; sleep 1
C1=$(A change add --kind config --host 127.0.0.11 --object app.ini --change "limit=9999" --capture "curl -s http://127.0.0.11:18080/config" \
  --rollback-cmd "curl -s -X POST -d limit=100 http://127.0.0.11:18080/config" | id_of C)
A wrap --host 127.0.0.11 --class write-to-disk -- curl -s -X POST -d "limit=9999" http://127.0.0.11:18080/config; sleep 1.5
C2=$(A change add --kind account --host 127.0.0.11 --object "app user drillsvc" --change "add user" --created \
  --capture "grep -c drillsvc $W/app/users.txt | sed 's/^0\$/<absent>/'" \
  --rollback-cmd "sed -i '/drillsvc/d' $W/app/users.txt" | id_of C)
A wrap --host 127.0.0.11 --class user-add -- curl -s -X POST -d drillsvc http://127.0.0.11:18080/users; sleep 1.5
USERACT=$(A log --list | grep user-add -m1 | cut -d" " -f1)
C3=$(A change add --kind infra --host 127.0.0.12 --object "listener 127.0.0.12:18081" --change "serve ./files on 18081" --created --autonomous \
  --capture "bash -c 'exec 3<>/dev/tcp/127.0.0.12/18081' 2>/dev/null && echo listening || echo '<absent>'" \
  --rollback-cmd "kill \$(cat $W/listener.pid)" | id_of C)
A log --host 127.0.0.12 --class process-creation "start a file listener on 127.0.0.12:18081"
( cd files; python3 -m http.server 18081 --bind 127.0.0.12 >/dev/null 2>&1 & echo $! > "$W/listener.pid" ); sleep 1.5
if [ $SYSTEM = 1 ]; then
  C4=$(A change add --kind account --host 127.0.0.11 --object "local user drillsvc" --change "useradd" --created \
    --capture "getent passwd drillsvc || echo '<absent>'" --rollback-cmd "userdel drillsvc" | id_of C)
  A wrap --host 127.0.0.11 --class user-add -- useradd -M -s /usr/sbin/nologin drillsvc; sleep 1.5
fi
: > "$W/hosts"
B change add --kind file --host 127.0.0.13 --object hosts-line --change "add line" --created --capture "grep -c files.example $W/hosts | sed 's/^0\$/<absent>/'" --rollback-cmd "sed -i '/files.example/d' $W/hosts" >/dev/null
printf '10.0.0.5 files.example\n' > "$W/hosts"
B log --host 127.0.0.13 --class write-to-disk "add a line to the hosts file on 127.0.0.13"
echo "(bravo changed a host that blue does not watch)"

step "a failing path: two attempts on the same wrong assumption"
A log --host 127.0.0.11 --layer authorization --result fail --assumption "admin cookie works on /admin" "GET /admin returned 403"
A log --host 127.0.0.11 --layer authorization --result fail --assumption "admin cookie works on /admin" "GET /admin returned 403 again"

step "blue-side analyst escalates (staged): freeze, SITREP, recommendation, decision, resume"
sleep 1
X=$(B detect L3 --host 127.0.0.11 --source blue-lead --action "$(A log --list -n 50 | grep "users" | head -1 | cut -d" " -f1)" --evidence "staged: incident opened after the new-account alert" | id_of X)
A freeze --reason "blue escalated to L3 (staged)"
A log --host 127.0.0.11 "try to keep going"; echo "(refused while frozen, exit $?)"
LASTA=$(A log --list | head -1 | cut -d' ' -f1)
A sitrep --status "frozen at L3" --observed "an incident was opened on 127.0.0.11" --assessed "our new-account change was seen" --ask "Control Team to decide" --risk "client responders may act on our assets" --based-on "$LASTA" | tail -2
R=$(A recommend limited-purple --why "alert was caused by us; let blue finish triage" | id_of R)
D=$(C decide limited-purple --by casey --why "tell the analyst this is the engagement, keep scope as is" --recommended-by alpha | id_of D)
C resume --approved-by casey --decision "$D"

step "teardown: alpha rolls back; one rollback is left incomplete on purpose"
A teardown | head -12
A change rollback "$C3" --run --verify || true
A change rollback "$C2" --how "removed user line" --run --verify || true
# incomplete: restore only part of the config
A change rollback "$C1" --how "restored limit but left the 'mode' line edited" --verify || true
printf 'mode=changed\nlimit=100\n' > app/app.ini
B change verify "$C1" || echo "(bravo's read-back caught it: exit $?)"
printf 'mode=standard\nlimit=100\n' > app/app.ini
B change verify "$C1" && echo "(fixed and verified by bravo)"
B change verify "$C2"; B change verify "$C3"
[ $SYSTEM = 1 ] && { A change rollback "$C4" --run --verify; B change verify "$C4"; }
B change rollback "$(B change list | grep hosts-line | awk '{print $1}')" --run --verify
A change verify "$(A change list | grep hosts-line | awk '{print $1}')"

step "closeout gate"
A close --check | head -20
A close --out "$W/out" | tail -8
A review "$W/blue-timeline.csv" --window 1 | tee "$W/review.txt" | head -40
A navigator "$W/blue-timeline.csv" --out "$W/out/navigator.json" >/dev/null
A verify-pack "$W/out/closeout-pack.zip" | tail -4
echo; echo "drill folder: $W"
