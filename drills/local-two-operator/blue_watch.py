"""A deliberately small stand-in for a blue team's sensors, so a drill has something to be seen by.
It is NOT a SIEM. It has three rules and misses a lot on purpose; what it misses is what the drill measures.

  a watched loopback port starts answering -> L1  "new-listener"
  line added to the app user list     -> L2  "account-created"
  line added to /etc/passwd           -> L2  "local-account-created"   (system mode only)

It does not watch the app config, the hosts file, the data files or the token file.
Usage: python3 blue_watch.py OUT.csv APP_DIR [--system]   (stop it with SIGTERM or Ctrl-C)"""
import csv
import datetime as dt
import signal
import socket
import sys
import threading
import time

out, app = sys.argv[1], sys.argv[2]
system = "--system" in sys.argv
stop = False
signal.signal(signal.SIGTERM, lambda *a: globals().__setitem__("stop", True))


PORTS = [("127.0.0.11", 18080), ("127.0.0.12", 18081), ("127.0.0.13", 18082)]


def is_open(ip, port):
    s = socket.socket(); s.settimeout(2)
    try:
        s.connect((ip, port)); return True
    except OSError:
        return False
    finally:
        s.close()


def nlines(p):
    try:
        return len(open(p).read().splitlines())
    except OSError:
        return 0


def emit(w, fh, host, source, summary, level):
    w.writerow([dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), host, source, summary, level]); fh.flush()


with open(out, "w", newline="") as fh:
    w = csv.writer(fh); w.writerow(["time", "host", "source", "summary", "level"]); fh.flush()
    users, pw = nlines(f"{app}/users.txt"), nlines("/etc/passwd")
    lock = threading.Lock()

    initial = {p: is_open(*p) for p in PORTS}

    def watch_port(ip, port):  # a port that starts answering is a new listener
        was = initial[(ip, port)]
        while not stop:
            now_open = is_open(ip, port)
            if now_open and not was:
                with lock:
                    emit(w, fh, ip, "new-listener", f"new listening port {ip}:{port}", "L1")
            was = now_open
            time.sleep(0.2)

    for ip, port in PORTS:
        threading.Thread(target=watch_port, args=(ip, port), daemon=True).start()
    open(out + ".ready", "w").write("ready")
    print("blue_watch: ready", flush=True)
    while not stop:
        time.sleep(0.2)
        n = nlines(f"{app}/users.txt")
        if n > users:
            with lock:
                emit(w, fh, "127.0.0.11", "account-created", "new account in the app user list", "L2")
        users = n
        if system:
            n = nlines("/etc/passwd")
            if n > pw:
                emit(w, fh, "127.0.0.11", "local-account-created", "new line in /etc/passwd", "L2")
            pw = n
