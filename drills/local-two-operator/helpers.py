"""Small cross-platform helpers the drill uses inside capture and rollback commands (so they behave the same in sh and cmd.exe)."""
import os
import signal
import socket
import sys
import urllib.request


def main(a):
    cmd = a[0]
    if cmd == "get":  # get URL [POST_DATA]
        data = a[2].encode() if len(a) > 2 else None
        print(urllib.request.urlopen(a[1], data=data, timeout=5).read().decode(), end="")
    elif cmd == "probe":  # probe HOST PORT -> listening / <absent>
        s = socket.socket(); s.settimeout(2)
        try:
            s.connect((a[1], int(a[2]))); print("listening")
        except OSError:
            print("<absent>")
        finally:
            s.close()
    elif cmd == "count":  # count FILE WORD -> how many lines contain WORD, or <absent>
        n = sum(1 for l in open(a[1]) if a[2] in l) if os.path.exists(a[1]) else 0
        print(n if n else "<absent>")
    elif cmd == "drop":  # drop FILE WORD -> remove the lines that contain WORD
        keep = [l for l in open(a[1]) if a[2] not in l]
        open(a[1], "w").write("".join(keep))
    elif cmd == "stop":  # stop PIDFILE
        os.kill(int(open(a[1]).read()), signal.SIGTERM)
    else:
        sys.exit("unknown helper")


if __name__ == "__main__":
    main(sys.argv[1:])
