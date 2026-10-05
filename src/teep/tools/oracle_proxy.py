#!/usr/bin/env python3
"""
oracle_proxy.py - Do tap dich THUC SU CAN (R) cua mot workload CI.

Y TUONG: chay workload sau mot HTTPS proxy chi lam MOT viec — ghi lai
moi CONNECT roi chuyen tiep. Khong giai ma TLS, khong doc noi dung.
Ket qua la danh sach host:port ma workload that su ket noi toi.

Do chinh la R trong cong thuc:
    Coverage  = |R n E| / |R|
    Tightness = |R| / |E|

CHAY
    # terminal 1
    python oracle_proxy.py --port 8888 --out r_npm.json

    # terminal 2
    export HTTPS_PROXY=http://127.0.0.1:8888
    export HTTP_PROXY=http://127.0.0.1:8888
    npm install express          # hoac pip install, go mod download...

    # Ctrl+C terminal 1 -> ghi file

UU DIEM so voi tcpdump/eBPF:
  - Khong can root, khong can NET_ADMIN
  - Chay duoc trong container binh thuong
  - Ghi duoc TEN MIEN, khong chi IP (tcpdump chi thay IP)

HAN CHE (phai ghi vao Limitations):
  - Chi bat duoc traffic ton trong bien HTTP(S)_PROXY
  - Khong bat duoc ket noi raw TCP hay UDP (vd DNS truc tiep, git://)
  - Mot so tool bo qua proxy -> can doi chieu voi tcpdump neu can chac chan
"""

import argparse
import json
import signal
import socket
import threading
import time
from collections import Counter
from pathlib import Path

HITS = Counter()
FIRST_SEEN = {}
_lock = threading.Lock()


def pipe(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(client, verbose):
    upstream = None
    try:
        client.settimeout(30)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = client.recv(4096)
            if not chunk:
                return
            buf += chunk
            if len(buf) > 65536:
                return

        line = buf.split(b"\r\n", 1)[0].decode("latin-1")
        parts = line.split()
        if len(parts) < 2:
            return
        method, target = parts[0], parts[1]

        if method.upper() == "CONNECT":
            host, _, port = target.partition(":")
            port = int(port or 443)
        else:
            # HTTP thuong: lay host tu absolute URI hoac header Host
            host, port = None, 80
            if "://" in target:
                rest = target.split("://", 1)[1]
                hostport = rest.split("/", 1)[0]
                host, _, p = hostport.partition(":")
                port = int(p or 80)
            if not host:
                for ln in buf.decode("latin-1").split("\r\n"):
                    if ln.lower().startswith("host:"):
                        hp = ln.split(":", 1)[1].strip()
                        host, _, p = hp.partition(":")
                        port = int(p or 80)
                        break
            if not host:
                return

        key = f"{host}:{port}"
        with _lock:
            HITS[key] += 1
            FIRST_SEEN.setdefault(key, round(time.time() - T0, 2))
        if verbose:
            print(f"  [{time.time()-T0:7.2f}s] {key}", flush=True)

        upstream = socket.create_connection((host, port), timeout=30)
        if method.upper() == "CONNECT":
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        else:
            upstream.sendall(buf)

        t = threading.Thread(target=pipe, args=(client, upstream), daemon=True)
        t.start()
        pipe(upstream, client)
    except Exception:
        pass
    finally:
        for s in (client, upstream):
            if s:
                try:
                    s.close()
                except OSError:
                    pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8888)
    ap.add_argument("--out", default="required_set.json")
    ap.add_argument("--label", default="workload", help="ten workload, ghi vao file")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--duration", type=int, default=0, help="tu dung sau N giay")
    a = ap.parse_args()

    global T0
    T0 = time.time()

    # 'kill %1' / 'kill <pid>' gui SIGTERM: Python thoat NGAY, khong chay khoi
    # finally -> MAT TOAN BO du lieu da thu duoc. Doi SIGTERM thanh
    # KeyboardInterrupt de di qua dung duong thoat co ghi file.
    def _on_term(signum, frame):
        raise KeyboardInterrupt
    try:
        signal.signal(signal.SIGTERM, _on_term)
    except (ValueError, OSError, AttributeError):
        pass

    def save(final=False):
        """Ghi ket qua ra file. Goi dinh ky, KHONG doi luc thoat.

        Ly do: tren Git Bash/mintty (va khi chay qua 'uv run'), Ctrl+C
        thuong giet tien trinh ngay o tang Windows, khoi finally khong bao
        gio chay -> mat sach du lieu. Ghi dinh ky thi du bi giet kieu gi,
        file van con du lieu toi lan luu gan nhat.
        """
        with _lock:
            hosts = sorted({k.split(":")[0] for k in HITS})
            out = {
                "label": a.label,
                "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "duration_s": round(time.time() - T0, 1),
                "n_endpoints": len(HITS),
                "n_hosts": len(hosts),
                "required_set": hosts,
                "endpoints": dict(HITS.most_common()),
                "first_seen_s": dict(FIRST_SEEN),
            }
        Path(a.out).write_text(json.dumps(out, indent=1), encoding="utf-8")
        return hosts

    def autosave():
        while True:
            time.sleep(5)
            try:
                save()
            except Exception:
                pass

    threading.Thread(target=autosave, daemon=True).start()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # CHU Y WINDOWS: SO_REUSEADDR tren Windows KHAC tren Linux — no cho phep
    # bind de len mot port DANG duoc tien trinh khac dung, khong bao loi.
    # Hau qua: chay proxy thu hai tren cung port se "thanh cong" gia tao,
    # nhung traffic lai chay vao proxy CU -> file ket qua rong ma khong hieu vi sao.
    # Tren Windows dung SO_EXCLUSIVEADDRUSE de bao loi ro rang thay vi im lang.
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", a.port))
    except OSError as e:
        raise SystemExit(
            f"Khong bind duoc port {a.port}: {e}\n"
            f"  -> Gan nhu chac chan con mot proxy CU dang chay tren port nay.\n"
            f"  -> Git Bash : ps | grep python   roi  kill -9 <pid>\n"
            f"  -> PowerShell: Get-NetTCPConnection -LocalPort {a.port}\n"
            f"  -> Hoac chay lai voi --port khac."
        )
    srv.listen(128)
    print(f"Proxy nghe tai 127.0.0.1:{a.port}")
    print(f"  export HTTPS_PROXY=http://127.0.0.1:{a.port}")
    print(f"  export HTTP_PROXY=http://127.0.0.1:{a.port}")
    print("Ctrl+C de dung va ghi ket qua.\n")

    # Luon dat timeout, ke ca khi khong dung --duration: accept() block vo han
    # tren Windows khong nhan Ctrl+C giua chung (KeyboardInterrupt chi duoc
    # kiem tra khi Python co quyen dieu khien, ma accept() block o tang OS).
    srv.settimeout(1.0)
    if a.duration:
        deadline = time.time() + a.duration
    try:
        while True:
            if a.duration and time.time() > deadline:
                break
            try:
                c, _ = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle, args=(c, not a.quiet), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        hosts = save(final=True)
        print(f"\n>>> {len(hosts)} host, {len(HITS)} endpoint -> {a.out}")
        for h in hosts:
            print(f"    {h}")


if __name__ == "__main__":
    main()
