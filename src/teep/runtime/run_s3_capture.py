#!/usr/bin/env python3
"""
run_s3_capture.py - Tu dong chay Oracle Proxy va capture traffic thuc te (S3)
cho day du cac nhom Workload CI/CD: Node.js, Python, Go, Java, Docker, Git.

Cac giai doan do luong:
  1. Git: Clone & fetch tags
  2. Node.js: pnpm install & pnpm build
  3. Python: pip install & run test
  4. Go: go mod download & go build
  5. Java: Maven dependency resolve & compile
  6. Docker: docker build
"""
from teep import paths as _P
import argparse
import json
import os
import shutil
import socket
import subprocess
import threading
import time
from collections import Counter
from pathlib import Path

PROXY_PORT = 8889
PROXY_HOST = "127.0.0.1"
OUT_DIR = Path(str(_P.data("measurement/s3_data")))
SUMMARY_FILE = Path(str(_P.data("measurement/s3_observed_full.json")))
TMP_WORK = Path(str(_P.data("tmp_s3_workspace")))


# -----------------------------------------------------------------------------
# LIGHTWEIGHT IN-PROCESS FORWARD PROXY
# -----------------------------------------------------------------------------
class InProcessProxy:
    def __init__(self, host=PROXY_HOST, port=PROXY_PORT):
        self.host = host
        self.port = port
        self.hits = Counter()
        self.first_seen = {}
        self._lock = threading.Lock()
        self._running = False
        self._srv = None
        self._t0 = 0

    def _pipe(self, a, b):
        try:
            while self._running:
                data = a.recv(65536)
                if not data:
                    break
                b.sendall(data)
        except OSError:
            pass

    def _handle(self, client):
        try:
            buf = b""
            while b"\r\n\r\n" not in buf and self._running:
                chunk = client.recv(4096)
                if not chunk:
                    return
                buf += chunk
            if not buf:
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
                host, port = None, 80
                for hline in buf.split(b"\r\n")[1:]:
                    if hline.lower().startswith(b"host:"):
                        hval = hline.split(b":", 1)[1].decode("latin-1").strip()
                        host, _, port_ = hval.partition(":")
                        port = int(port_ or 80)
                        break
                if not host:
                    return

            key = f"{host.lower()}:{port}"
            now = round(time.time() - self._t0, 2)
            with self._lock:
                self.hits[key] += 1
                self.first_seen.setdefault(key, now)
            print(f"    [{now:6.2f}s] {key}", flush=True)

            upstream = socket.create_connection((host, port), timeout=30)
            if method.upper() == "CONNECT":
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                upstream.sendall(buf)

            threading.Thread(target=self._pipe, args=(client, upstream), daemon=True).start()
            self._pipe(upstream, client)
        except Exception:
            pass
        finally:
            try:
                client.close()
            except Exception:
                pass

    def start(self):
        self.hits.clear()
        self.first_seen.clear()
        self._t0 = time.time()
        self._running = True
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((self.host, self.port))
        self._srv.listen(128)
        self._srv.settimeout(0.5)

        def run_loop():
            while self._running:
                try:
                    c, _ = self._srv.accept()
                    threading.Thread(target=self._handle, args=(c,), daemon=True).start()
                except socket.timeout:
                    continue
                except OSError:
                    break

        threading.Thread(target=run_loop, daemon=True).start()

    def stop(self):
        self._running = False
        if self._srv:
            try:
                self._srv.close()
            except Exception:
                pass
        hosts = sorted({k.split(":")[0] for k in self.hits})
        return {
            "duration_s": round(time.time() - self._t0, 2),
            "n_hosts": len(hosts),
            "n_endpoints": len(self.hits),
            "observed_hosts": hosts,
            "endpoints": dict(self.hits.most_common()),
            "first_seen": self.first_seen,
        }


# -----------------------------------------------------------------------------
# DANH SACH WORKLOADS THEO TUNG NHOM HE SINH THAI (TRU RUST & OS)
# -----------------------------------------------------------------------------
WORKLOADS = {
    # 1. GIT WORKLOAD
    "git_clone": {
        "label": "git_clone_checkout",
        "desc": "Git - Clone repository & Fetch tags",
        "tool_check": "git",
        "repo_url": "https://github.com/carbon-language/carbon-lang",
        "run_cmd": "git clone --depth 1 https://github.com/carbon-language/carbon-lang . && git fetch --tags",
    },
    # 2. NODE.JS (INSTALL + BUILD)
    "nodejs_dockit": {
        "label": "nodejs_install_build",
        "desc": "Node.js (pnpm) - Install dependencies & Build project",
        "tool_check": "pnpm",
        "repo_url": "https://github.com/nodejs/doc-kit",
        "run_cmd": "pnpm install --frozen-lockfile --store-dir=./pnpm_store --force && pnpm build",
    },
    # 3. PYTHON (INSTALL + TEST/RUN)
    "python_modelapi": {
        "label": "python_install_test",
        "desc": "Python (pip) - Install requirements & Run pytest",
        "tool_check": "python",
        "repo_url": "https://github.com/open-edge-platform/model_api",
        "run_cmd": "python -m pip install --no-cache-dir requests urllib3 pytest && python -m pytest --version",
    },
    # 4. GO (MOD DOWNLOAD + BUILD)
    "go_apko": {
        "label": "go_mod_and_build",
        "desc": "Go - Download modules & Build binaries",
        "tool_check": "go",
        "repo_url": "https://github.com/chainguard-dev/apko",
        "run_cmd": "go clean -modcache && go mod download && go build ./...",
    },
    # 5. GO (CASE P20 TERRAFORM)
    "go_p20_terraform": {
        "label": "go_p20_corefunc",
        "desc": "Go (P20 Terraform) - Download provider modules",
        "tool_check": "go",
        "repo_url": "https://github.com/northwood-labs/terraform-provider-corefunc",
        "run_cmd": "go clean -modcache && go mod download",
    },
    # 6. JAVA (MAVEN DEPENDENCY & COMPILE)
    "java_maven": {
        "label": "java_maven_compile",
        "desc": "Java (Maven) - Resolve dependencies & Compile",
        "tool_check": "mvn",
        "repo_url": "https://github.com/Hack23/cia",
        "run_cmd": "mvn dependency:resolve-plugins dependency:resolve",
    },
    # 7. DOCKER (DOCKER BUILD)
    "docker_build": {
        "label": "docker_build_image",
        "desc": "Docker - Build container image",
        "tool_check": "docker",
        "repo_url": "https://github.com/madnuttah/unbound-docker",
        "run_cmd": "docker build --no-cache -t test-img-s3 .",
    },
}


def run_single_workload(wid, cfg, proxy):
    print("\n" + "=" * 78)
    print(f"[*] CHAY WORKLOAD [{wid}]: {cfg['desc']}")
    print("=" * 78)

    # Kiem tra xem may da co toolchain nay chua
    tool = cfg["tool_check"]
    if shutil.which(tool) is None:
        print(f"[!] BO QUA: May ban chua cai dat tool '{tool}'. (Cai dat '{tool}' de kich hoat workload nay).")
        return None

    w_dir = TMP_WORK / wid
    if w_dir.exists():
        shutil.rmtree(w_dir, ignore_errors=True)
    w_dir.mkdir(parents=True, exist_ok=True)

    if wid != "git_clone":
        print(f"[*] Clone repository: {cfg['repo_url']}...")
        clone_res = subprocess.run(["git", "clone", "--depth", "1", cfg["repo_url"], str(w_dir)],
                                   capture_output=True, text=True)
        if clone_res.returncode != 0:
            print(f"[!] Loi clone: {clone_res.stderr[:200]}")
            return None

    # Bat dau Proxy
    proxy.start()
    print(f"[*] Proxy dang lang nghe tai {PROXY_HOST}:{PROXY_PORT}")
    print(f"[*] Thuc thi lenh: {cfg['run_cmd']}")

    env = os.environ.copy()
    env["HTTP_PROXY"] = f"http://{PROXY_HOST}:{PROXY_PORT}"
    env["HTTPS_PROXY"] = f"http://{PROXY_HOST}:{PROXY_PORT}"
    env["http_proxy"] = f"http://{PROXY_HOST}:{PROXY_PORT}"
    env["https_proxy"] = f"http://{PROXY_HOST}:{PROXY_PORT}"

    try:
        proc = subprocess.run(cfg["run_cmd"], shell=True, cwd=str(w_dir),
                              env=env, capture_output=True, text=True, timeout=120)
        print(f"[+] Lenh hoan tat voi exit code: {proc.returncode}")
    except subprocess.TimeoutExpired:
        print("[!] Timeout sau 120s, tiep tuc xu ly log capture...")
    except Exception as e:
        print(f"[!] Loi khi chay lenh: {e}")

    captured = proxy.stop()
    captured["workload_id"] = wid
    captured["label"] = cfg["label"]
    captured["description"] = cfg["desc"]

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_file = OUT_DIR / f"{wid}.json"
    out_file.write_text(json.dumps(captured, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n>>> Da bat duoc {captured['n_hosts']} hosts, {captured['n_endpoints']} endpoints -> {out_file}")
    for h in captured["observed_hosts"]:
        print(f"    - {h}")

    return captured


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=list(WORKLOADS.keys()), help="Chi chay 1 workload")
    a = ap.parse_args()

    proxy = InProcessProxy()
    all_results = {}

    target_workloads = [a.only] if a.only else list(WORKLOADS.keys())
    for wid in target_workloads:
        res = run_single_workload(wid, WORKLOADS[wid], proxy)
        if res:
            all_results[wid] = res

    if all_results:
        master_summary = {
            "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "n_workloads": len(all_results),
            "workloads": all_results,
        }
        SUMMARY_FILE.write_text(json.dumps(master_summary, indent=2, ensure_ascii=False), encoding="utf-8")
        print("\n" + "=" * 78)
        print(f"[+] DA HOAN TAT CAPTURE S3 CHO {len(all_results)} WORKLOADS THANH CONG!")
        print(f">>> File tong hop master: {SUMMARY_FILE}")
        print("=" * 78)


if __name__ == "__main__":
    main()