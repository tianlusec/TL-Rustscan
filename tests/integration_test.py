import subprocess
import socket
import threading
import time
import json
import os
import sys

HOST = "127.0.0.1"
PORTS_TO_OPEN = [33333, 44444]
PORT_CLOSED = 55555
EXE_PATH_RELEASE = os.path.join("target", "release", "TL-Rustscan.exe")
EXE_PATH_DIST = os.path.join("dist", "TL-Rustscan.exe")

def get_executable():
    if os.path.exists(EXE_PATH_DIST):
        return EXE_PATH_DIST
    if os.path.exists(EXE_PATH_RELEASE):
        return EXE_PATH_RELEASE
    
    return None

def start_dummy_server(port, stop_event):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind((HOST, port))
        server_sock.listen(1)
        server_sock.settimeout(1.0)
        
        while not stop_event.is_set():
            try:
                conn, addr = server_sock.accept()
                conn.close()
            except socket.timeout:
                continue
            except Exception as e:
                break
    except Exception as e:
        print(f"[!] Failed to bind {port}: {e}")
    finally:
        server_sock.close()

def run_test():
    exe = get_executable()
    if not exe:
        print("错误: 找不到 TL-Rustscan.exe。")
        print("请先安装 Rust 并运行 'cargo build --release' 或 'build.bat' 进行编译。")
        sys.exit(1)

    print(f"[*] Found executable: {exe}")

    stop_event = threading.Event()
    threads = []
    for port in PORTS_TO_OPEN:
        t = threading.Thread(target=start_dummy_server, args=(port, stop_event))
        t.start()
        threads.append(t)

    time.sleep(1)

    try:
        ports_arg = f"{PORTS_TO_OPEN[0]},{PORTS_TO_OPEN[1]},{PORT_CLOSED}"
        cmd = [exe, HOST, "-p", ports_arg, "--json", "--show-closed"]
        
        print(f"[*] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, encoding='utf-8', errors='ignore')

        if result.returncode != 0:
            print(f"[!] Tool execution failed with code {result.returncode}")
            print(result.stderr)
            return

        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError:
            print("[!] Failed to parse JSON output")
            print("Raw output:", result.stdout)
            return

        print("[*] Verifying results...")
        target_result = None
        for t in output:
            if t['ip'] == HOST:
                target_result = t
                break
        
        if not target_result:
            print(f"[!] No result found for {HOST}")
            return

        scan_ports = {p['port']: p['state'] for p in target_result['ports']}
        
        success = True
        
        for p in PORTS_TO_OPEN:
            state = scan_ports.get(p)
            if state == 'open':
                print(f"[PASS] Port {p} is detected as OPEN")
            else:
                print(f"[FAIL] Port {p} expected OPEN, got {state}")
                success = False

        state_closed = scan_ports.get(PORT_CLOSED)
        if state_closed == 'closed' or state_closed == 'filtered':
             print(f"[PASS] Port {PORT_CLOSED} is detected as {state_closed.upper()}")
        else:
             print(f"[FAIL] Port {PORT_CLOSED} expected CLOSED/FILTERED, got {state_closed}")
             success = False

        if success:
            print("\n 测试通过！工具运行正常。")
        else:
            print("\n 测试失败。请检查日志。")

    finally:
        stop_event.set()
        for t in threads:
            t.join()

if __name__ == "__main__":
    run_test()
