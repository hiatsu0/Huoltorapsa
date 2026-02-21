#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys
import time


def pid_is_running(pid):
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            STILL_ACTIVE = 259
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return False
            try:
                exit_code = ctypes.c_ulong()
                if ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)) == 0:
                    return False
                return exit_code.value == STILL_ACTIVE
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def wait_for_parent_exit(parent_pid, timeout_seconds=30.0):
    deadline = time.time() + max(0.0, timeout_seconds)
    while time.time() < deadline:
        if not pid_is_running(parent_pid):
            return True
        time.sleep(0.2)
    return not pid_is_running(parent_pid)


def start_server_process(python_exe, server_script, workdir):
    cmd = [python_exe, server_script]
    kwargs = {
        "cwd": workdir,
        "env": {**os.environ, "HUOLTORAPSA_NO_BROWSER": "1", "HUOLTORAPSA_AUTO_RESTART": "1"},
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if os.name == "nt":
        flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        kwargs["creationflags"] = flags
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen(cmd, **kwargs)


def parse_args():
    parser = argparse.ArgumentParser(description="Huoltorapsa restart helper")
    parser.add_argument("--pid", type=int, required=True, help="Parent process PID")
    parser.add_argument("--python", required=True, help="Python executable path")
    parser.add_argument("--script", required=True, help="Server script path")
    parser.add_argument("--cwd", required=True, help="Working directory")
    return parser.parse_args()


def main():
    args = parse_args()
    wait_for_parent_exit(args.pid, timeout_seconds=30.0)
    # Extra short delay helps when socket release lags momentarily.
    time.sleep(0.4)
    start_server_process(args.python, args.script, args.cwd)


if __name__ == "__main__":
    main()
