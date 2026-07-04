#!/usr/bin/env python3
"""BountyOS outbound Linux/Parrot tool runner.

The runner never opens an inbound port. It connects to BountyOS over WSS,
advertises allow-listed installed tools, receives structured argv jobs, and
executes them without a shell.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict
from urllib.parse import urlencode

import websockets

DEFAULT_TOOL_SPECS = {
    "headers": ("curl", "--version"),
    "curl": ("curl", "--version"),
    "python3": ("python3", "--version"),
    "subfinder": ("subfinder", "-version"),
    "httpx": ("httpx", "-version"),
    "nuclei": ("nuclei", "-version"),
    "naabu": ("naabu", "-version"),
    "dnsx": ("dnsx", "-version"),
    "katana": ("katana", "-version"),
    "ffuf": ("ffuf", "-V"),
    "gau": ("gau", "--version"),
    "waybackurls": ("waybackurls", "-h"),
    "assetfinder": ("assetfinder", "-h"),
    "anew": ("anew", "-h"),
    "qsreplace": ("qsreplace", "-h"),
    "unfurl": ("unfurl", "-h"),
    "hakrawler": ("hakrawler", "-h"),
    "gospider": ("gospider", "-version"),
    "shodan": ("shodan", "--version"),
    "arjun": ("arjun", "--version"),
    "uro": ("uro", "--version"),
    "amass": ("amass", "version"),
    "nmap": ("nmap", "--version"),
    "masscan": ("masscan", "--version"),
    "sqlmap": ("sqlmap", "--version"),
    "whatweb": ("whatweb", "--version"),
    "wafw00f": ("wafw00f", "--version"),
    "nikto": ("nikto", "-Version"),
    "gobuster": ("gobuster", "version"),
    "feroxbuster": ("feroxbuster", "--version"),
    "dnsrecon": ("dnsrecon", "--version"),
    "dnsenum": ("dnsenum", "--version"),
    "fierce": ("fierce", "--version"),
    "theharvester": ("theHarvester", "--version"),
    "recon-ng": ("recon-ng", "--version"),
    "dmitry": ("dmitry", "--help"),
    "whois": ("whois", "--version"),
    "dig": ("dig", "-v"),
    "openssl": ("openssl", "version"),
    "jq": ("jq", "--version"),
}


def load_tool_specs() -> Dict[str, tuple[str, str]]:
    specs = dict(DEFAULT_TOOL_SPECS)
    path = Path(__file__).with_name("tool_specs.json")
    if path.exists():
        try:
            payload = json.loads(path.read_text())
            for name, meta in payload.items():
                binary = str(meta.get("binary") or name)
                version_flag = str(meta.get("version_flag") or "--version")
                specs[str(name)] = (binary, version_flag)
        except Exception as exc:
            print(f"Warning: could not load {path}: {exc}", file=sys.stderr)
    return specs

TOOL_SPECS = load_tool_specs()

ALIASES = {"headers": "curl", "theharvester": "theHarvester"}
MAX_OUTPUT_BYTES = int(os.getenv("BOUNTYOS_RUNNER_MAX_OUTPUT", "10000000"))


def get_version(binary_path: str, flag: str) -> str:
    try:
        result = subprocess.run([binary_path, flag], capture_output=True, text=True, timeout=8)
        text = (result.stdout + result.stderr).strip().splitlines()
        return text[0][:160] if text else "?"
    except Exception:
        return "?"


def discover_tools() -> Dict[str, dict]:
    tools: Dict[str, dict] = {}
    for name, (binary, version_flag) in TOOL_SPECS.items():
        path = shutil.which(binary)
        if path:
            tools[name] = {
                "binary": binary,
                "path": path,
                "version": get_version(path, version_flag),
            }
    return tools


def normalize_server_url(url: str) -> str:
    """Normalize server URL to WebSocket format."""
    url = url.strip().rstrip("/")
    if not url:
        return ""
    if url.startswith("https://"):
        return "wss://" + url[len("https://"):]
    if url.startswith("http://"):
        return "ws://" + url[len("http://"):]
    if not url.startswith("wss://") and not url.startswith("ws://"):
        return "wss://" + url
    return url


class Runner:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        try:
            import websockets
        except ImportError:
            print("[-] Error: 'websockets' library is missing. Install it with: pip install websockets", file=sys.stderr)
            sys.exit(1)

        self.tools = discover_tools()
        self.processes: Dict[str, asyncio.subprocess.Process] = {}
        self.send_lock = asyncio.Lock()
        self.ws = None

        print(f"[*] Runner ID: {self.args.runner_id}")
        print(f"[*] Server URL: {self.args.server}")
        print(f"[*] Hostname: {socket.gethostname()}")
        print(f"[*] Platform: {platform.system()} {platform.release()}")
        print(f"[*] PATH: {os.environ.get('PATH', 'not set')}")
        print(f"[*] Discovered {len(self.tools)} tools: {', '.join(sorted(self.tools.keys()))}")

        if self.args.check:
            self.run_check()
            sys.exit(0)

    def run_check(self) -> None:
        print("\n--- Runner Check Mode ---")
        missing = []
        for name in TOOL_SPECS:
            if name not in self.tools:
                missing.append(name)

        if missing:
            print(f"[!] Missing expected tools: {', '.join(sorted(missing))}")
        else:
            print("[+] All expected tools discovered.")

        print("[+] Runner check completed successfully.")

    async def send(self, payload: dict) -> None:
        if not self.ws:
            return
        async with self.send_lock:
            await self.ws.send(json.dumps(payload))

    async def heartbeat(self) -> None:
        while True:
            await asyncio.sleep(20)
            await self.send({"type": "heartbeat", "at": time.time(), "running_jobs": list(self.processes)})

    def validate_job(self, tool: str, argv: list[str]) -> list[str]:
        if tool not in self.tools:
            raise ValueError(f"Tool is not installed or allowed: {tool}")
        if not isinstance(argv, list) or not argv or len(argv) > 256:
            raise ValueError("Invalid argv")
        argv = [str(v) for v in argv]
        if any("\x00" in v or len(v) > 8192 for v in argv):
            raise ValueError("Invalid argument")
        expected = ALIASES.get(tool, self.tools[tool]["binary"])
        supplied = Path(argv[0]).name
        if supplied != expected:
            raise ValueError(f"Executable mismatch: expected {expected}, got {supplied}")
        argv[0] = self.tools[tool]["path"]
        return argv

    async def run_job(self, message: dict) -> None:
        job_id = str(message.get("job_id") or "")
        tool = str(message.get("tool") or "")
        timeout = max(5, min(int(message.get("timeout") or 300), 3600))
        started = time.monotonic()
        try:
            argv = self.validate_job(tool, message.get("argv") or [])
            await self.send({"type": "job_started", "job_id": job_id, "tool": tool})
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
            )
            self.processes[job_id] = proc
            output_bytes = 0
            while True:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout)
                if not line:
                    break
                output_bytes += len(line)
                if output_bytes > MAX_OUTPUT_BYTES:
                    proc.terminate()
                    raise RuntimeError("Maximum output size exceeded")
                await self.send({
                    "type": "job_output",
                    "job_id": job_id,
                    "stream": "stdout",
                    "line": line.decode(errors="replace").rstrip(),
                })
            exit_code = await asyncio.wait_for(proc.wait(), timeout=10)
            await self.send({
                "type": "job_result",
                "job_id": job_id,
                "status": "completed" if exit_code == 0 else "failed",
                "exit_code": exit_code,
                "error": None if exit_code == 0 else f"Exited with code {exit_code}",
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
            })
        except asyncio.TimeoutError:
            proc = self.processes.get(job_id)
            if proc:
                proc.kill()
                await proc.wait()
            await self.send({
                "type": "job_result", "job_id": job_id, "status": "timeout",
                "exit_code": None, "error": f"Timed out after {timeout}s",
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
            })
        except asyncio.CancelledError:
            proc = self.processes.get(job_id)
            if proc:
                proc.kill()
                await proc.wait()
            await self.send({"type": "job_result", "job_id": job_id, "status": "cancelled", "exit_code": None, "error": "Cancelled"})
            raise
        except Exception as exc:
            await self.send({
                "type": "job_result", "job_id": job_id, "status": "failed",
                "exit_code": None, "error": str(exc),
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
            })
        finally:
            self.processes.pop(job_id, None)

    async def cancel_job(self, job_id: str) -> None:
        proc = self.processes.get(job_id)
        if proc and proc.returncode is None:
            proc.kill()
            await proc.wait()

    async def session(self) -> None:
        query = urlencode({"runner_id": self.args.runner_id})
        uri = self.args.server.rstrip("/") + "/ws/runners/connect?" + query

        masked_uri = uri
        if "token=" in uri:
            # Although token is usually in auth message, if it was in URI we would mask it
            pass

        print(f"[*] Connecting to {self.args.server}", flush=True)
        print(f"[*] Runner ID: {self.args.runner_id}", flush=True)

        try:
            async with websockets.connect(
                uri,
                ping_interval=20,
                ping_timeout=30,
                close_timeout=10,
                max_size=2_000_000,
            ) as ws:
                self.ws = ws
                await self.send({"type": "auth", "token": self.args.token})
                await self.send({
                    "type": "hello",
                    "name": self.args.name,
                    "hostname": socket.gethostname(),
                    "platform": f"{platform.system()} {platform.release()} / {platform.machine()}",
                    "tools": self.tools,
                    "labels": self.args.labels,
                    "runner_version": "1.0.0",
                })
                print("[+] Connection established and authenticated", flush=True)
                heartbeat_task = asyncio.create_task(self.heartbeat())
                tasks: Dict[str, asyncio.Task] = {}
                try:
                    async for raw in ws:
                        message = json.loads(raw)
                        mtype = message.get("type")
                        if mtype == "job":
                            job_id = str(message.get("job_id"))
                            tasks[job_id] = asyncio.create_task(self.run_job(message))
                        elif mtype == "cancel_job":
                            job_id = str(message.get("job_id"))
                            task = tasks.get(job_id)
                            if task:
                                task.cancel()
                            await self.cancel_job(job_id)
                        elif mtype == "refresh_inventory":
                            self.tools = discover_tools()
                            await self.send({
                                "type": "hello", "name": self.args.name,
                                "hostname": socket.gethostname(),
                                "platform": f"{platform.system()} {platform.release()} / {platform.machine()}",
                                "tools": self.tools, "labels": self.args.labels,
                                "runner_version": "1.0.0",
                            })
                finally:
                    heartbeat_task.cancel()
                    for task in tasks.values():
                        task.cancel()
                    self.ws = None
        except websockets.exceptions.InvalidStatusCode as exc:
            if exc.status_code == 401:
                print(f"[-] Authentication failed (401) for {self.args.runner_id}", file=sys.stderr)
            else:
                print(f"[-] Server returned invalid status code: {exc.status_code}", file=sys.stderr)
            raise
        except (socket.gaierror, ConnectionRefusedError) as exc:
            print(f"[-] Network/DNS error: {exc}", file=sys.stderr)
            raise
        except websockets.exceptions.ConnectionClosed as exc:
            print(f"[-] Connection closed by server: {exc.code} {exc.reason}", file=sys.stderr)
            raise

    async def forever(self) -> None:
        delay = 2
        while True:
            try:
                print(f"Connecting to {self.args.server} as {self.args.name} ({len(self.tools)} tools)", flush=True)
                await self.session()
                delay = 2
            except KeyboardInterrupt:
                return
            except Exception as exc:
                print(f"Runner connection error: {exc}; retrying in {delay}s", file=sys.stderr, flush=True)
                await asyncio.sleep(delay)
                delay = min(delay * 2, 60)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BountyOS outbound tool runner")
    parser.add_argument("--server", default=os.getenv("BOUNTYOS_SERVER"), help="https:// or wss:// BountyOS base URL")
    parser.add_argument("--runner-id", default=os.getenv("BOUNTYOS_RUNNER_ID"))
    parser.add_argument("--token", default=os.getenv("BOUNTYOS_RUNNER_TOKEN"))
    parser.add_argument("--name", default=os.getenv("BOUNTYOS_RUNNER_NAME", socket.gethostname()))
    parser.add_argument("--labels", default=os.getenv("BOUNTYOS_RUNNER_LABELS", "parrot,remote"))
    parser.add_argument("--check", action="store_true", help="Check dependencies and tools then exit")
    args = parser.parse_args()

    args.server = normalize_server_url(args.server or "")

    if not args.check:
        if not args.server or not args.runner_id or not args.token:
            parser.error("--server, --runner-id and --token are required (unless using --check)")

    args.labels = [x.strip() for x in str(args.labels).split(",") if x.strip()]
    return args


if __name__ == "__main__":
    asyncio.run(Runner(parse_args()).forever())
