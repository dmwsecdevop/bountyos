#!/usr/bin/env python3
import json, sys, time, uuid, urllib.request, urllib.error

BASE = "https://bountyos-wyr2fxj3ta-el.a.run.app"
RUN_ID = str(uuid.uuid4())[:8]

def api(method, path, data=None):
    body = None
    headers = {}
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=120) as r:
        raw = r.read().decode()
        return json.loads(raw) if raw else {}

def submit(tool, target, args):
    print(f"[+] {tool} -> {target}")
    return api("POST", "/api/v1/runners/jobs", {
        "tool": tool,
        "target": target,
        "args": args,
        "approved": True,
        "metadata": {"run_id": RUN_ID}
    })

def get_jobs():
    return api("GET", "/api/v1/runners/jobs")

def wait_job(tool, target, timeout=600):
    end = time.time() + timeout
    while time.time() < end:
        matches = [
            j for j in get_jobs()
            if j.get("tool_name") == tool
            and j.get("target") == target
            and RUN_ID in str(j.get("metadata_json", ""))
        ]
        if matches:
            matches.sort(key=lambda x: x.get("created_at",""), reverse=True)
            j = matches[0]
            if j.get("status") in ("completed", "failed"):
                print(f"    status={j['status']}")
                if j.get("error"):
                    print(f"    error={j['error']}")
                return j
        time.sleep(3)
    raise TimeoutError(f"{tool} timeout")

def uniq_lines(text, limit):
    out, seen = [], set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line in seen:
            continue
        seen.add(line)
        out.append(line)
        if len(out) >= limit:
            break
    return out

def main():
    if len(sys.argv) != 2:
        print("Usage: hunter_chain.py example.com")
        sys.exit(1)

    domain = sys.argv[1]
    print("[+] run_id:", RUN_ID)

    submit("subfinder", domain, ["-d", domain, "-silent"])
    sub = wait_job("subfinder", domain)

    hosts = uniq_lines(sub.get("output"), 10) or [domain]
    print("[+] hosts:", len(hosts))

    live = []
    for h in hosts:
        url = h if h.startswith("http") else f"https://{h}"
        submit("httpx", url, ["-u", url, "-status-code", "-title"])
        r = wait_job("httpx", url)
        if r.get("status") == "completed" and r.get("output"):
            print(r["output"][:200])
            live.append(url)

    print("[+] live:", len(live))

    for url in live[:3]:
        submit("nuclei", url, ["-u", url, "-severity", "info,low"])
        wait_job("nuclei", url)

    print("[+] complete")

if __name__ == "__main__":
    main()
