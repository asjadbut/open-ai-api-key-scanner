import requests
import re
import os
import hashlib
import json
from datetime import datetime

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
WEBHOOK = os.getenv("ALERT_WEBHOOK")

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json"
}

QUERIES = [
    '"sk-" "openai"',
    '"sess-" "openai"',
    '"OPENAI_API_KEY"',
    '"openai.api_key"'
]

SEEN_FILE = "seen_hashes.json"


# -----------------------
# Utils
# -----------------------

def load_seen():
    try:
        with open(SEEN_FILE, "r") as f:
            return set(json.load(f))
    except:
        return set()

def save_seen(seen):
    with open(SEEN_FILE, "w") as f:
        json.dump(list(seen), f)

def hash_item(text):
    return hashlib.sha256(text.encode()).hexdigest()

def mask_key(key):
    return key[:6] + "..." + key[-4:] if key else ""

def extract_candidates(content):
    pattern = r"(sk-[A-Za-z0-9]{20,})|(sess-[A-Za-z0-9]{20,})"
    matches = re.findall(pattern, content)
    return [m[0] or m[1] for m in matches]


# -----------------------
# GitHub Code Search
# -----------------------

def search_github(query):
    url = f"https://api.github.com/search/code?q={query}&per_page=20"
    r = requests.get(url, headers=HEADERS)
    if r.status_code != 200:
        return []
    return r.json().get("items", [])

def fetch_file(api_url):
    r = requests.get(api_url, headers=HEADERS)
    if r.status_code != 200:
        return ""
    data = r.json()
    if "content" in data:
        import base64
        return base64.b64decode(data["content"]).decode(errors="ignore")
    return ""


# -----------------------
# Commit Scanning
# -----------------------

def get_recent_commits(repo):
    url = f"https://api.github.com/repos/{repo}/commits?per_page=5"
    r = requests.get(url, headers=HEADERS)
    if r.status_code != 200:
        return []
    return r.json()

def scan_commit(repo, sha):
    url = f"https://api.github.com/repos/{repo}/commits/{sha}"
    r = requests.get(url, headers=HEADERS)
    if r.status_code != 200:
        return []

    data = r.json()
    findings = []

    for file in data.get("files", []):
        patch = file.get("patch", "")
        if not patch:
            continue

        for key in extract_candidates(patch):
            findings.append({
                "source": "commit",
                "repo": repo,
                "file": file["filename"],
                "key": key,
                "url": data["html_url"]
            })

    return findings


# -----------------------
# Gists
# -----------------------

def search_gists():
    url = "https://api.github.com/gists/public"
    r = requests.get(url, headers=HEADERS)

    findings = []

    if r.status_code != 200:
        return findings

    for gist in r.json():
        for file in gist["files"].values():
            raw_url = file.get("raw_url")
            if not raw_url:
                continue

            try:
                content = requests.get(raw_url).text
            except:
                continue

            for key in extract_candidates(content):
                findings.append({
                    "source": "gist",
                    "repo": gist["owner"]["login"],
                    "file": file["filename"],
                    "key": key,
                    "url": gist["html_url"]
                })

    return findings


# -----------------------
# Paste (light scan)
# -----------------------

def scan_paste_feed():
    findings = []

    try:
        r = requests.get("https://pastebin.com/archive")
        ids = re.findall(r'href="/(\w+)"', r.text)
    except:
        return findings

    for pid in ids[:10]:
        try:
            raw = requests.get(f"https://pastebin.com/raw/{pid}").text
        except:
            continue

        for key in extract_candidates(raw):
            findings.append({
                "source": "paste",
                "repo": "pastebin",
                "file": pid,
                "key": key,
                "url": f"https://pastebin.com/{pid}"
            })

    return findings


# -----------------------
# Scoring
# -----------------------

def score(f):
    s = 0

    if f["source"] == "commit":
        s += 3
    elif f["source"] == "gist":
        s += 2
    elif f["source"] == "paste":
        s += 1

    name = f["file"].lower()

    if any(x in name for x in ["env", "config", "prod"]):
        s += 3

    if "test" in name:
        s -= 2

    return s


# -----------------------
# Alert
# -----------------------

def send_alert(findings):
    if not WEBHOOK or not findings:
        return

    text = "🚨 OpenAI Key Exposure Candidates\n\n"

    for f in findings:
        text += (
            f"[{f['source'].upper()}] {f['repo']}\n"
            f"File: {f['file']}\n"
            f"Key: {mask_key(f['key'])}\n"
            f"{f['url']}\n\n"
        )

    requests.post(WEBHOOK, json={"text": text})


# -----------------------
# Main
# -----------------------

def main():
    seen = load_seen()
    all_findings = []

    # GitHub search + commit scan
    for q in QUERIES:
        items = search_github(q)

        for item in items:
            repo = item["repository"]["full_name"]

            content = fetch_file(item["url"])
            for key in extract_candidates(content):
                all_findings.append({
                    "source": "code",
                    "repo": repo,
                    "file": item["name"],
                    "key": key,
                    "url": item["html_url"]
                })

            # commit scan
            for c in get_recent_commits(repo):
                all_findings.extend(scan_commit(repo, c["sha"]))

    # gists
    all_findings.extend(search_gists())

    # paste
    all_findings.extend(scan_paste_feed())

    # dedup
    unique = []
    for f in all_findings:
        h = hash_item(f["key"])
        if h in seen:
            continue
        seen.add(h)
        unique.append(f)

    save_seen(seen)

    # sort + top results
    unique = sorted(unique, key=score, reverse=True)[:10]

    send_alert(unique)

    print(f"Done. {len(unique)} new findings.")


if __name__ == "__main__":
    main()
