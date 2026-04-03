import requests
import re
import os
import hashlib
import json
from datetime import datetime, timedelta
import time

# -----------------------
# Configuration
# -----------------------

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
WEBHOOK = os.getenv("ALERT_WEBHOOK")
DUMMY_MODE = os.getenv("DUMMY_MODE", "false").lower() == "true"

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
# Utility Functions
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
    return [m[0] or m[1] for m in re.findall(pattern, content)]

# -----------------------
# Confidence Scoring
# -----------------------

def confidence_score(f):
    filename = f["file"].lower()
    high_risk_ext = [".env", ".js", ".config", ".prod"]
    low_risk_keywords = ["example", "test", "demo", "sample"]

    if any(filename.endswith(ext) for ext in high_risk_ext):
        confidence = "HIGH"
    elif any(k in filename for k in low_risk_keywords):
        confidence = "LOW"
    else:
        confidence = "MEDIUM"

    if "commit_date" in f:
        try:
            commit_date = datetime.strptime(f["commit_date"], "%Y-%m-%dT%H:%M:%SZ")
            if commit_date < datetime.utcnow() - timedelta(days=180):
                if confidence == "HIGH":
                    confidence = "MEDIUM"
                elif confidence == "MEDIUM":
                    confidence = "LOW"
        except:
            pass

    return confidence

# -----------------------
# GitHub Code & Commits
# -----------------------

def search_github(query):
    url = f"https://api.github.com/search/code?q={query}&per_page=50"
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

def get_recent_commits(repo):
    url = f"https://api.github.com/repos/{repo}/commits?per_page=10"
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
                "url": data["html_url"],
                "commit_date": data.get("commit", {}).get("committer", {}).get("date")
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

    for gist in r.json()[:30]:
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
# Paste Scan
# -----------------------

def scan_paste_feed():
    findings = []
    try:
        r = requests.get("https://pastebin.com/archive")
        ids = re.findall(r'href="/(\w+)"', r.text)
    except:
        return findings

    for pid in ids[:30]:
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
# Alerts
# -----------------------

def send_alert(findings):
    if not WEBHOOK or not findings:
        return

    # Discord embed style alert
    embeds = []
    for f in findings:
        conf = confidence_score(f)
        embeds.append({
            "title": f"[{conf}] {f['source'].upper()} | {f['repo']}",
            "description": f"**File:** {f['file']}\n**Key:** `{mask_key(f['key'])}`\n[View Source]({f['url']})",
            "color": 16711680 if conf=="HIGH" else 16753920 if conf=="MEDIUM" else 8421504,
            "timestamp": datetime.utcnow().isoformat()
        })

    payload = {"embeds": embeds}
    try:
        requests.post(WEBHOOK, json=payload)
    except:
        print("Failed to send alert")

# -----------------------
# Main
# -----------------------

def main():
    seen = load_seen()
    all_findings = []

    if DUMMY_MODE:
        all_findings.append({
            "source": "dummy",
            "repo": "test/repo",
            "file": ".env",
            "key": "sk-test12345678901234567890",
            "url": "https://github.com/test/repo"
        })
    else:
        # GitHub code + commit scan
        for q in QUERIES:
            items = search_github(q)
            time.sleep(1)
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
                for c in get_recent_commits(repo):
                    all_findings.extend(scan_commit(repo, c["sha"]))
                    time.sleep(1)

        # gists
        all_findings.extend(search_gists())

        # paste
        all_findings.extend(scan_paste_feed())

    # Deduplicate
    unique = []
    for f in all_findings:
        h = hash_item(f["key"])
        if h in seen:
            continue
        seen.add(h)
        unique.append(f)

    save_seen(seen)

    # Sort by confidence (HIGH first)
    unique = sorted(unique, key=lambda f: ["LOW","MEDIUM","HIGH"].index(confidence_score(f)), reverse=True)[:10]

    send_alert(unique)
    print(f"Done. {len(unique)} new findings.")

if __name__ == "__main__":
    main()
