import requests
import re
import os
import hashlib
from datetime import datetime, timedelta
import time

# -----------------------
# Config
# -----------------------

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
]

DB_FILE = "findings_db.txt"

# -----------------------
# DB Handling
# -----------------------

def load_db():
    try:
        with open(DB_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except:
        return set()

def save_db(new_hashes):
    with open(DB_FILE, "a") as f:
        for h in new_hashes:
            f.write(h + "\n")

# -----------------------
# Utils
# -----------------------

def hash_item(text):
    return hashlib.sha256(text.encode()).hexdigest()

def mask_key(key):
    return key[:6] + "..." + key[-4:]

def extract_keys(text):
    pattern = r"(sk-[A-Za-z0-9]{20,})|(sess-[A-Za-z0-9]{20,})"
    return [m[0] or m[1] for m in re.findall(pattern, text)]

# -----------------------
# Confidence Scoring
# -----------------------

def confidence_score(f):
    filename = f["file"].lower()
    high_ext = [".env", ".js", ".config"]
    low_words = ["example", "test", "demo"]

    if any(filename.endswith(ext) for ext in high_ext):
        conf = "HIGH"
    elif any(w in filename for w in low_words):
        conf = "LOW"
    else:
        conf = "MEDIUM"

    if "commit_date" in f:
        try:
            dt = datetime.strptime(f["commit_date"], "%Y-%m-%dT%H:%M:%SZ")
            if dt < datetime.utcnow() - timedelta(days=180):
                if conf == "HIGH":
                    conf = "MEDIUM"
                elif conf == "MEDIUM":
                    conf = "LOW"
        except:
            pass

    return conf

# -----------------------
# GitHub Search
# -----------------------

def search_github(query):
    url = f"https://api.github.com/search/code?q={query}&per_page=30"
    r = requests.get(url, headers=HEADERS)
    if r.status_code != 200:
        return []
    return r.json().get("items", [])

def fetch_file(url):
    r = requests.get(url, headers=HEADERS)
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

def get_commits(repo):
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
        for key in extract_keys(patch):
            findings.append({
                "source": "commit",
                "repo": repo,
                "file": file["filename"],
                "key": key,
                "url": data["html_url"],
                "commit_date": data["commit"]["committer"]["date"]
            })

    return findings

# -----------------------
# Gists
# -----------------------

def scan_gists():
    findings = []
    r = requests.get("https://api.github.com/gists/public", headers=HEADERS)
    if r.status_code != 200:
        return findings

    for gist in r.json()[:20]:
        for file in gist["files"].values():
            raw_url = file.get("raw_url")
            if not raw_url:
                continue
            try:
                content = requests.get(raw_url).text
            except:
                continue

            for key in extract_keys(content):
                findings.append({
                    "source": "gist",
                    "repo": gist["owner"]["login"],
                    "file": file["filename"],
                    "key": key,
                    "url": gist["html_url"]
                })

    return findings

# -----------------------
# Pastebin
# -----------------------

def scan_paste():
    findings = []
    try:
        r = requests.get("https://pastebin.com/archive")
        ids = re.findall(r'href="/(\w+)"', r.text)
    except:
        return findings

    for pid in ids[:20]:
        try:
            raw = requests.get(f"https://pastebin.com/raw/{pid}").text
        except:
            continue

        for key in extract_keys(raw):
            findings.append({
                "source": "paste",
                "repo": "pastebin",
                "file": pid,
                "key": key,
                "url": f"https://pastebin.com/{pid}"
            })

    return findings

# -----------------------
# Alerts (Discord Embed)
# -----------------------

def send_alert(findings):
    if not WEBHOOK or not findings:
        return

    embeds = []

    for f in findings:
        conf = confidence_score(f)

        color = 16711680 if conf == "HIGH" else 16753920 if conf == "MEDIUM" else 8421504

        embeds.append({
            "title": f"{conf} | {f['source'].upper()} | {f['repo']}",
            "description": f"📄 **File:** {f['file']}\n🔑 **Key:** `{mask_key(f['key'])}`\n🔗 [View]({f['url']})",
            "color": color,
            "timestamp": datetime.utcnow().isoformat()
        })

    requests.post(WEBHOOK, json={"embeds": embeds})

# -----------------------
# Main
# -----------------------

def main():
    existing = load_db()
    all_findings = []

    # GitHub
    for q in QUERIES:
        items = search_github(q)
        time.sleep(1)

        for item in items:
            repo = item["repository"]["full_name"]

            content = fetch_file(item["url"])
            for key in extract_keys(content):
                all_findings.append({
                    "source": "code",
                    "repo": repo,
                    "file": item["name"],
                    "key": key,
                    "url": item["html_url"]
                })

            for c in get_commits(repo):
                all_findings.extend(scan_commit(repo, c["sha"]))
                time.sleep(0.5)

    # Gists + Paste
    all_findings.extend(scan_gists())
    all_findings.extend(scan_paste())

    # Deduplicate using DB
    new_findings = []
    new_hashes = []

    for f in all_findings:
        h = hash_item(f["key"])
        if h in existing:
            continue

        existing.add(h)
        new_findings.append(f)
        new_hashes.append(h)

    # Save new hashes
    save_db(new_hashes)

    # Sort by confidence
    new_findings = sorted(
        new_findings,
        key=lambda f: ["LOW", "MEDIUM", "HIGH"].index(confidence_score(f)),
        reverse=True
    )[:10]

    send_alert(new_findings)

    print(f"Done. {len(new_findings)} new findings.")

if __name__ == "__main__":
    main()
