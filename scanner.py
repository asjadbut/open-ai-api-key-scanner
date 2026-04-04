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

# 🔥 Freshness filter (IMPORTANT)
MAX_AGE_DAYS = 90

# -----------------------
# Safe Request Wrapper
# -----------------------

def safe_get(url, headers=None, retries=3, timeout=10):
    for i in range(retries):
        try:
            r = requests.get(url, headers=headers, timeout=timeout)
            if r.status_code == 200:
                return r
            else:
                print(f"[WARN] {r.status_code} {url}")
        except requests.exceptions.RequestException as e:
            print(f"[Retry {i+1}] {e}")
            time.sleep(2)
    return None

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

def is_fresh(date_str):
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
        return dt >= datetime.utcnow() - timedelta(days=MAX_AGE_DAYS)
    except:
        return True  # if unknown, don't block

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
        if not is_fresh(f["commit_date"]):
            if conf == "HIGH":
                conf = "MEDIUM"
            elif conf == "MEDIUM":
                conf = "LOW"

    return conf

# -----------------------
# GitHub Search
# -----------------------

def search_github(query):
    url = f"https://api.github.com/search/code?q={query}&per_page=30"
    r = safe_get(url, HEADERS)
    if not r:
        return []
    return r.json().get("items", [])

def fetch_file(url):
    r = safe_get(url, HEADERS)
    if not r:
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
    r = safe_get(url, HEADERS)
    if not r:
        return []
    return r.json()

def scan_commit(repo, sha):
    url = f"https://api.github.com/repos/{repo}/commits/{sha}"
    r = safe_get(url, HEADERS)
    if not r:
        return []

    data = r.json()
    findings = []

    commit_date = data["commit"]["committer"]["date"]

    # 🔥 Skip old commits completely
    if not is_fresh(commit_date):
        return []

    for file in data.get("files", []):
        patch = file.get("patch", "")
        if not patch:
            continue

        for key in extract_keys(patch):
            findings.append({
                "source": "commit",
                "repo": repo,
                "file": file["filename"],
                "key": key,
                "url": data["html_url"],
                "commit_date": commit_date
            })

    return findings

# -----------------------
# Gists
# -----------------------

def scan_gists():
    findings = []
    r = safe_get("https://api.github.com/gists/public", HEADERS)
    if not r:
        return findings

    for gist in r.json()[:20]:
        updated = gist.get("updated_at")

        # 🔥 skip old gists
        if updated and not is_fresh(updated):
            continue

        for file in gist["files"].values():
            raw_url = file.get("raw_url")
            if not raw_url:
                continue

            r2 = safe_get(raw_url)
            if not r2:
                continue

            for key in extract_keys(r2.text):
                findings.append({
                    "source": "gist",
                    "repo": gist["owner"]["login"],
                    "file": file["filename"],
                    "key": key,
                    "url": gist["html_url"],
                    "commit_date": updated
                })

    return findings

# -----------------------
# Pastebin
# -----------------------

def scan_paste():
    findings = []
    r = safe_get("https://pastebin.com/archive")
    if not r:
        return findings

    ids = re.findall(r'href="/(\w+)"', r.text)

    for pid in ids[:20]:
        r2 = safe_get(f"https://pastebin.com/raw/{pid}")
        if not r2:
            continue

        for key in extract_keys(r2.text):
            findings.append({
                "source": "paste",
                "repo": "pastebin",
                "file": pid,
                "key": key,
                "url": f"https://pastebin.com/{pid}",
                "commit_date": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            })

    return findings

# -----------------------
# Alerts
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

    try:
        requests.post(WEBHOOK, json={"embeds": embeds})
    except:
        print("Webhook failed")

# -----------------------
# Main
# -----------------------

def main():
    existing = load_db()
    all_findings = []

    for q in QUERIES:
        items = search_github(q)
        time.sleep(2)

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
                time.sleep(1)

    all_findings.extend(scan_gists())
    all_findings.extend(scan_paste())

    new_findings = []
    new_hashes = []

    for f in all_findings:
        h = hash_item(f["key"])
        if h in existing:
            continue

        existing.add(h)
        new_findings.append(f)
        new_hashes.append(h)

    save_db(new_hashes)

    new_findings = sorted(
        new_findings,
        key=lambda f: ["LOW", "MEDIUM", "HIGH"].index(confidence_score(f)),
        reverse=True
    )[:10]

    send_alert(new_findings)

    print(f"Done. {len(new_findings)} new findings.")

if __name__ == "__main__":
    main()
