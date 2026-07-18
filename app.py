"""
USPS Mail Webhook — Step 5: Full pipeline (webhook + push + web page)
======================================================================
The complete flow:
  1. Mailgun POSTs the forwarded USPS email to /mail-arrived
  2. We verify it's really Mailgun (signature check)
  3. We respond 200 IMMEDIATELY and process in a background thread
  4. We pull envelope scans (attachments, or <img> URLs from the HTML part)
     + body text (plain AND html — the package table only exists in HTML)
  5. OpenAI returns structured JSON (mail pieces + packages)
  6. Deterministic cleanup: drop hallucinated items, regex-fill packages
  7. We build ONE result object {summary, items, date} and STORE IT ON DISK
  8. We fire an Ntfy push notification (tap it -> opens /today)
  9. You open /today -> the page renders the stored JSON beautifully

What changed in this revision (and why):
  * PACKAGES: the digest's package table (FROM: senders, tracking numbers)
    lives ONLY in the email's HTML part (Mailgun's body-html). The old code
    only read the plain-text part, which is a bare summary — so OpenAI had
    nothing to extract and returned "Unknown". We now parse the HTML too.
  * IMAGES: mailpiece scans arrive as remote <img> URLs in the HTML, not as
    attachments, so request.files was empty ("0 IMAGE(S) ATTACHED"). We now
    download those URLs when there are no attachments.
  * HALLUCINATIONS: with 0 images and package-less text, the model invented
    a mail piece AND a package. The prompt now forbids that, and a
    deterministic sanitizer drops any item that has no supporting evidence.
  * NTFY PUSH: "[Errno 101] Network is unreachable" was IPv6 — ntfy.sh has
    AAAA records but Railway containers have no IPv6 route. We force IPv4.
  * STALE/EMPTY /today: LATEST_MAIL lived in memory, and gunicorn kills
    workers stuck >30s (our OpenAI call can take 90s) — wiping the data and
    causing Mailgun retries (duplicate processing). We now answer webhooks
    instantly (background thread) and persist the digest to a JSON file that
    every page load re-reads.
"""

import os
import re
import json
import base64
import hashlib
import hmac
import socket
import threading
import html as html_lib
from datetime import datetime

try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except ImportError:  # very old Python — degrade gracefully to UTC
    ZoneInfo = None

import requests
import urllib3.util.connection as urllib3_connection
from flask import Flask, request, Response

# --- Force IPv4 for all outbound HTTPS -------------------------------------
# Purpose: ntfy.sh publishes IPv6 (AAAA) records, but Railway containers have
# no IPv6 route, so urllib3's first connect attempt died with
# "[Errno 101] Network is unreachable" — while api.openai.com kept working
# because it resolved IPv4-first. Pinning the address family to AF_INET makes
# every requests/urllib3 call (ntfy, OpenAI, image downloads) use IPv4.
urllib3_connection.allowed_gai_family = lambda: socket.AF_INET

app = Flask(__name__)

# --- Secrets / config (set these in Railway -> Variables) ---
MAILGUN_SIGNING_KEY = os.environ.get("MAILGUN_SIGNING_KEY", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "usps_informed_delivery")
NTFY_BASE_URL = os.environ.get("NTFY_BASE_URL", "https://ntfy.sh").rstrip("/")
PUBLIC_URL = os.environ.get("PUBLIC_URL", "https://web-production-0d2b6.up.railway.app")
TIMEZONE = os.environ.get("TIMEZONE", "America/New_York")

OPENAI_MODEL = "gpt-5.4-mini"

# Skip images under 5 KB — those are logos/spacers/tracking pixels, not
# mailpiece scans. Real envelope scans are always well above 5 KB.
MIN_MAILPIECE_BYTES = 5_000
MAX_IMAGES = 12  # hard cap so a weird email can't blow up the vision bill

try:
    LOCAL_TZ = ZoneInfo(TIMEZONE) if ZoneInfo else None
except Exception:
    LOCAL_TZ = ZoneInfo("UTC") if ZoneInfo else None


def local_now():
    """Current time in the configured timezone (UTC if zoneinfo is unavailable)."""
    return datetime.now(LOCAL_TZ) if LOCAL_TZ else datetime.utcnow()

# --- On-disk persistence ----------------------------------------------------
# Purpose: LATEST_MAIL used to be a module-level variable. Gunicorn reboots
# workers (deploys, crashes, request timeouts) and every reboot silently wiped
# it, so /today flashed "0 mail, 0 packages" until the next digest arrived.
# Now the digest is written to disk atomically and EVERY page load reads it
# back, so worker restarts (and multi-worker setups) always serve the same
# data. Point DATA_DIR at a Railway Volume to survive redeploys too.
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
DATA_FILE = os.path.join(DATA_DIR, "latest_mail.json")

EMPTY_MAIL = {
    "summary": "No mail processed yet today.",
    "items": [],
    "date": None,
    "updated_at": None,
}


def load_latest_mail():
    """Read the stored digest from disk. Falls back to EMPTY_MAIL on any
    problem (missing file, half-written JSON, wrong shape)."""
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            return data
    except Exception:
        pass
    return dict(EMPTY_MAIL)


def save_latest_mail(data):
    """Write the digest atomically: write a temp file, then os.replace, so a
    /today reader can never catch a half-written file."""
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, DATA_FILE)


def verify_mailgun_signature(token, timestamp, signature):
    if not MAILGUN_SIGNING_KEY:
        print("⚠️  WARNING: No MAILGUN_SIGNING_KEY set. Skipping signature check.")
        return True
    expected = hmac.new(
        key=MAILGUN_SIGNING_KEY.encode("utf-8"),
        msg=f"{timestamp}{token}".encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def choose_body(data):
    """
    Pick the fuller of Mailgun's two body-text fields.

    Purpose: Mailgun exposes two flavors of the email body:
      - 'stripped-text' — cleaner, with quoted replies and forwarded-message
        cruft removed. Great for MANUALLY forwarded email (lots of cruft).
      - 'body-plain'    — the raw plain-text version, complete but noisier.

    We used to always prefer 'stripped-text'. But AUTO-forwarded USPS emails
    already come through leaner, and 'stripped-text' sometimes over-strips
    legitimate content (like the package list). 'body-plain' on the same
    email keeps everything.

    Length is a good proxy for completeness here — you can't extract what
    isn't in the text — so we take whichever field is longer.
    """
    stripped = (data.get("stripped-text") or "").strip()
    raw      = (data.get("body-plain")    or "").strip()
    if not stripped:
        return raw
    if not raw:
        return stripped
    chosen_raw = len(raw) > len(stripped)
    print(f"  📝 body-plain: {len(raw)} chars, stripped-text: {len(stripped)} chars"
          f" → using {'body-plain (fuller)' if chosen_raw else 'stripped-text'}")
    return raw if chosen_raw else stripped


def choose_html(data):
    """
    Pick the fuller of Mailgun's two HTML fields (same length heuristic as
    choose_body).

    Purpose: THIS is where the package data actually lives. The USPS digest's
    package table (FROM: senders, expected timing, tracking numbers) exists
    only in the HTML part of the email; the plain-text part is a bare
    "view your mailpieces online" summary. The old pipeline never read the
    HTML, which is why packages kept coming back with sender "Unknown".
    """
    full     = (data.get("body-html")     or "").strip()
    stripped = (data.get("stripped-html") or "").strip()
    chosen = full if len(full) >= len(stripped) else stripped
    print(f"  📝 body-html: {len(full)} chars, stripped-html: {len(stripped)} chars"
          f" → using {'body-html' if chosen is full else 'stripped-html'}")
    return chosen


def html_to_text(raw_html):
    """
    Convert the digest HTML to readable plain text.

    How: drop <script>/<style> entirely, turn block-level closing tags and
    <br> into newlines (so table cells like "FROM:" and the sender land on
    separate lines), strip every remaining tag, unescape entities (&amp;
    etc.), then collapse whitespace and drop empty lines.
    """
    if not raw_html:
        return ""
    txt = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", raw_html)
    txt = re.sub(r"(?i)<br\s*/?>", "\n", txt)
    txt = re.sub(r"(?i)</(p|div|tr|td|th|li|h[1-6]|table|span)>", "\n", txt)
    txt = re.sub(r"<[^>]+>", " ", txt)
    txt = html_lib.unescape(txt)
    lines = [re.sub(r"[ \t]+", " ", ln).strip() for ln in txt.splitlines()]
    return "\n".join(ln for ln in lines if ln)


def extract_image_urls(raw_html):
    """
    Pull candidate mailpiece-scan URLs out of the digest HTML.

    Purpose: in these forwarded digests the envelope scans are remote <img>
    tags (hosted on USPS servers), NOT attachments — so request.files is
    empty and the old pipeline sent 0 images to OpenAI. We collect every
    http(s) img src, skipping obvious logos/spacers/tracking pixels (the
    size filter in the pipeline does the final culling).
    """
    urls = []
    for m in re.finditer(r'<img[^>]+src=["\']([^"\']+)["\']', raw_html or "", re.IGNORECASE):
        u = html_lib.unescape(m.group(1)).strip()
        if not u.lower().startswith("http"):
            continue  # cid:/data: URIs are useless to us here
        low = u.lower()
        if any(bad in low for bad in ("spacer", "pixel", "1x1", "beacon", "logo", "open?", "unsubscribe")):
            continue
        if u not in urls:
            urls.append(u)
    return urls


def download_images(urls):
    """Fetch candidate scan URLs. Anything that isn't an image/* response or
    fails to download is skipped with a log line; size-filtering happens in
    the pipeline alongside attachments."""
    images = []
    for u in urls[:MAX_IMAGES]:
        try:
            r = requests.get(u, timeout=15)
            r.raise_for_status()
            ctype = (r.headers.get("Content-Type") or "").lower()
            if "image" not in ctype:
                print(f"  ⏭️  Not an image ({ctype or 'unknown type'}): {u[:80]}")
                continue
            images.append((u.rsplit("/", 1)[-1][:60] or "scan.jpg", r.content))
            print(f"  📎 Downloaded scan from HTML: {len(r.content)} bytes — {u[:80]}")
        except Exception as e:
            print(f"  ⚠️  Image download failed ({u[:60]}): {e}")
    return images


def find_tracking_numbers(text):
    """
    Find USPS tracking numbers: 20-34 digits, possibly grouped with spaces
    or dashes ("9400 1000 0000 0000 0000 00"). Returns digit-only strings,
    deduped, in order of appearance.
    """
    trackings = []
    for m in re.finditer(r"\b(?:\d[ -]?){20,34}\b", text or ""):
        t = re.sub(r"\D", "", m.group(0))
        if 20 <= len(t) <= 34 and t not in trackings:
            trackings.append(t)
    return trackings


def analyze_mail(images, body_text):
    """One OpenAI call with images + body text. Returns list of item dicts."""
    if not OPENAI_API_KEY:
        print("⚠️  No OPENAI_API_KEY set — skipping the AI analysis.")
        return []
    instructions = (
        "You are analyzing a USPS Informed Delivery daily digest.\n\n"
        "TWO sources:\n"
        "1) The attached grayscale IMAGES are scans of envelope exteriors, each picture contains only ONE mailpiece, no exception."
        "(letters/mail pieces).\n"
        "2) The TEXT below lists EXPECTED PACKAGES ('FROM:' senders, expected "
        "timing, tracking numbers).\n\n"
        "Return ONLY a JSON object with a single key \"items\", an array.\n\n"
        "For each MAIL piece in the images, an object with EXACTLY:\n"
        '  "type": "mail",\n'
        '  "recipient": string (addressee or "unknown" if you cannot detect any names, use the name as it is, do not use Honorifics & Titles),\n'
        '  "sender": string (SHORT readable name like "IRS", not the full '
        'address block; or "unknown"),\n'
        '  "category": one of "financial","government","medical","personal",'
        '"advertising", or other category you deem reasonable,\n'
        '  "is_advertisement": boolean,\n'
        '  "importance": 1, 2, or 3 (3=bills/government/tax/medical/legal/'
        "checks; 2=normal personal mail; 1=junk/ads),\n"
        '  "action_needed": boolean,\n'
        '  "summary": string (one short line describing the mail piece; do NOT include the recipient name as it is shown separately),\n'
        '  "confidence": "high","medium", or "low" (scans are blurry — be '
        "honest).\n\n"
        "For each PACKAGE in the text, an object with EXACTLY (always include every package, even if sender or tracking are missing — use 'Unknown' for missing fields):\n"
        '  "type": "package",\n'
        '  "sender": string (the FROM: company, "Unknown" if not listed),\n'
        '  "tracking_number": string (the long digit string with any spaces removed, or "unknown"),\n'
        '  "expected": string ("Today", "1-2 Days", or "unknown"),\n'
        '  "summary": string (one short line).\n\n'
        "STRICT RULES — read carefully:\n"
        "- If NO images are attached to this request, there are NO mail "
        "pieces. Return zero mail items. Never describe an image you were "
        "not given.\n"
        "- Only report packages that are explicitly listed in the text below. "
        "Never invent or guess senders, tracking numbers, or items.\n"
        "- Tracking numbers may be written with spaces between digit groups; "
        "output the digits only.\n\n"
        "No extra keys. No text outside the JSON.\n\n"
        "=== PACKAGE TEXT FROM EMAIL BODY ===\n"
        + (body_text or "(no body text)")
    )
    content = [{"type": "text", "text": instructions}]
    for filename, raw_bytes in images:
        b64 = base64.b64encode(raw_bytes).decode("utf-8")
        content.append({
            "type": "image_url",
            "image_url": {"url": f"data:image/jpeg;base64,{b64}"},
        })
    payload = {
        "model": OPENAI_MODEL,
        "messages": [{"role": "user", "content": content}],
        "response_format": {"type": "json_object"},
    }

    # --- 🔍 DEBUG: show exactly what we're sending to OpenAI ---
    # Purpose: if packages aren't detected, this reveals which side is failing.
    # If the body-text section below is missing package lines, the problem is
    # upstream (Gmail/Mailgun stripped them). If they're present but OpenAI
    # still misses them, the problem is prompt/model.
    print("--- 🔍 PROMPT SENT TO OPENAI ---")
    print(instructions[:2500])
    if len(instructions) > 2500:
        print(f"... [+{len(instructions) - 2500} more chars]")
    print(f"--- 🔍 {len(images)} IMAGE(S) ATTACHED ---")
    for fn, raw in images:
        print(f"     • {fn}: {len(raw)} bytes")
    print("--- 🔍 END PROMPT ---")

    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=90,
        )
        resp.raise_for_status()
        raw_text = resp.json()["choices"][0]["message"]["content"]
        # --- 🔍 DEBUG: show OpenAI's raw response before we parse it ---
        # If parsing fails or items are missing, this tells us whether it's
        # the model's output or our JSON handling that dropped them.
        print("--- 🔍 OPENAI RAW RESPONSE ---")
        print(raw_text[:2500] if raw_text else "(empty)")
        if raw_text and len(raw_text) > 2500:
            print(f"... [+{len(raw_text) - 2500} more chars]")
        print("--- 🔍 END RESPONSE ---")
        if not raw_text:
            return []
        return json.loads(raw_text).get("items", [])
    except Exception as e:
        print(f"❌ OpenAI call/parse failed: {e}")
        return []


def parse_digest_counts(body_text):
    """
    Extract the authoritative mail/package counts from the USPS digest summary line:
    "You have 3 mailpiece(s) and 1 inbound package(s) arriving soon."
    Returns (mail_count, package_count) as ints, or (None, None) if not found.
    """
    m = re.search(
        r"You have\s+(\d+)\s+mailpiece(?:\(s\)|s)?\s+and\s+(\d+)\s+inbound\s*package(?:\(s\)|s)?",
        body_text, re.IGNORECASE,
    )
    if m:
        return int(m.group(1)), int(m.group(2))
    m2 = re.search(r"You have\s+(\d+)\s+mailpiece(?:\(s\)|s)?", body_text, re.IGNORECASE)
    if m2:
        return int(m2.group(1)), 0
    m3 = re.search(r"(\d+)\s+inbound\s*package(?:\(s\)|s)?", body_text, re.IGNORECASE)
    if m3:
        return 0, int(m3.group(1))
    return None, None


def parse_digest_date(text):
    """
    Pull the digest's own date: "Today's Deliveries: 07/18/2026" -> "2026-07-18".
    Purpose: date-stamps the stored data so the /today page can say WHICH day
    it's showing — previously yesterday's digest looked identical to today's.
    Falls back to None if the line isn't there (caller substitutes today).
    """
    m = re.search(r"Today's Deliveries:\s*(\d{1,2})/(\d{1,2})/(\d{4})", text or "")
    if m:
        mo, d, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        try:
            return datetime(y, mo, d).date().isoformat()
        except ValueError:
            return None
    return None


def sanitize_items(items, images, body_text, mail_count, package_count):
    """
    Deterministic anti-hallucination cleanup.

    Purpose: today the model invented a mail piece ("grayscale scan too
    unclear") when ZERO images were attached, and a package ("Unknown sender")
    when the text mentioned none. The model's output is advisory; these rules
    are enforced no matter what it says:

      - No images were sent      => no mail items can exist.
      - Digest says 0 mailpieces => no mail items can exist.
      - Digest says 0 packages   => no package items can exist.
      - No package evidence in the text at all (no digest count, no tracking
        number, no "FROM:" line) => no package items can exist.
    """
    has_pkg_evidence = (
        (package_count or 0) > 0
        or bool(find_tracking_numbers(body_text))
        or re.search(r"(?im)^\s*FROM:\s*\S", body_text or "") is not None
    )
    cleaned = []
    for it in items or []:
        if it.get("type") == "package":
            if package_count == 0 or not has_pkg_evidence:
                print(f"  🧹 Dropping unsupported package item (sender: {it.get('sender')!r})")
                continue
            cleaned.append(it)
        else:
            if not images or mail_count == 0:
                print(f"  🧹 Dropping mail item with no image evidence (sender: {it.get('sender')!r})")
                continue
            cleaned.append(it)
    return cleaned


def fill_packages_from_text(items, body_text, package_count):
    """
    Regex safety net for packages.

    Purpose: the model sometimes returns packages with sender "Unknown" and
    tracking "unknown" even when both are sitting right there in the email
    text. When the model's packages are missing or incomplete, we extract
    "FROM: <sender>" lines and 20+ digit tracking numbers directly from the
    text and fill the gaps (model values win when they're real; regex values
    fill the Unknowns and any missing package slots).
    """
    def known(v):
        return bool(v) and str(v).lower() not in ("unknown", "")

    pkgs = [i for i in items if i.get("type") == "package"]
    complete = pkgs and all(known(p.get("sender")) and known(p.get("tracking_number")) for p in pkgs)
    if complete and (package_count is None or len(pkgs) >= package_count):
        return items

    senders = []
    for s in re.findall(r"(?im)^\s*FROM:\s*(.+?)\s*$", body_text or ""):
        s = s.split("Expected")[0].strip().rstrip(".,")[:60]
        if s and s.lower() != "unknown" and s not in senders:
            senders.append(s)
    trackings = find_tracking_numbers(body_text)

    if not senders and not trackings:
        return items

    tl = (body_text or "").lower()
    if re.search(r"expected delivery[^\n]{0,60}today", tl):
        expected = "Today"
    elif "1-2 day" in tl or "1 - 2 day" in tl:
        expected = "1-2 Days"
    else:
        expected = "unknown"

    n = max(len(pkgs), package_count or 0, len(senders), len(trackings))
    new_pkgs = []
    for i in range(n):
        base = pkgs[i] if i < len(pkgs) else {}
        sender = base.get("sender") if known(base.get("sender")) else (senders[i] if i < len(senders) else "Unknown")
        tracking = base.get("tracking_number") if known(base.get("tracking_number")) else (trackings[i] if i < len(trackings) else "unknown")
        new_pkgs.append({
            "type": "package",
            "sender": sender,
            "tracking_number": tracking,
            "expected": base.get("expected") if known(base.get("expected")) else expected,
            "summary": base.get("summary") or f"Package from {sender}",
        })
        print(f"  🧩 Package {i + 1} after regex fill: sender={sender!r} tracking={tracking!r}")

    others = [i for i in items if i.get("type") != "package"]
    return others + new_pkgs


def build_headline(items, mail_count=None, package_count=None):
    """Build the one-line summary. Uses authoritative email counts when available."""
    letters = [i for i in items if i.get("type") != "package"]
    packages = [i for i in items if i.get("type") == "package"]

    def name_list(group):
        names = []
        for p in group:
            s = p.get("sender", "unknown")
            if s and s.lower() != "unknown" and s not in names:
                names.append(s)
        if not names:
            return ""
        if len(names) == 1:
            return names[0]
        if len(names) == 2:
            return names[0] + " and " + names[1]
        return ", ".join(names[:-1]) + ", and " + names[-1]

    n_letters = mail_count if mail_count is not None else len(letters)
    n_packages = package_count if package_count is not None else len(packages)

    parts = []
    if n_letters:
        senders = name_list(letters)
        word = "piece" if n_letters == 1 else "pieces"
        line = f"{n_letters} {word} of mail"
        if senders:
            line += f" from {senders}"
        parts.append(line)
    if n_packages:
        senders = name_list(packages)
        word = "package" if n_packages == 1 else "packages"
        line = f"{n_packages} {word}"
        if senders:
            line += f" from {senders}"
        parts.append(line)

    if not parts:
        return "No mail or packages detected today."
    body = parts[0] if len(parts) == 1 else parts[0] + " and " + parts[1]
    return "You have " + body + " today."


def send_push(headline, items):
    """Fire an Ntfy notification. Tapping it opens the /today page.
    Body leads with PACKAGES (most actionable), then per-piece mail details."""
    if not NTFY_TOPIC:
        return
    packages = [i for i in items if i.get("type") == "package"]
    mail = [i for i in items if i.get("type") != "package"]

    lines = []

    if packages:
        word = "package" if len(packages) == 1 else "packages"
        lines.append(f"📦 {len(packages)} {word}:")
        for p in packages:
            sender = p.get("sender", "Unknown")
            expected = p.get("expected", "unknown")
            detail = f"📦 {sender}"
            if expected and expected.lower() != "unknown":
                detail += f" (arriving {expected.lower()})"
            lines.append(detail)

    if mail:
        word = "mail" if len(mail) == 1 else "mails"
        lines.append(f"✉️ {len(mail)} {word}:")
        for m in mail:
            sender = m.get("sender", "Unknown")
            recipient = m.get("recipient", "")
            summary = m.get("summary", "")
            detail = f"✉️ {sender}"
            extras = []
            if recipient and recipient.lower() not in ("unknown", ""):
                extras.append(f"for {recipient}")
            if summary:
                extras.append(summary)
            if extras:
                detail += f" ({', '.join(extras)})"
            lines.append(detail)

    body = "\n".join(lines) if lines else "No mail or packages today."

    try:
        r = requests.post(
            f"{NTFY_BASE_URL}/{NTFY_TOPIC}",
            data=body.encode("utf-8"),
            headers={
                "Title": "Today's Mail",
                "Tags": "mailbox_with_mail",
                "Click": f"{PUBLIC_URL}/today",
                "Priority": "default",
            },
            timeout=15,
        )
        if r.status_code == 200:
            print(f"  🔔 Push sent to {NTFY_BASE_URL}/{NTFY_TOPIC}")
        else:
            print(f"  ⚠️  Ntfy returned HTTP {r.status_code}: {r.text[:200]}")
    except Exception as e:
        print(f"  ⚠️  Push failed (not fatal): {e}")


def parse_delivery_alert(subject, body_text):
    """
    Pull sender, expected time, and tracking number out of a USPS delivery
    alert email using plain regex — NO AI call needed.
    Returns a dict {sender, time, tracking, is_today} or None if unparseable.
    """
    text = (subject or "") + "\n" + (body_text or "")

    trackings = find_tracking_numbers(text)
    tracking = trackings[0] if trackings else None

    sender_match = re.search(r"(?:Package\s+)?Shipped from:\s*(.+?)(?:\n|$)",
                             text, re.IGNORECASE)
    sender = sender_match.group(1).strip().rstrip(".,") if sender_match else None

    time_match = re.search(r"by\s+(\d{1,2}:\d{2}\s*(?:am|pm|AM|PM))", text)
    expected_time = time_match.group(1).lower().replace(" ", "") if time_match else None

    is_today = bool(re.search(r"\bdeliver\s+your\s+package\s+today\b", text, re.IGNORECASE))

    day_match = re.search(
        r"Expected Delivery on\s+(Sunday|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday)",
        text, re.IGNORECASE,
    )
    weekday = day_match.group(1).capitalize() if day_match else None

    if not tracking or not sender:
        return None
    return {
        "sender": sender,
        "tracking": tracking,
        "expected_time": expected_time,
        "is_today": is_today,
        "weekday": weekday,
    }


def send_delivery_alert_push(alert):
    """Send a HIGH-priority push for an individual delivery alert."""
    if not NTFY_TOPIC:
        return

    if alert["is_today"]:
        title = f"Your package from {alert['sender']} is out for delivery today"
    elif alert["weekday"]:
        title = f"Your package from {alert['sender']} will be out for delivery on {alert['weekday']}"
    else:
        title = f"Your package from {alert['sender']} is out for delivery"

    body_parts = []
    if alert["expected_time"]:
        body_parts.append(f"Arriving by {alert['expected_time']}")
    body_parts.append(f"Tracking: {alert['tracking']}")
    body = " · ".join(body_parts)

    usps_url = (
        "https://tools.usps.com/go/TrackConfirmAction?tLabels="
        + alert["tracking"]
    )

    try:
        r = requests.post(
            f"{NTFY_BASE_URL}/{NTFY_TOPIC}",
            data=body.encode("utf-8"),
            headers={
                "Title": title,
                "Tags": "package",
                "Click": usps_url,
                "Priority": "high",
            },
            timeout=15,
        )
        if r.status_code == 200:
            print(f"  🔔 Delivery alert pushed: {alert['sender']} / {alert['tracking']}")
        else:
            print(f"  ⚠️  Ntfy returned HTTP {r.status_code}: {r.text[:200]}")
    except Exception as e:
        print(f"  ⚠️  Delivery alert push failed: {e}")


@app.route("/mail-arrived", methods=["POST"])
def mail_arrived():
    data = request.form

    if not verify_mailgun_signature(
        data.get("token", ""), data.get("timestamp", ""), data.get("signature", "")
    ):
        print("❌ Bad signature — rejecting.")
        return "Forbidden", 403

    # Snapshot everything we need BEFORE responding — the request context is
    # destroyed as soon as we return, and upload streams can't be re-read.
    form = data.to_dict()
    uploads = []
    for key in request.files:
        f = request.files[key]
        uploads.append((f.filename or key, f.content_type or "", f.read()))

    # Respond 200 IMMEDIATELY and process in a background thread.
    # Purpose: the OpenAI vision call can take 30-90s, but Mailgun expects a
    # quick 2xx (otherwise it retries — which is why the digest was processed
    # TWICE in the logs) and gunicorn kills workers stuck on a request >30s
    # by default (which wiped the in-memory digest mid-write — the direct
    # cause of the "0 mail, 0 packages" flashes). A fast 200 + a daemon
    # thread avoids both. The thread keeps running inside the worker after
    # the response goes out.
    threading.Thread(target=process_email, args=(form, uploads), daemon=True).start()
    return "OK", 200


def process_email(data, uploads):
    """Runs in the background thread: route the email, analyze, store, push."""
    try:
        print("\n" + "=" * 60)
        subject = data.get("subject", "")
        print(f"📬 NEW EMAIL — {subject or '(no subject)'}")
        print("=" * 60)

        body_text = choose_body(data)
        subj_lower = subject.lower()
        is_delivery_alert = (
            "expected delivery" in subj_lower
            or "out for delivery" in subj_lower
            or "arriving by" in subj_lower
        ) and "daily digest" not in subj_lower

        if is_delivery_alert:
            print("  🚚 Detected: USPS delivery alert (push-only, no /today update)")
            alert = parse_delivery_alert(subject, body_text)
            if alert:
                send_delivery_alert_push(alert)
            else:
                print("  ⚠️  Could not parse delivery alert reliably — skipped.")
            print("=" * 60 + "\n")
            return

        # --- Full Daily Digest pipeline ---
        raw_html = choose_html(data)
        html_text = html_to_text(raw_html)

        # The package table (FROM: senders, tracking numbers) lives in the
        # HTML part; the plain-text part is a bare summary. Use whichever
        # derived text is fuller as the text the AI (and our regexes) see.
        package_text = html_text if len(html_text) > len(body_text) else body_text
        print(f"  📝 Text for analysis: {len(package_text)} chars"
              f" ({'from HTML part' if package_text is html_text else 'from plain-text part'})")

        # 1) Attachments first (some setups DO forward scans as files).
        images = []
        for filename, ctype, raw in uploads:
            if ctype.startswith("image/"):
                if len(raw) < MIN_MAILPIECE_BYTES:
                    print(f"  ⏭️  Skipped small image (likely logo/spacer): {filename} ({len(raw)} bytes)")
                    continue
                images.append((filename, raw))
                print(f"  📎 Found attachment image: {filename} ({len(raw)} bytes)")

        # 2) No attachments? The scans are remote <img> URLs in the HTML.
        if not images and raw_html:
            urls = extract_image_urls(raw_html)
            print(f"  🖼️  No attachments — found {len(urls)} candidate image URL(s) in the HTML")
            for fn, raw in download_images(urls):
                if len(raw) < MIN_MAILPIECE_BYTES:
                    print(f"  ⏭️  Skipped small downloaded image (logo/icon): {fn} ({len(raw)} bytes)")
                    continue
                images.append((fn, raw))

        images = images[:MAX_IMAGES]

        if not images and not package_text:
            print("  (Nothing to analyze.)")
            print("=" * 60 + "\n")
            return

        mail_count, package_count = parse_digest_counts(package_text)
        if mail_count is not None:
            print(f"  📊 Email says: {mail_count} mailpiece(s), {package_count} package(s)")

        print(f"\n  🤖 Sending {len(images)} image(s) + body text to {OPENAI_MODEL}...")
        items = analyze_mail(images, package_text)

        # Deterministic cleanup: no evidence, no item. Then regex-fill any
        # packages the model returned as "Unknown".
        items = sanitize_items(items, images, package_text, mail_count, package_count)
        items = fill_packages_from_text(items, package_text, package_count)

        headline = build_headline(items, mail_count=mail_count, package_count=package_count)

        now = local_now()
        digest_date = parse_digest_date(package_text) or now.date().isoformat()
        stored = {
            "summary": headline,
            "items": items,
            "date": digest_date,
            "updated_at": now.isoformat(timespec="seconds"),
        }
        save_latest_mail(stored)
        print(f"  💾 Stored digest for {digest_date} to disk")

        print("\n--- 📋 SUMMARY ---")
        print(headline)
        print("--- 🗂️  ITEMS ---")
        print(json.dumps(items, indent=2))

        send_push(headline, items)
        print("=" * 60 + "\n")

    except Exception as e:
        # Never let a background exception die silently in the logs.
        print(f"❌ Background processing failed: {e}")
        import traceback
        traceback.print_exc()


@app.route("/today")
def today():
    """Render the briefing page with today's stored JSON injected live.
    Re-reads the data file on every request, so restarts and multiple
    gunicorn workers always serve the same digest."""
    template_path = os.path.join(os.path.dirname(__file__), "templates", "today.html")
    with open(template_path, "r", encoding="utf-8") as fh:
        html = fh.read()
    data = load_latest_mail()
    payload = json.dumps({
        "summary": data["summary"],
        "items": data["items"],
        "date": data.get("date"),
        "updated_at": data.get("updated_at"),
    })
    html = html.replace("__MAIL_DATA__", payload)
    resp = Response(html, mimetype="text/html")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.route("/today.json")
def today_json():
    """Raw JSON, used by the page's auto-refresh on visibility change."""
    data = load_latest_mail()
    resp = Response(
        json.dumps({
            "summary": data["summary"],
            "items": data["items"],
            "date": data.get("date"),
            "updated_at": data.get("updated_at"),
        }),
        mimetype="application/json",
    )
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.route("/", methods=["GET"])
def home():
    return "Mail webhook is running. Open /today to see today's mail. 📬"


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
