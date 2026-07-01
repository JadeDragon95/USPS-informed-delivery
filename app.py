"""
USPS Mail Webhook — Step 5: Full pipeline (webhook + push + web page)
======================================================================
The complete flow:
  1. Mailgun POSTs the forwarded USPS email to /mail-arrived
  2. We verify it's really Mailgun (signature check)
  3. We pull envelope scans (images) + body text (packages)
  4. OpenAI returns structured JSON (mail pieces + packages)
  5. We build ONE result object {summary, items} and STORE it in memory
  6. We fire an Ntfy push notification (tap it -> opens /today)
  7. You open /today -> the page renders today's stored JSON beautifully

Everything lives in one Flask app on Railway. The web page and the webhook
share data through the in-memory LATEST_MAIL variable: the webhook writes it,
the /today page reads it. New mail each day overwrites it (today-only view).
"""

import os
import re
import json
import base64
import hashlib
import hmac
from datetime import datetime

import requests
from flask import Flask, request, Response

app = Flask(__name__)

# --- Secrets / config (set these in Railway -> Variables) ---
MAILGUN_SIGNING_KEY = os.environ.get("MAILGUN_SIGNING_KEY", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "usps_informed_delivery")
PUBLIC_URL = os.environ.get("PUBLIC_URL", "https://web-production-0d2b6.up.railway.app")

OPENAI_MODEL = "gpt-5.4-mini"

LATEST_MAIL = {"summary": "No mail processed yet today.", "items": [], "updated_at": None}


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
        '  "tracking_number": string (the long digit string or "unknown"),\n'
        '  "expected": string ("Today", "1-2 Days", or "unknown"),\n'
        '  "summary": string (one short line).\n\n'
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
        print(raw_text[:2500])
        if len(raw_text) > 2500:
            print(f"... [+{len(raw_text) - 2500} more chars]")
        print("--- 🔍 END RESPONSE ---")
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
        r"You have\s+(\d+)\s+mailpiece[s]?\s*\(s\)\s+and\s+(\d+)\s+inbound package[s]?\s*\(s\)",
        body_text, re.IGNORECASE,
    )
    if m:
        return int(m.group(1)), int(m.group(2))
    m2 = re.search(r"You have\s+(\d+)\s+mailpiece[s]?\s*\(s\)", body_text, re.IGNORECASE)
    if m2:
        return int(m2.group(1)), 0
    return None, None


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
        requests.post(
            f"https://ntfy.sh/{NTFY_TOPIC}",
            data=body.encode("utf-8"),
            headers={
                "Title": "Today's Mail",
                "Tags": "mailbox_with_mail",
                "Click": f"{PUBLIC_URL}/today",
                "Priority": "default",
            },
            timeout=10,
        )
        print(f"  🔔 Push sent to ntfy.sh/{NTFY_TOPIC}")
    except Exception as e:
        print(f"  ⚠️  Push failed (not fatal): {e}")


def parse_delivery_alert(subject, body_text):
    """
    Pull sender, expected time, and tracking number out of a USPS delivery
    alert email using plain regex — NO AI call needed.
    Returns a dict {sender, time, tracking, is_today} or None if unparseable.
    """
    text = (subject or "") + "\n" + (body_text or "")

    tracking_match = re.search(r"\b(\d{20,})\b", text)
    tracking = tracking_match.group(1) if tracking_match else None

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
        requests.post(
            f"https://ntfy.sh/{NTFY_TOPIC}",
            data=body.encode("utf-8"),
            headers={
                "Title": title,
                "Tags": "package",
                "Click": usps_url,
                "Priority": "high",
            },
            timeout=10,
        )
        print(f"  🔔 Delivery alert pushed: {alert['sender']} / {alert['tracking']}")
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

    print("\n" + "=" * 60)
    subject = data.get("subject", "")
    print(f"📬 NEW EMAIL — {subject or '(no subject)'}")
    print("=" * 60)

    body_text = data.get("stripped-text") or data.get("body-plain") or ""
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
        return "OK", 200

    # --- Full Daily Digest pipeline ---
    # Skip images under 5 KB — those are logos/spacers, not mailpiece scans.
    MIN_MAILPIECE_BYTES = 5_000
    images = []
    for key in request.files:
        f = request.files[key]
        raw = f.read()
        if f.content_type and f.content_type.startswith("image/"):
            if len(raw) < MIN_MAILPIECE_BYTES:
                print(f"  ⏭️  Skipped small image (likely logo/spacer): {f.filename} ({len(raw)} bytes)")
                continue
            images.append((f.filename, raw))
            print(f"  📎 Found image: {f.filename} ({len(raw)} bytes)")

    body_text = data.get("stripped-text") or data.get("body-plain") or ""
    print(f"  📝 Body text: {len(body_text)} chars")

    if not images and not body_text:
        print("  (Nothing to analyze.)")
        return "OK", 200

    mail_count, package_count = parse_digest_counts(body_text)
    if mail_count is not None:
        print(f"  📊 Email says: {mail_count} mailpiece(s), {package_count} package(s)")

    print(f"\n  🤖 Sending {len(images)} image(s) + body text to {OPENAI_MODEL}...")
    items = analyze_mail(images, body_text)
    headline = build_headline(items, mail_count=mail_count, package_count=package_count)

    LATEST_MAIL["summary"] = headline
    LATEST_MAIL["items"] = items
    LATEST_MAIL["updated_at"] = datetime.utcnow().isoformat()

    print("\n--- 📋 SUMMARY ---")
    print(headline)
    print("--- 🗂️  ITEMS ---")
    print(json.dumps(items, indent=2))

    send_push(headline, items)
    print("=" * 60 + "\n")

    return "OK", 200


@app.route("/today")
def today():
    """Render the briefing page with today's stored JSON injected live."""
    template_path = os.path.join(os.path.dirname(__file__), "templates", "today.html")
    with open(template_path, "r", encoding="utf-8") as fh:
        html = fh.read()
    payload = json.dumps({
        "summary": LATEST_MAIL["summary"],
        "items": LATEST_MAIL["items"],
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
    resp = Response(
        json.dumps({"summary": LATEST_MAIL["summary"], "items": LATEST_MAIL["items"]}),
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
