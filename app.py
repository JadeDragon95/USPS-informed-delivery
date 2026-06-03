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
# Your ntfy topic. Default matches what you subscribed to on your phone.
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "usps_informed_delivery")
# Your public page URL — tapping the notification opens this.
PUBLIC_URL = os.environ.get("PUBLIC_URL", "https://web-production-0d2b6.up.railway.app")

OPENAI_MODEL = "gpt-5.4-mini"

# --- The shared store: webhook writes, /today reads ---
# WHY a plain dict in memory: you chose "today only," so there's nothing to
# persist. New mail overwrites. Clears on redeploy (acceptable for a daily view).
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
        "1) The attached grayscale IMAGES are scans of envelope exteriors "
        "(letters/mail pieces).\n"
        "2) The TEXT below lists EXPECTED PACKAGES ('FROM:' senders, expected "
        "timing, tracking numbers).\n\n"
        "Return ONLY a JSON object with a single key \"items\", an array.\n\n"
        "For each MAIL piece in the images, an object with EXACTLY:\n"
        '  "type": "mail",\n'
        '  "recipient": string (addressee or "unknown"),\n'
        '  "sender": string (SHORT readable name like "IRS", not the full '
        'address block; or "unknown"),\n'
        '  "category": one of "financial","government","medical","personal",'
        '"advertising","other",\n'
        '  "is_advertisement": boolean,\n'
        '  "importance": 1, 2, or 3 (3=bills/government/tax/medical/legal/'
        "checks; 2=normal personal mail; 1=junk/ads),\n"
        '  "action_needed": boolean,\n'
        '  "summary": string (one short line),\n'
        '  "confidence": "high","medium", or "low" (scans are blurry — be '
        "honest).\n\n"
        "For each PACKAGE in the text, an object with EXACTLY:\n"
        '  "type": "package",\n'
        '  "sender": string (the FROM: company),\n'
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
        return json.loads(raw_text).get("items", [])
    except Exception as e:
        print(f"❌ OpenAI call/parse failed: {e}")
        return []


def build_headline(items):
    """Build the one-line summary FROM the JSON. Code counts (exact)."""
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

    parts = []
    if letters:
        senders = name_list(letters)
        word = "piece" if len(letters) == 1 else "pieces"
        line = f"{len(letters)} {word} of mail"
        if senders:
            line += f" from {senders}"
        parts.append(line)
    if packages:
        senders = name_list(packages)
        word = "package" if len(packages) == 1 else "packages"
        line = f"{len(packages)} {word}"
        if senders:
            line += f" from {senders}"
        parts.append(line)

    if not parts:
        return "No mail or packages detected today."
    body = parts[0] if len(parts) == 1 else parts[0] + " and " + parts[1]
    return "You have " + body + " today."


def send_push(headline, items):
    """Fire an Ntfy notification. Tapping it opens the /today page.
    Body leads with PACKAGES (most actionable), then the mail count."""
    if not NTFY_TOPIC:
        return
    packages = [i for i in items if i.get("type") == "package"]
    mail = [i for i in items if i.get("type") != "package"]
    action_count = len([i for i in mail if i.get("action_needed")])

    def name_list(group):
        names = []
        for p in group:
            s = p.get("sender", "")
            if s and s.lower() != "unknown" and s not in names:
                names.append(s)
        if not names:
            return ""
        if len(names) == 1:
            return names[0]
        if len(names) == 2:
            return names[0] + " and " + names[1]
        return ", ".join(names[:-1]) + ", and " + names[-1]

    # Build the message with packages FIRST.
    lines = []
    if packages:
        senders = name_list(packages)
        word = "package" if len(packages) == 1 else "packages"
        line = f"📦 {len(packages)} {word}"
        if senders:
            line += f" from {senders}"
        lines.append(line)
    if mail:
        senders = name_list(mail)
        word = "piece" if len(mail) == 1 else "pieces"
        line = f"✉️ {len(mail)} {word} of mail"
        if senders:
            line += f" from {senders}"
        if action_count:
            line += f" ({action_count} need action)"
        lines.append(line)
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

    WHY no AI: these emails follow a strict USPS template, so regex is
    instant, free, and more reliable than asking a model to extract fields.
    Returns a dict {sender, time, tracking, is_today} or None if it can't
    parse confidently (in which case we skip the alert rather than guess).

    Example subject:
      "USPS® Expected Delivery on Saturday, May 16, 2026 arriving by 9:00pm 9234..."
    Example body:
      "...Your item is out for delivery on May 16, 2026 at 7:49 am in
       SHINGLEHOUSE, PA 16748. USPS expects to deliver your package today
       by 9:00pm. Tracking Number: 9234690376107700453486
       Package Shipped from: BEAUTYLISH, INC."
    """
    text = (subject or "") + "\n" + (body_text or "")

    # Tracking number: long digit string (USPS = 20+ digits)
    tracking_match = re.search(r"\b(\d{20,})\b", text)
    tracking = tracking_match.group(1) if tracking_match else None

    # Sender: "Package Shipped from: NAME" or "Shipped from: NAME"
    sender_match = re.search(r"(?:Package\s+)?Shipped from:\s*(.+?)(?:\n|$)",
                             text, re.IGNORECASE)
    sender = sender_match.group(1).strip().rstrip(".,") if sender_match else None

    # Expected time: "by 9:00pm" / "by 9:00 PM"
    time_match = re.search(r"by\s+(\d{1,2}:\d{2}\s*(?:am|pm|AM|PM))", text)
    expected_time = time_match.group(1).lower().replace(" ", "") if time_match else None

    # Is today vs future day: USPS body literally says "today" for same-day
    # ("USPS expects to deliver your package today by ...").
    is_today = bool(re.search(r"\bdeliver\s+your\s+package\s+today\b", text, re.IGNORECASE))

    # For non-today: pull the weekday out of the subject ("Expected Delivery on Saturday,...")
    day_match = re.search(
        r"Expected Delivery on\s+(Sunday|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday)",
        text, re.IGNORECASE,
    )
    weekday = day_match.group(1).capitalize() if day_match else None

    if not tracking or not sender:
        # Can't confidently identify the package — bail rather than guess.
        return None
    return {
        "sender": sender,
        "tracking": tracking,
        "expected_time": expected_time,    # e.g. "9:00pm" or None
        "is_today": is_today,
        "weekday": weekday,                # e.g. "Saturday" or None
    }


def send_delivery_alert_push(alert):
    """Send a HIGH-priority push for an individual delivery alert.
    Tapping it opens the USPS tracking page for THAT package."""
    if not NTFY_TOPIC:
        return

    # Title: "Your package from X is/will be out for delivery today/on Saturday"
    if alert["is_today"]:
        title = f"Your package from {alert['sender']} is out for delivery today"
    elif alert["weekday"]:
        title = f"Your package from {alert['sender']} will be out for delivery on {alert['weekday']}"
    else:
        # Fallback if we couldn't parse the day — still useful, just less specific
        title = f"Your package from {alert['sender']} is out for delivery"

    # Body: arrival window + tracking number
    body_parts = []
    if alert["expected_time"]:
        body_parts.append(f"Arriving by {alert['expected_time']}")
    body_parts.append(f"Tracking: {alert['tracking']}")
    body = " · ".join(body_parts)

    # USPS tracking deep link — tapping the notification jumps right to status.
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
                "Priority": "high",     # bypasses Do Not Disturb on most setups
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

    # --- Route by email type (cheap subject check, no AI) ---
    # USPS sends two distinct kinds of email:
    #   1) "Daily Digest" — the morning summary (process for /today, full pipeline)
    #   2) "Expected Delivery" / "Out for Delivery" — per-package alerts (push only)
    # WHY split here: delivery alerts are real-time moments, not summary data,
    # so they shouldn't overwrite /today or cost an OpenAI call.
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

    # --- Otherwise: full Daily Digest pipeline ---
    images = []
    for key in request.files:
        f = request.files[key]
        raw = f.read()
        if f.content_type and f.content_type.startswith("image/"):
            images.append((f.filename, raw))
            print(f"  📎 Found image: {f.filename} ({len(raw)} bytes)")

    body_text = data.get("stripped-text") or data.get("body-plain") or ""
    print(f"  📝 Body text: {len(body_text)} chars")

    if not images and not body_text:
        print("  (Nothing to analyze.)")
        return "OK", 200
    print(f"\n  🤖 Sending {len(images)} image(s) + body text to {OPENAI_MODEL}...")
    items = analyze_mail(images, body_text)
    headline = build_headline(items)

    # --- Store the single result object (the page reads this) ---
    LATEST_MAIL["summary"] = headline
    LATEST_MAIL["items"] = items
    LATEST_MAIL["updated_at"] = datetime.utcnow().isoformat()

    print("\n--- 📋 SUMMARY ---")
    print(headline)
    print("--- 🗂️  ITEMS ---")
    print(json.dumps(items, indent=2))

    # --- Notify your phone ---
    send_push(headline, items)
    print("=" * 60 + "\n")

    return "OK", 200


@app.route("/today")
def today():
    """Render the briefing page with today's stored JSON injected live."""
    # Load the HTML template and swap the placeholder for real data.
    # WHY inject server-side: the page gets the data at load time, so there's
    # no separate API call — open the URL and it's just there.
    template_path = os.path.join(os.path.dirname(__file__), "templates", "today.html")
    with open(template_path, "r", encoding="utf-8") as fh:
        html = fh.read()
    payload = json.dumps({
        "summary": LATEST_MAIL["summary"],
        "items": LATEST_MAIL["items"],
    })
    html = html.replace("__MAIL_DATA__", payload)
    resp = Response(html, mimetype="text/html")
    # Layered anti-cache: no single header is enough on iOS Safari. We combine
    # Cache-Control (modern), Pragma (HTTP/1.0 fallback), and Expires (legacy)
    # so every layer is told the same thing — never reuse this response.
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
