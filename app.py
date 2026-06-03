"""
USPS Mail Webhook — Step 4: Mail (from images) + Packages (from body text)
===========================================================================
Key insight this version handles: USPS package info is NOT in the scan
images — it's TEXT in the email body ("Expected Today / FROM: ... / tracking#").
So we now send BOTH the images AND the body text to OpenAI, and it returns
two kinds of items:

  MAIL piece (from the envelope scans):
    type="mail", recipient, sender, category, is_advertisement,
    importance (1-3), action_needed, summary, confidence

  PACKAGE (from the body text):
    type="package", sender, tracking_number, expected, summary

A "type" field tells our code which shape each item is.
"""

import os
import json
import base64
import hashlib
import hmac
import requests
from flask import Flask, request

app = Flask(__name__)

MAILGUN_SIGNING_KEY = os.environ.get("MAILGUN_SIGNING_KEY", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = "gpt-5.4-mini"


def verify_mailgun_signature(token, timestamp, signature):
    """WHY: the URL is public; this proves the POST is really from Mailgun."""
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
    """
    ONE OpenAI call with both the envelope images AND the email body text.
    Returns a list of dicts — a mix of type="mail" and type="package".
    """
    if not OPENAI_API_KEY:
        print("⚠️  No OPENAI_API_KEY set — skipping the AI analysis.")
        return []

    instructions = (
        "You are analyzing a USPS Informed Delivery daily digest.\n\n"
        "TWO sources of information:\n"
        "1) The attached grayscale IMAGES are scans of envelope exteriors "
        "(letters/mail pieces).\n"
        "2) The TEXT below lists EXPECTED PACKAGES (with 'FROM:' senders, "
        "expected-delivery timing, and tracking numbers).\n\n"
        "Return ONLY a JSON object with a single key \"items\", an array.\n\n"
        "For each MAIL piece seen in the images, add an object with EXACTLY:\n"
        '  "type": "mail",\n'
        '  "recipient": string (addressee, or "unknown"),\n'
        '  "sender": string (short readable name, e.g. "IRS", not the full '
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
        "For each PACKAGE found in the text, add an object with EXACTLY:\n"
        '  "type": "package",\n'
        '  "sender": string (the FROM: company),\n'
        '  "tracking_number": string (the long digit string, or "unknown"),\n'
        '  "expected": string (e.g. "Today", "1-2 Days", or "unknown"),\n'
        '  "summary": string (one short line).\n\n'
        "Do not add keys beyond those listed for each type. "
        "Do not include any text outside the JSON.\n\n"
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
    """Builds the one-line summary. Code counts (exact); AI doesn't."""
    letters = [i for i in items if i.get("type") == "mail"]
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
        # 3+ names: Oxford-comma style "A, B, and C"
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
    # Join the mail-part and package-part. Use " and " (no comma) since each
    # part may already contain commas in its own sender list — avoids the
    # awkward "IRS, and PSECU, and 2 packages" double-"and" pileup.
    if len(parts) == 1:
        body = parts[0]
    else:
        body = parts[0] + " and " + parts[1]
    return "You have " + body + " today."


@app.route("/mail-arrived", methods=["POST"])
def mail_arrived():
    data = request.form

    if not verify_mailgun_signature(
        data.get("token", ""), data.get("timestamp", ""), data.get("signature", "")
    ):
        print("❌ Bad signature — rejecting.")
        return "Forbidden", 403

    print("\n" + "=" * 60)
    print(f"📬 NEW EMAIL — {data.get('subject', '(no subject)')}")
    print("=" * 60)

    # Pull envelope scans from attachments
    images = []
    for key in request.files:
        f = request.files[key]
        raw = f.read()
        if f.content_type and f.content_type.startswith("image/"):
            images.append((f.filename, raw))
            print(f"  📎 Found image: {f.filename} ({len(raw)} bytes)")

    # Pull the body text (where package info lives). Prefer stripped-text
    # (Mailgun removes quoted/forwarded cruft); fall back to body-plain.
    body_text = data.get("stripped-text") or data.get("body-plain") or ""
    print(f"  📝 Body text: {len(body_text)} chars")

    if not images and not body_text:
        print("  (Nothing to analyze.)")
        return "OK", 200

    print(f"\n  🤖 Sending {len(images)} image(s) + body text to {OPENAI_MODEL}...")
    items = analyze_mail(images, body_text)

    headline = build_headline(items)

    print("\n--- 📋 ONE-LINE SUMMARY ---")
    print(headline)
    print("\n--- 🗂️  ITEMS JSON ---")
    print(json.dumps(items, indent=2))
    print("=" * 60 + "\n")

    return "OK", 200


@app.route("/", methods=["GET"])
def home():
    return "Mail webhook is running. Send mail to your sandbox address. 📬"


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
