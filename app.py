"""
USPS Mail Webhook — Step 3: Structured JSON per mail piece
===========================================================
What this version does:
  1. Verifies the request really came from Mailgun (signature check)
  2. Pulls the JPEG scans out of the email attachments
  3. Asks OpenAI to return STRUCTURED JSON — one object per mail piece
  4. Builds a one-line headline from that JSON (code counts, not the AI)
  5. Prints both the headline and the per-piece JSON in the Railway logs
  6. Returns 200 OK fast (so Mailgun doesn't retry)

THE SCHEMA (one object per piece):
  recipient        — who the mail is addressed to
  sender           — who it's from (best guess from the envelope)
  category         — financial | government | medical | personal |
                     advertising | package | other
  is_advertisement — true/false
  is_package       — true/false
  importance       — 1 (junk/ad), 2 (normal), 3 (important: bills, govt,
                     tax, medical, legal, checks)
  action_needed    — true/false (does this likely need you to DO something)
  summary          — one short human line for the web page
  confidence       — high | medium | low (these are blurry envelope scans,
                     so honest uncertainty beats a confident wrong guess)
"""

import os
import json
import base64
import hashlib
import hmac
import requests
from flask import Flask, request

app = Flask(__name__)

# --- Secrets (set these in Railway → Variables; never hard-code them) ---
MAILGUN_SIGNING_KEY = os.environ.get("MAILGUN_SIGNING_KEY", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")

OPENAI_MODEL = "gpt-5.4-mini"  # bump to "gpt-5.5" if scans are hard to read


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


def analyze_mail_images(images):
    """
    Sends all scans to OpenAI in ONE call and gets back a list of structured
    mail pieces (Python dicts matching THE SCHEMA above).

    'images' is a list of (filename, raw_bytes) tuples.
    Returns: a list of dicts, or [] if something went wrong.
    """
    if not OPENAI_API_KEY:
        print("⚠️  No OPENAI_API_KEY set — skipping the AI analysis.")
        return []

    # WHY instructions-before-images: the model reads content in order, so
    # priming it with the task + exact schema first improves accuracy.
    instructions = (
        "These are today's USPS Informed Delivery mail scans — grayscale "
        "images of envelope exteriors and any package notices. "
        "Analyze EACH image as a separate piece of mail. "
        "Return ONLY a JSON object with a single key \"pieces\", whose value "
        "is an array. Each array element must have EXACTLY these keys:\n"
        '  "recipient": string (who it is addressed to, or "unknown"),\n'
        '  "sender": string (who it is from, best guess, or "unknown"),\n'
        '  "category": one of "financial","government","medical","personal",'
        '"advertising","package","other",\n'
        '  "is_advertisement": boolean,\n'
        '  "is_package": boolean,\n'
        '  "importance": integer 1, 2, or 3 '
        "(3 = important like bills/government/tax/medical/legal/checks; "
        "2 = normal personal mail; 1 = junk or advertising),\n"
        '  "action_needed": boolean (likely requires you to do something),\n'
        '  "summary": string (one short line describing the piece),\n'
        '  "confidence": one of "high","medium","low" '
        "(these scans are blurry — be honest about uncertainty).\n"
        "Do not add any keys. Do not include any text outside the JSON."
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
        # WHY response_format json_object: forces OpenAI to return valid JSON
        # with no ```fences or chatty preamble — the #1 cause of parse errors.
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
        parsed = json.loads(raw_text)            # safe: json mode guarantees JSON
        return parsed.get("pieces", [])
    except Exception as e:
        print(f"❌ OpenAI call/parse failed: {e}")
        return []


def build_headline(pieces):
    """
    Builds the one-line summary FROM the JSON. Code does the counting (not the
    AI) because counting must be exact. Returns a single string.

    Example: "You have 3 pieces of mail from Voya, PSECU, and Seneca, and
              1 package from Amazon today."
    """
    letters = [p for p in pieces if not p.get("is_package")]
    packages = [p for p in pieces if p.get("is_package")]

    def name_list(items):
        # Unique sender names, preserving order, skipping unknowns.
        names = []
        for p in items:
            s = p.get("sender", "unknown")
            if s and s.lower() != "unknown" and s not in names:
                names.append(s)
        if not names:
            return ""
        if len(names) == 1:
            return names[0]
        return ", ".join(names[:-1]) + ", and " + names[-1]

    parts = []
    if letters:
        senders = name_list(letters)
        piece_word = "piece" if len(letters) == 1 else "pieces"
        line = f"{len(letters)} {piece_word} of mail"
        if senders:
            line += f" from {senders}"
        parts.append(line)
    if packages:
        senders = name_list(packages)
        pkg_word = "package" if len(packages) == 1 else "packages"
        line = f"{len(packages)} {pkg_word}"
        if senders:
            line += f" from {senders}"
        parts.append(line)

    if not parts:
        return "No mail detected today."
    return "You have " + ", and ".join(parts) + " today."


@app.route("/mail-arrived", methods=["POST"])
def mail_arrived():
    data = request.form

    # --- 1. Verify it's really Mailgun ---
    if not verify_mailgun_signature(
        data.get("token", ""), data.get("timestamp", ""), data.get("signature", "")
    ):
        print("❌ Bad signature — rejecting.")
        return "Forbidden", 403

    print("\n" + "=" * 60)
    print(f"📬 NEW EMAIL — {data.get('subject', '(no subject)')}")
    print("=" * 60)

    # --- 2. Pull the JPEG scans out of the attachments ---
    images = []
    for key in request.files:
        f = request.files[key]
        raw = f.read()
        if f.content_type and f.content_type.startswith("image/"):
            images.append((f.filename, raw))
            print(f"  📎 Found image: {f.filename} ({len(raw)} bytes)")

    if not images:
        print("  (No images in this email — nothing to analyze.)")
        return "OK", 200

    # --- 3. Analyze into structured JSON ---
    print(f"\n  🤖 Sending {len(images)} image(s) to {OPENAI_MODEL}...")
    pieces = analyze_mail_images(images)

    # --- 4. Build the headline from the JSON (code counts, not the AI) ---
    headline = build_headline(pieces)

    # --- 5. Print both ---
    print("\n--- 📋 ONE-LINE SUMMARY ---")
    print(headline)
    print("\n--- 🗂️  PER-PIECE JSON ---")
    print(json.dumps(pieces, indent=2))
    print("=" * 60 + "\n")

    # --- 6. Return 200 fast ---
    return "OK", 200


@app.route("/", methods=["GET"])
def home():
    return "Mail webhook is running. Send mail to your sandbox address. 📬"


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
