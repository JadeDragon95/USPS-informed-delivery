"""
USPS Mail Webhook — Step 2: Read the scans with OpenAI
=======================================================
Now that we've seen the payload structure, this version:
  1. Verifies the request really came from Mailgun (signature check)
  2. Pulls the JPEG scans out of the email attachments
  3. Sends them to OpenAI's vision model for a summary
  4. Prints that summary in the Railway logs
  5. Returns 200 OK fast (so Mailgun doesn't retry)

Push notification + web page come later — one layer at a time.
"""

import os
import base64
import hashlib
import hmac
import requests
from flask import Flask, request

app = Flask(__name__)

# --- Secrets (set these in Railway → Variables; never hard-code them) ---
MAILGUN_SIGNING_KEY = os.environ.get("MAILGUN_SIGNING_KEY", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")

# Vision-capable, fast, and cheap — ideal for a daily batch of mail scans.
# Bump to "gpt-5.5" if the scans ever come out too blurry to read.
OPENAI_MODEL = "gpt-5.4-mini"


def verify_mailgun_signature(token, timestamp, signature):
    """
    WHY: your webhook URL is public. Without this check, anyone could POST
    fake 'emails' to it. Mailgun proves it's really them with a signature
    we recompute and compare.
    """
    if not MAILGUN_SIGNING_KEY:
        print("⚠️  WARNING: No MAILGUN_SIGNING_KEY set. Skipping signature check.")
        return True
    expected = hmac.new(
        key=MAILGUN_SIGNING_KEY.encode("utf-8"),
        msg=f"{timestamp}{token}".encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def summarize_mail_images(images):
    """
    Sends the scan images to OpenAI and returns a text summary.

    'images' is a list of (filename, raw_bytes) tuples.
    WHY one call with all images: cheaper and faster than looping, and the
    model can cross-reference pieces (e.g. spot two from the same sender).
    """
    if not OPENAI_API_KEY:
        return "⚠️  No OPENAI_API_KEY set — skipping the AI summary for now."

    # WHY instructions-before-images: vision models read the content list in
    # order, so priming them with the task first improves what they extract.
    content = [{
        "type": "text",
        "text": (
            "These are today's USPS Informed Delivery mail scans. "
            "For each piece of mail, identify the sender if readable, briefly "
            "describe what it looks like, and flag anything important such as "
            "bills, government mail, medical mail, or checks. Note any packages "
            "separately. Keep it short and scannable — one line per piece."
        ),
    }]

    # Attach each image as a base64 data URL (how the API accepts inline images).
    for filename, raw_bytes in images:
        b64 = base64.b64encode(raw_bytes).decode("utf-8")
        content.append({
            "type": "image_url",
            "image_url": {"url": f"data:image/jpeg;base64,{b64}"},
        })

    payload = {
        "model": OPENAI_MODEL,
        "messages": [{"role": "user", "content": content}],
    }

    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=60,  # vision calls take a few seconds; don't hang forever
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        # WHY catch broadly: a failed AI call shouldn't crash the webhook and
        # make Mailgun retry. We log the error and still return 200 below.
        return f"❌ OpenAI call failed: {e}"


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
    # From the real USPS payload we saw: images arrive in request.files as
    # attachment-1, attachment-2, etc., as image/jpeg.
    images = []
    for key in request.files:
        f = request.files[key]
        raw = f.read()
        if f.content_type and f.content_type.startswith("image/"):
            images.append((f.filename, raw))
            print(f"  📎 Found image: {f.filename} ({len(raw)} bytes)")

    if not images:
        print("  (No images in this email — nothing to summarize.)")
        return "OK", 200

    # --- 3. Send to OpenAI for a summary ---
    print(f"\n  🤖 Sending {len(images)} image(s) to {OPENAI_MODEL}...")
    summary = summarize_mail_images(images)

    # --- 4. Print the result ---
    print("\n--- 📋 TODAY'S MAIL SUMMARY ---")
    print(summary)
    print("=" * 60 + "\n")

    # --- 5. Return 200 fast ---
    return "OK", 200


@app.route("/", methods=["GET"])
def home():
    return "Mail webhook is running. Send mail to your sandbox address. 📬"


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
