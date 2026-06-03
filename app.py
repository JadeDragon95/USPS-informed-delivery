"""
USPS Mail Webhook — Step 1: the Payload Dumper
================================================
This is the FIRST version. Its only job: catch what Mailgun POSTs
and show you exactly what's inside, so we can see how USPS structures
its scan images before writing extraction logic.

It does three things:
  1. Verifies the request really came from Mailgun (signature check)
  2. Logs the entire parsed payload so you can inspect it
  3. Returns 200 OK fast (so Mailgun doesn't retry)
"""

import os
import hashlib
import hmac
import json
from flask import Flask, request

app = Flask(__name__)

# Mailgun signs every webhook with your account's signing key.
# We'll set this on Railway later (never hard-code secrets in the file).
MAILGUN_SIGNING_KEY = os.environ.get("MAILGUN_SIGNING_KEY", "")


def verify_mailgun_signature(token, timestamp, signature):
    """
    WHY this exists: your webhook URL is public. Without this check,
    ANYONE could POST fake "emails" to it. Mailgun proves it's really
    them by sending a signature we can recompute and compare.
    """
    if not MAILGUN_SIGNING_KEY:
        # No key set yet — allow through so you can test, but warn loudly.
        print("⚠️  WARNING: No MAILGUN_SIGNING_KEY set. Skipping signature check.")
        return True

    expected = hmac.new(
        key=MAILGUN_SIGNING_KEY.encode("utf-8"),
        msg=f"{timestamp}{token}".encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()
    # hmac.compare_digest avoids timing attacks — the safe way to compare.
    return hmac.compare_digest(expected, signature)


@app.route("/mail-arrived", methods=["POST"])
def mail_arrived():
    # Mailgun sends the email as form data (not JSON), so we read request.form.
    data = request.form

    # --- 1. Verify it's really Mailgun ---
    token = data.get("token", "")
    timestamp = data.get("timestamp", "")
    signature = data.get("signature", "")
    if not verify_mailgun_signature(token, timestamp, signature):
        print("❌ Bad signature — rejecting.")
        return "Forbidden", 403

    # --- 2. Dump EVERYTHING so we can see the structure ---
    print("\n" + "=" * 60)
    print("📬 NEW EMAIL RECEIVED — full payload below")
    print("=" * 60)

    # The common parsed fields Mailgun gives you:
    print(f"From:        {data.get('from', '(none)')}")
    print(f"Subject:     {data.get('subject', '(none)')}")
    print(f"Recipient:   {data.get('recipient', '(none)')}")
    print(f"# of attachments: {data.get('attachment-count', '0')}")

    print("\n--- ALL FORM FIELDS (this is the key part) ---")
    for field_name in sorted(data.keys()):
        value = data.get(field_name, "")
        # Truncate huge fields (like the full HTML body) so logs stay readable
        preview = value if len(value) < 300 else value[:300] + f"... [{len(value)} chars total]"
        print(f"  • {field_name}: {preview}")

    # --- 3. Show uploaded files (attachments / inline images) ---
    print("\n--- UPLOADED FILES (attachments & inline images) ---")
    if request.files:
        for key in request.files:
            f = request.files[key]
            content = f.read()
            print(f"  • {key}: filename='{f.filename}', "
                  f"type='{f.content_type}', size={len(content)} bytes")
    else:
        print("  (none in request.files)")

    print("=" * 60 + "\n")

    # --- 4. Return 200 FAST ---
    # WHY: a non-2xx makes Mailgun retry the same message over and over.
    return "OK", 200


@app.route("/", methods=["GET"])
def home():
    # A simple page so you can confirm the server is alive in a browser.
    return "Mail webhook is running. Send mail to your sandbox address. 📬"


if __name__ == "__main__":
    # Railway tells us which port to use via the PORT environment variable.
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
