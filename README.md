# USPS-informed-delivery

## Web Push (optional)

The `/today` PWA can receive a browser notification whenever a new digest is
processed — same content as the ntfy push. Set these Railway variables on the
app service and redeploy:

```
WEB_PUSH_PUBLIC_KEY=<public key>
WEB_PUSH_PRIVATE_KEY=<private key>
WEB_PUSH_EMAIL=you@example.com
```

Generate a keypair with `npx web-push generate-vapid-keys`. Then open `/today`
in Safari, tap "Enable notifications", and install it to the home screen.
Subscriptions are stored next to the digest in `data/push_subscriptions.json`
(persist with the same Railway Volume used for `DATA_DIR`).
