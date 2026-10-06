# Design decisions

Short notes on the choices that shaped phonecheck, what each trades away, and what would change them.

## 1. Android only, over ADB

iOS gives no way for a computer to list or remove apps without enrolling the device in management, which a customer's personal phone will not be. Android's debugging bridge (ADB) can list installed apps, read their permissions, and uninstall them, with no root and no app installed on the phone.
**Trade-off:** it only covers Android, and the owner has to enable USB debugging. A narrow tool that works beats a universal one that only pretends to.

## 2. Reading and changing are separate, and changing is hard to do by accident

The collector and rule engine only read. `removal.py` is the single place that changes a phone, and it is small on purpose: valid package name, present in the phone's *current* user-app list, chosen by a person. The CLI makes the person choose numbers and then type `remove`; the web page requires a click plus a confirm dialog plus an explicit `confirm` field in the API call. Nothing is ever preselected and there is no `--yes`.
**Why:** a wrong removal on someone's phone is the worst thing this tool can do. Making that path narrow and boring is worth more than a faster one.

## 3. A transparent points system, not machine learning

Each rule returns points and a sentence. The score is the sum. Every flag can be explained to a customer ("it can draw over other apps, which is how fake virus pop-ups appear") and traced to one function.
**Why not ML:** there is no labelled dataset, an unexplainable "78% junk" is useless at a counter, and a bad call has to be debuggable. **What would change this:** a few hundred real, labelled phones. Even then the explanation layer would stay.
**Weights are judgment calls.** Strong signals (accessibility service, device administrator, known junk) are 4-8; weak ones (starts at boot, recently installed) are 1. They are constants in `rules.py`, covered by tests that pin the demo phone's scores, so a change to a weight is a visible, deliberate edit.

## 4. A suspicious name alone never means "likely junk"

A junk-sounding package name is worth 3 points, exactly the "worth a look" threshold and below the 6 needed for "likely junk". Legitimate security apps have names like these too. Behaviour (overlay, accessibility service, device-admin rights, off-store install) is what moves an app to the top.

## 5. Trusting an app requires a real store installer

Skipping well-known apps avoids false alarms on WhatsApp, Spotify and so on, but a package name is only a string. A modified or look-alike APK installed from a file can reuse `com.instagram.android`. So trust applies only when the installer is also a known store, and an entry on the junk list overrides trust. The demo phone contains exactly this case and a test pins it.

## 6. One small device interface, three implementations

`shell(*args)` and `uninstall(package)`. A real phone, a replay of recorded text, and a recorder that wraps another device all satisfy it. This is what makes 270+ tests, a hardware-free demo, and `capture` (turn a real phone's output into a new test fixture) possible without mocking `subprocess` everywhere. The demo phones are produced by pushing scripted answers through the real collector and recorder, and a test fails if the committed copies drift.

## 7. Standard library only

No runtime dependencies. It installs anywhere Python 3.10+ runs, there is nothing to audit or update, and the web server is `http.server` plus roughly 230 lines. The only third-party package anywhere is Playwright, as an optional test tool.
**Trade-off:** more hand-written code than a framework would need. For three endpoints that is cheaper than a dependency.

## 8. Untrusted text on both sides

*Toward the phone:* arguments sent to `adb shell` run through a shell on the phone, so each is checked against a character allowlist and package names must match Android's naming rules. *From the phone:* version strings and package names are whatever an app's author typed, so the HTML report escapes everything and the web page only ever uses `textContent`. Tests include a hostile version string that must appear as text and not execute in a real browser.

## 9. The local web server is treated as a target

A page on localhost that can uninstall apps is attractive to any website the user happens to visit. Defences, each tested: bind to 127.0.0.1 only; exact `Host` header match (DNS rebinding); a random per-run token the page gets from the server (cross-site request forgery); JSON-only POST bodies (browsers can't send these cross-origin without a preflight that is never approved); no CORS headers; a strict Content-Security-Policy with no inline script; request-size limit; errors never include internals.

## 10. Privacy by omission

It only asks for what the rules need. It does not read contacts, messages, photos, accounts or identifiers, and reports and JSON contain none (a test checks this). The one risk left is `capture`, whose output lists every installed app, so it warns, and `.gitignore` excludes captures and generated reports.

## Known weaknesses

- Parsers are written for the commonly documented `dumpsys` formats and have been tested against synthetic and recorded output, not yet a wide range of real phones. `capture` exists to close that gap.
- False positives are expected for legitimate security apps. The report says "signals, not verdicts" and a person always decides.
- Reports show package names rather than app titles; resolving titles would need more than the standard shell commands offer.
