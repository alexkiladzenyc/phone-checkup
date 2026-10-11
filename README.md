# phonecheck

[![CI](https://github.com/alexkiladzenyc/phone-checkup/actions/workflows/ci.yml/badge.svg)](https://github.com/alexkiladzenyc/phone-checkup/actions/workflows/ci.yml)
![Python 3.10–3.13](https://img.shields.io/badge/python-3.10%E2%80%933.13-blue)
![Dependencies: none](https://img.shields.io/badge/runtime%20dependencies-none-brightgreen)

A command-line tool (plus a small local web page) that plugs into an Android phone over USB, looks through the installed apps, and tells you which ones look like scareware and why. You decide what gets removed.

![The web interface after scanning the demo phone](docs/screenshot.png)

## Why I built it

I work in phone retail, and "can you check if something's wrong with my phone?" comes up all the time. Nine times out of ten the answer is a fake cleaner, booster or "antivirus" app whose whole job is to make the phone look infected. Finding them means going through Settings app by app and uninstalling each one by hand, several times a day.

So I wrote something to do the looking for me. It reads what Android will share over USB, scores each app on what it actually does, and writes the reasons in language I can read out to a customer. It never removes anything unless I tell it to.

## Trying it without a phone

You need Python 3.10 or newer. There's nothing else to install.

```bash
git clone https://github.com/alexkiladzenyc/phone-checkup.git
cd phone-checkup
pip install -e .

phonecheck scan --demo messy      # a made-up phone full of junk
phonecheck scan --demo clean      # a healthy one
phonecheck remove --demo messy    # the removal flow (simulated, nothing real happens)
phonecheck serve --demo messy     # same thing in the browser
```

The demo phones are fake ("DemoCorp" models) and come from `tools/make_demo_phones.py`. No real phone data is in this repo.

## Using it on a real phone

Install Android's [platform-tools](https://developer.android.com/tools/releases/platform-tools) so `adb` is on your PATH. On the phone, go to Settings > About phone and tap *Build number* seven times, then turn on *USB debugging* under Developer options. Plug it in and tap *Allow* when it asks.

```bash
phonecheck devices              # check the phone shows up
phonecheck scan                 # print the report
phonecheck scan --format html   # save a page to show the customer
phonecheck remove               # pick apps to remove (it asks twice)
phonecheck serve                # the browser version
```

Remember to switch USB debugging off afterwards. The tool reminds you at the end.

## What it looks at

Everything comes from standard `adb shell` commands. For the phone itself: model, Android version, battery and storage. For each app you installed (system apps are skipped): where it was installed from, version, install date, permissions, and whether it can draw over other apps, has an accessibility service or notification listener turned on, is a device administrator, has a home-screen icon, or has been excused from battery saving.

It doesn't touch contacts, messages, photos, call history, accounts, the phone number, serial or IMEI. The only thing that ever changes the phone is `remove` (or the remove button in the web page), and only after you confirm.

## How apps get scored

Each rule is a small function that returns some points and a sentence explaining itself. An app's score is just the total.

| Rule | Points | What it means |
|---|---|---|
| `known_junk` | 8 | On your known-junk list |
| `accessibility_service` | 4 | Can read the screen and tap for you |
| `device_admin` | 4 | Can lock the phone and resist being uninstalled |
| `junk_name` | 3 | Name sounds like a cleaner/booster/antivirus |
| `hidden_icon` | 3 | No home-screen icon, so the owner can't find it |
| `notification_listener` | 3 | Can read every notification, login codes included |
| `not_from_store` | 2 | Didn't come from an app store |
| `overlay` | 2 | Can draw over other apps (that's how the fake "virus found" pop-ups work) |
| `cleaner_permissions` | 2 | Asks for the permissions fake cleaners use to look busy |
| `sensitive_access` | 2 | Has access to 3+ of texts, contacts, call history, mic, calls |
| `boot_start` | 1 | Starts itself whenever the phone turns on |
| `recently_installed` | 1 | Installed in the last week |
| `installs_apps` | 1 | Can ask to install other apps |
| `battery_exempt` | 1 | Android never puts it to sleep |

6 or more is "likely junk", 3 to 5 is "worth a look", and anything under 3 isn't shown. A suspicious name on its own only gets you to 3, so an app has to actually *do* something sketchy to be called junk. I explain why I went with points instead of anything fancier in [DECISIONS.md](DECISIONS.md).

A few other things it does:

- Well-known apps in `data/trusted_apps.txt` are skipped, but only if they came from a real store. A sideloaded APK pretending to be Instagram still gets scored (there's one on the demo phone).
- `data/known_junk.txt` is empty on purpose. When I run into a new fake cleaner I add it there and every scan after that catches it. You can pass your own lists with `--junk-list` and `--trusted-list`.
- If the phone's answer to something can't be understood, the tool assumes nothing rather than assuming the worst. Otherwise one weird manufacturer could make every app look hidden.

## Keeping a history

The same junk shows up over and over, so I wanted to know which apps to watch for. Add `--save` to `scan`, `remove` or `serve` and the scan gets logged to a small SQLite file on your computer (`--db` or the `PHONECHECK_DB` variable to put it somewhere else).

```bash
phonecheck history                      # recent scans
phonecheck history stats                # most flagged apps, and which rules flagged them
phonecheck history stats --since 2026-10-01
phonecheck history export --out flagged.csv
```

It only saves the phone model and the apps that got flagged, never the full app list or anything about the owner.

If you want to see what changed on a phone between two visits, save a JSON report each time and diff them:

```bash
phonecheck scan --format json --out before.json
# ...later
phonecheck scan --format json --out after.json
phonecheck diff before.json after.json
```

It lists what's new, what's gone, and what got better or worse. `--fail-on-new` makes it exit with 1 if anything new or worse turned up, in case you want to script it.

## Safety

Removing the wrong app from someone's phone is the worst thing this tool could do, so that part is deliberately slow:

- Nothing is pre-ticked. `remove` shows the list, asks for numbers, then makes you type `remove`. There's no `--yes` flag.
- Before uninstalling, it re-reads the phone's list of user-installed apps and refuses anything that isn't on it, so system apps and typos can't be hit. If one package is refused, nothing is removed.
- Every argument sent to the phone is checked against a character allowlist, so text coming from the phone can't turn into a command.
- The web page only listens on 127.0.0.1. It checks the Host header, needs a random token for every API call, only accepts JSON, sends a strict Content-Security-Policy, and puts text from the phone on the page as plain text. Each of those has a test.
- Device-administrator apps won't uninstall normally. The tool tells you that and how to switch their admin rights off first.

## How the code is laid out

```
            cli.py ─────────── server.py + web/
               │                      │
               └──────────┬───────────┘
                          ▼
   collector.py ──► rules.py ──► report.py ──► compare.py
        │                │            │
        │                │            └──► history.py
        ▼                └──► removal.py   (the only code that changes a phone)
   parsers.py
        │
        ▼
     adb.py:  AdbDevice | FixtureDevice | RecordingDevice
```

Everything above `adb.py` talks to the phone through two methods, `shell` and `uninstall`. A real phone, a folder of recorded output and a recorder are interchangeable, which is how I can test and demo the whole thing without plugging anything in.

```
src/phonecheck/
  adb.py        talking to a phone, plus replay/record and the argument allowlist
  parsers.py    turns adb output into data
  collector.py  decides what to ask the phone, builds a snapshot
  rules.py      the scoring rules and thresholds
  report.py     text, HTML and JSON output
  removal.py    the guarded uninstall
  history.py    the SQLite scan log
  compare.py    diffing two reports
  cli.py        the commands
  server.py     the local web server
  web/          the page itself (plain HTML/CSS/JS, no build step)
tools/          scripts that regenerate the demo phones and the screenshot
tests/
```

## Tests

```bash
pip install -e ".[dev]"
pytest
ruff check
mypy
```

There are about 340 tests. They cover the parsers (including garbage input), every rule, the trust and look-alike cases, removal refusals, the CLI, the history database, and every one of the web server's security checks over real HTTP. There are also some browser tests with Playwright that click through the page and make sure hostile text from a phone shows up as text instead of running. They skip themselves if Playwright isn't installed (`pip install -e ".[e2e]" && playwright install chromium`).

GitHub Actions runs everything on Linux, Windows and macOS with Python 3.10 through 3.13.

One test regenerates the demo phones and fails if the committed copies don't match, so the demo can't quietly drift from the code.

## Status and limitations

So far I've tested it against recorded and synthetic output. The parsers follow the usual `dumpsys` formats, but phone makers like to change things. If a phone prints something the parser doesn't get, `phonecheck capture --out DIR` saves the raw output so I can write a fix and a test for it. (Don't share captures from other people's phones, since they list every app.)

Other limits:

- Android only. iPhones don't allow this kind of access.
- USB debugging has to be on, which takes a minute to set up.
- It works on heuristics. A real security app can look like scareware (they often have overlay and accessibility access), and a well-hidden bad app might score low. That's why it explains every flag and never removes anything by itself.
- It isn't an antivirus and doesn't scan app code.
- It shows package names like `com.example.app` rather than the app's name or icon.

Things I'd like to add: app names and icons, more rules as I see new junk in the wild, a one-file installer for Windows and Mac, and a history page in the web interface.

## AI assistance

This project was built with AI assistance (Claude Code), directed and reviewed by the author. The reasoning behind the design is written down in [DECISIONS.md](DECISIONS.md).

## License

MIT
