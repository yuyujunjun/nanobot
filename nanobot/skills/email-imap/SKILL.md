---
name: email-imap
description: Read and manage email via IMAP using a Python CLI (supports multiple accounts). If the user asks for email without specifying an account, run across all configured accounts.
metadata: {"nanobot":{"emoji":"📬","os":["darwin","linux"],"requires":{"bins":["python3"]}}}
---

# IMAP Email Reader (Python)

This skill reuses the command model from openclaw `mvarrieur/imap-email` and implements it in Python.

## Agent behavior rule

- If the user says “email” but does not specify an account, treat it as **all configured accounts**.
- If the user specifies an account, pass `--account <name>`.
- For commands that operate on a single message (`fetch`, `mark-read`, `mark-unread`), prefer using the returned `id` value (`account:uid`).

## Account source

- Account configuration is external (workspace memory/config), not managed in this skill.
- This skill does not define, validate, or explain account credentials.
- The skill only calls script interfaces and consumes JSON results.

## Commands (agent-callable interfaces)

Script path: `{baseDir}/scripts/imap.py`

### check

```bash
python3 "{baseDir}/scripts/imap.py" check --limit 10 --recent 2h
python3 "{baseDir}/scripts/imap.py" check --account work --limit 10
```

- Default query is `UNSEEN`
- If `--account` is omitted, this runs on all accounts
- Returns `account`, `id`, `uid`, `from`, `subject`, `date`, `snippet`, `flags`

### fetch

```bash
python3 "{baseDir}/scripts/imap.py" fetch work:12345
python3 "{baseDir}/scripts/imap.py" fetch 12345 --account work
```

- Fetches full email by UID
- Returns full content: `text`, `html`, `attachments`, `flags`, etc.

### search

```bash
python3 "{baseDir}/scripts/imap.py" search --unseen --from sender@example.com --subject "invoice" --recent 7d --limit 20
python3 "{baseDir}/scripts/imap.py" search --account personal --unseen --limit 20
```

Options:
- `--unseen` / `--seen`
- `--from <email>`
- `--subject <text>`
- `--recent <30m|2h|7d>`
- `--since <YYYY-MM-DD>`
- `--before <YYYY-MM-DD>`
- `--limit <n>`
- `--mailbox <name>`
- `--account <name>` (omit to search all accounts)

### mark-read / mark-unread

```bash
python3 "{baseDir}/scripts/imap.py" mark-read work:12345 personal:67890
python3 "{baseDir}/scripts/imap.py" mark-unread 12345 --account work
```

### list-mailboxes

```bash
python3 "{baseDir}/scripts/imap.py" list-mailboxes
python3 "{baseDir}/scripts/imap.py" list-mailboxes --account work
```

### list-accounts

```bash
python3 "{baseDir}/scripts/imap.py" list-accounts
```

## Current scope

This is the framework version:
- IMAP connect/read/search/mark/list is available
- JSON output is stable for agent automation

Next step: define higher-level automation interfaces (importance reminder, junk correction, thread grouping policies).
