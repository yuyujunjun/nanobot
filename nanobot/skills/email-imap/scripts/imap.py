#!/usr/bin/env python3
import argparse
import email
import imaplib
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from datetime import datetime, timedelta
from email.header import decode_header
from email.message import Message
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any


CONFIG_FILENAME = "email-imap-accounts.json"
OUTLOOK_DEFAULT_SCOPE = "offline_access https://outlook.office.com/IMAP.AccessAsUser.All"


def parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def decode_mime_header(value: str | None) -> str | None:
    if value is None:
        return None
    parts: list[str] = []
    for raw, charset in decode_header(value):
        if isinstance(raw, bytes):
            parts.append(raw.decode(charset or "utf-8", errors="replace"))
        else:
            parts.append(raw)
    return "".join(parts)


def decode_imap_bytes(data: bytes | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def to_jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return decode_imap_bytes(value)
    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {k: to_jsonable(v) for k, v in value.items()}
    return value


def normalize_account(raw: dict[str, Any], idx: int) -> dict[str, Any]:
    auth_method = str(raw.get("imap_auth_method") or "password").strip().lower()
    name = str(raw.get("name") or raw.get("imap_user") or f"account-{idx}")
    return {
        "name": name,
        "imap_host": raw.get("imap_host") or "127.0.0.1",
        "imap_port": int(raw.get("imap_port") or 993),
        "imap_user": raw.get("imap_user"),
        "imap_pass": raw.get("imap_pass"),
        "imap_auth_method": auth_method,
        "imap_oauth2_access_token": raw.get("imap_oauth2_access_token"),
        "imap_tls": parse_bool(str(raw.get("imap_tls")) if raw.get("imap_tls") is not None else None, True),
        "imap_reject_unauthorized": parse_bool(
            str(raw.get("imap_reject_unauthorized")) if raw.get("imap_reject_unauthorized") is not None else None,
            True,
        ),
        "imap_mailbox": raw.get("imap_mailbox") or "INBOX",
    }


def config_candidates() -> list[Path]:
    paths: list[Path] = []
    from_env = os.getenv("NANOBOT_EMAIL_IMAP_CONFIG")
    if from_env:
        paths.append(Path(from_env).expanduser())

    cwd_candidate = Path.cwd() / ".nanobot" / "memory" / CONFIG_FILENAME
    paths.append(cwd_candidate)

    script_file = Path(__file__).resolve()
    repo_candidate = script_file.parents[4] / ".nanobot" / "memory" / CONFIG_FILENAME
    paths.append(repo_candidate)
    return paths


def resolve_config_path() -> Path:
    existing = next((p for p in config_candidates() if p.exists()), None)
    if existing:
        return existing
    return config_candidates()[1]


def load_config_payload() -> tuple[Path, dict[str, Any]]:
    cfg_path = resolve_config_path()
    if cfg_path.exists():
        payload = json.loads(cfg_path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            return cfg_path, payload
    return cfg_path, {"accounts": []}


def save_config_payload(cfg_path: Path, payload: dict[str, Any]) -> None:
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def http_post_form_json(url: str, form: dict[str, str]) -> dict[str, Any]:
    encoded = urllib.parse.urlencode(form).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return json.loads(body)
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"error": "http_error", "error_description": body}
        if isinstance(parsed, dict) and parsed.get("error"):
            return parsed
        raise RuntimeError(f"OAuth HTTP {err.code}: {parsed}")


def iso_after_seconds(seconds: int) -> str:
    target = datetime.utcnow() if seconds <= 0 else (datetime.utcnow() + timedelta(seconds=seconds))
    return target.replace(microsecond=0).isoformat() + "Z"


def cmd_auth_outlook(
    account_name: str,
    client_id: str,
    tenant: str,
    scope: str,
    open_browser: bool,
) -> dict[str, Any]:
    if not client_id:
        raise RuntimeError("--client-id is required")

    device_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode"
    token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"

    device = http_post_form_json(device_url, {"client_id": client_id, "scope": scope})
    device_code = device.get("device_code")
    if not device_code:
        raise RuntimeError(f"Device code response invalid: {device}")

    message = device.get("message")
    verify_uri = str(device.get("verification_uri") or "")
    verify_uri_complete = str(device.get("verification_uri_complete") or "")
    opened = False
    if open_browser:
        target = verify_uri_complete or verify_uri
        if target:
            try:
                opened = webbrowser.open(target, new=2)
            except Exception:
                opened = False

    if message:
        print(message)
    else:
        user_code = device.get("user_code")
        print(f"Open: {verify_uri}")
        print(f"Code: {user_code}")

    if open_browser:
        if opened:
            print("Opened browser for Microsoft sign-in.")
        else:
            print("Could not open browser automatically. Please open the URL shown above manually.")

    interval = int(device.get("interval") or 5)
    expires_in = int(device.get("expires_in") or 900)
    deadline = time.time() + expires_in

    token: dict[str, Any] | None = None
    while time.time() < deadline:
        time.sleep(interval)
        current = http_post_form_json(
            token_url,
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "device_code": str(device_code),
            },
        )

        if "access_token" in current:
            token = current
            break

        err = str(current.get("error") or "")
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval += 5
            continue
        raise RuntimeError(f"OAuth token error: {current}")

    if not token:
        raise RuntimeError("Timed out waiting for Outlook authorization")

    cfg_path, payload = load_config_payload()
    accounts = payload.get("accounts")
    if not isinstance(accounts, list):
        accounts = []
        payload["accounts"] = accounts

    idx = next((i for i, row in enumerate(accounts) if isinstance(row, dict) and row.get("name") == account_name), None)
    if idx is None:
        raise RuntimeError(f"Account '{account_name}' not found in {cfg_path}")

    account = accounts[idx]
    account["imap_auth_method"] = "oauth2"
    account["imap_oauth2_access_token"] = token.get("access_token")
    account["imap_oauth2_refresh_token"] = token.get("refresh_token")
    account["imap_oauth2_token_type"] = token.get("token_type")
    account["imap_oauth2_expires_in"] = token.get("expires_in")
    account["imap_oauth2_expires_at"] = iso_after_seconds(int(token.get("expires_in") or 0))
    account["oauth_client_id"] = client_id
    account["oauth_tenant"] = tenant
    account["oauth_scope"] = scope

    save_config_payload(cfg_path, payload)

    return {
        "success": True,
        "account": account_name,
        "config": str(cfg_path),
        "token_type": token.get("token_type"),
        "expires_in": token.get("expires_in"),
        "expires_at": account["imap_oauth2_expires_at"],
        "scope": token.get("scope"),
        "message": "Outlook OAuth token stored. You can now run check --account <name>.",
    }


def load_accounts_from_config() -> list[dict[str, Any]]:
    cfg_path = next((p for p in config_candidates() if p.exists()), None)
    if not cfg_path:
        return []

    payload = json.loads(cfg_path.read_text(encoding="utf-8"))
    rows = payload.get("accounts") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return []

    return [normalize_account(row, idx + 1) for idx, row in enumerate(rows) if isinstance(row, dict)]


def load_accounts() -> list[dict[str, Any]]:
    accounts = load_accounts_from_config()
    if accounts:
        return accounts

    env_account = normalize_account(
        {
            "name": os.getenv("IMAP_ACCOUNT_NAME") or "default",
            "imap_host": os.getenv("IMAP_HOST", "127.0.0.1"),
            "imap_port": os.getenv("IMAP_PORT", "993"),
            "imap_user": os.getenv("IMAP_USER"),
            "imap_pass": os.getenv("IMAP_PASS"),
            "imap_auth_method": os.getenv("IMAP_AUTH_METHOD", "password"),
            "imap_oauth2_access_token": os.getenv("IMAP_OAUTH2_ACCESS_TOKEN"),
            "imap_tls": os.getenv("IMAP_TLS"),
            "imap_reject_unauthorized": os.getenv("IMAP_REJECT_UNAUTHORIZED"),
            "imap_mailbox": os.getenv("IMAP_MAILBOX", "INBOX"),
        },
        1,
    )
    return [env_account]


def find_account(accounts: list[dict[str, Any]], account_key: str) -> dict[str, Any]:
    for account in accounts:
        if account["name"] == account_key or account.get("imap_user") == account_key:
            return account
    raise RuntimeError(f"Unknown account: {account_key}")


def split_account_uid(value: str) -> tuple[str | None, str]:
    if ":" not in value:
        return None, value
    left, right = value.split(":", 1)
    return left, right


class ImapClient:
    def __init__(self, account: dict[str, Any]) -> None:
        self.name = str(account["name"])
        self.host = str(account["imap_host"])
        self.port = int(account["imap_port"])
        self.user = account["imap_user"]
        self.password = account["imap_pass"]
        self.auth_method = str(account.get("imap_auth_method") or "password").lower()
        self.oauth2_access_token = account.get("imap_oauth2_access_token")
        self.use_ssl = bool(account["imap_tls"])
        self.reject_unauthorized = bool(account["imap_reject_unauthorized"])
        self.default_mailbox = str(account["imap_mailbox"])
        self.conn: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None

    def connect(self) -> None:
        if not self.user:
            raise RuntimeError(f"Missing IMAP user for account '{self.name}'")

        if self.use_ssl:
            context = ssl.create_default_context()
            if not self.reject_unauthorized:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            self.conn = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=context)
        else:
            self.conn = imaplib.IMAP4(self.host, self.port)

        if self.auth_method in {"oauth2", "xoauth2", "modern", "modern-auth", "modern_auth"}:
            if not self.oauth2_access_token:
                raise RuntimeError(
                    f"Missing imap_oauth2_access_token for account '{self.name}' (OAuth2 auth)"
                )
            auth_string = f"user={self.user}\x01auth=Bearer {self.oauth2_access_token}\x01\x01"
            self.conn.authenticate("XOAUTH2", lambda _: auth_string.encode("utf-8"))
        else:
            if not self.password:
                raise RuntimeError(f"Missing IMAP password for account '{self.name}'")
            self.conn.login(self.user, self.password)

    def close(self) -> None:
        if not self.conn:
            return
        try:
            self.conn.logout()
        except Exception:
            pass
        finally:
            self.conn = None

    def select_mailbox(self, mailbox: str | None) -> None:
        if not self.conn:
            raise RuntimeError("Not connected")
        target = mailbox or self.default_mailbox
        status, _ = self.conn.select(f'"{target}"', readonly=False)
        if status != "OK":
            raise RuntimeError(f"Failed to open mailbox: {target}")


UID_FETCH_PATTERN = re.compile(rb"UID\s+(\d+)", re.IGNORECASE)
FLAG_FETCH_PATTERN = re.compile(rb"FLAGS\s*\(([^)]*)\)", re.IGNORECASE)


def parse_relative_time(value: str) -> datetime:
    match = re.fullmatch(r"(\d+)([mhd])", value.strip().lower())
    if not match:
        raise ValueError("Invalid --recent format. Use: 30m, 2h, 7d")

    amount = int(match.group(1))
    unit = match.group(2)
    now = datetime.now()
    if unit == "m":
        return now - timedelta(minutes=amount)
    if unit == "h":
        return now - timedelta(hours=amount)
    return now - timedelta(days=amount)


def imap_date(dt: datetime) -> str:
    return dt.strftime("%d-%b-%Y")


def extract_uid_and_flags(meta: bytes) -> tuple[str | None, list[str]]:
    uid_match = UID_FETCH_PATTERN.search(meta)
    flag_match = FLAG_FETCH_PATTERN.search(meta)
    uid = uid_match.group(1).decode("utf-8") if uid_match else None
    flags: list[str] = []
    if flag_match:
        raw = flag_match.group(1).decode("utf-8", errors="replace").strip()
        if raw:
            flags = raw.split()
    return uid, flags


def get_message_by_uid(conn: imaplib.IMAP4 | imaplib.IMAP4_SSL, uid: str) -> tuple[bytes, bytes]:
    status, data = conn.uid("fetch", uid, "(RFC822 FLAGS UID)")
    if status != "OK" or not data or data[0] is None:
        raise RuntimeError(f"Message UID {uid} not found")

    first = data[0]
    if not isinstance(first, tuple) or len(first) < 2:
        raise RuntimeError(f"Unexpected fetch response for UID {uid}")

    meta = first[0]
    body = first[1]
    if not isinstance(meta, bytes) or not isinstance(body, bytes):
        raise RuntimeError(f"Invalid message payload for UID {uid}")
    return meta, body


def extract_text_and_html(msg: Message) -> tuple[str | None, str | None, list[dict[str, Any]]]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict[str, Any]] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = (part.get("Content-Disposition") or "").lower()
            content_type = part.get_content_type()
            payload = part.get_payload(decode=True)
            charset = part.get_content_charset() or "utf-8"

            if "attachment" in content_disposition:
                filename = decode_mime_header(part.get_filename())
                attachments.append(
                    {
                        "filename": filename,
                        "contentType": content_type,
                        "size": len(payload or b""),
                    }
                )
                continue

            if payload is None:
                continue

            text = payload.decode(charset, errors="replace")
            if content_type == "text/plain":
                text_parts.append(text)
            elif content_type == "text/html":
                html_parts.append(text)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace")
            if msg.get_content_type() == "text/html":
                html_parts.append(text)
            else:
                text_parts.append(text)

    text_out = "\n".join(text_parts).strip() if text_parts else None
    html_out = "\n".join(html_parts).strip() if html_parts else None
    return text_out, html_out, attachments


def message_summary(uid: str, flags: list[str], body: bytes, with_snippet: bool = False) -> dict[str, Any]:
    msg = email.message_from_bytes(body)
    text, html, _ = extract_text_and_html(msg)
    snippet_src = text or html or ""
    snippet = re.sub(r"\s+", " ", snippet_src).strip()[:200] if with_snippet else None

    date_raw = decode_mime_header(msg.get("Date"))
    date_parsed = None
    if date_raw:
        try:
            date_parsed = parsedate_to_datetime(date_raw)
        except Exception:
            date_parsed = date_raw

    result = {
        "uid": uid,
        "from": decode_mime_header(msg.get("From")) or "Unknown",
        "subject": decode_mime_header(msg.get("Subject")) or "(no subject)",
        "date": date_parsed,
        "flags": flags,
    }
    if with_snippet:
        result["snippet"] = snippet
    return result


def decorate_with_account(account: str, result: dict[str, Any]) -> dict[str, Any]:
    copy = dict(result)
    uid = str(copy.get("uid", ""))
    copy["account"] = account
    copy["id"] = f"{account}:{uid}" if uid else None
    return copy


def cmd_check(client: ImapClient, mailbox: str | None, limit: int, recent: str | None) -> list[dict[str, Any]]:
    if not client.conn:
        raise RuntimeError("Not connected")

    client.select_mailbox(mailbox)
    criteria: list[Any] = ["UNSEEN"]
    if recent:
        criteria.extend(["SINCE", imap_date(parse_relative_time(recent))])

    status, data = client.conn.search(None, *criteria)
    if status != "OK":
        raise RuntimeError("Failed to search messages")

    uids = [decode_imap_bytes(v) for v in (data[0].split() if data and data[0] else [])]
    uids = list(reversed(uids))[:limit]

    out: list[dict[str, Any]] = []
    for uid in uids:
        meta, body = get_message_by_uid(client.conn, uid)
        parsed_uid, flags = extract_uid_and_flags(meta)
        item = message_summary(parsed_uid or uid, flags, body, with_snippet=True)
        out.append(decorate_with_account(client.name, item))
    return out


def cmd_fetch(client: ImapClient, uid: str, mailbox: str | None) -> dict[str, Any]:
    if not client.conn:
        raise RuntimeError("Not connected")

    client.select_mailbox(mailbox)
    meta, body = get_message_by_uid(client.conn, uid)
    parsed_uid, flags = extract_uid_and_flags(meta)
    msg = email.message_from_bytes(body)
    text, html, attachments = extract_text_and_html(msg)

    date_raw = decode_mime_header(msg.get("Date"))
    date_parsed = None
    if date_raw:
        try:
            date_parsed = parsedate_to_datetime(date_raw)
        except Exception:
            date_parsed = date_raw

    item = {
        "uid": parsed_uid or uid,
        "from": decode_mime_header(msg.get("From")),
        "to": decode_mime_header(msg.get("To")),
        "subject": decode_mime_header(msg.get("Subject")),
        "date": date_parsed,
        "text": text,
        "html": html,
        "attachments": attachments,
        "flags": flags,
    }
    return decorate_with_account(client.name, item)


def cmd_search(
    client: ImapClient,
    mailbox: str | None,
    unseen: bool,
    seen: bool,
    from_filter: str | None,
    subject_filter: str | None,
    recent: str | None,
    since: str | None,
    before: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    if not client.conn:
        raise RuntimeError("Not connected")

    client.select_mailbox(mailbox)
    criteria: list[Any] = []

    if unseen:
        criteria.append("UNSEEN")
    if seen:
        criteria.append("SEEN")
    if from_filter:
        criteria.extend(["FROM", from_filter])
    if subject_filter:
        criteria.extend(["SUBJECT", subject_filter])

    if recent:
        criteria.extend(["SINCE", imap_date(parse_relative_time(recent))])
    else:
        if since:
            parsed = datetime.strptime(since, "%Y-%m-%d")
            criteria.extend(["SINCE", imap_date(parsed)])
        if before:
            parsed = datetime.strptime(before, "%Y-%m-%d")
            criteria.extend(["BEFORE", imap_date(parsed)])

    if not criteria:
        criteria = ["ALL"]

    status, data = client.conn.search(None, *criteria)
    if status != "OK":
        raise RuntimeError("Failed to search messages")

    uids = [decode_imap_bytes(v) for v in (data[0].split() if data and data[0] else [])]
    uids = list(reversed(uids))[:limit]

    out: list[dict[str, Any]] = []
    for uid in uids:
        meta, body = get_message_by_uid(client.conn, uid)
        parsed_uid, flags = extract_uid_and_flags(meta)
        item = message_summary(parsed_uid or uid, flags, body, with_snippet=False)
        out.append(decorate_with_account(client.name, item))
    return out


def cmd_mark(client: ImapClient, mailbox: str | None, uids: list[str], unread: bool) -> dict[str, Any]:
    if not client.conn:
        raise RuntimeError("Not connected")

    if not uids:
        raise RuntimeError("UID(s) required")

    client.select_mailbox(mailbox)
    flag_action = "-FLAGS" if unread else "+FLAGS"
    for uid in uids:
        status, _ = client.conn.uid("store", uid, flag_action, "(\\Seen)")
        if status != "OK":
            raise RuntimeError(f"Failed to update UID {uid}")

    return {
        "success": True,
        "account": client.name,
        "uids": uids,
        "action": "marked as unread" if unread else "marked as read",
    }


def parse_mailbox_line(raw_line: bytes) -> dict[str, Any]:
    text = decode_imap_bytes(raw_line)
    match = re.match(r"^\((?P<attrs>[^)]*)\)\s+\"(?P<delim>.*)\"\s+(?P<name>.+)$", text)
    if not match:
        return {"raw": text}

    attrs = match.group("attrs").split()
    delim = match.group("delim")
    name = match.group("name").strip()
    if name.startswith('"') and name.endswith('"'):
        name = name[1:-1]

    return {
        "name": name,
        "delimiter": delim,
        "attributes": attrs,
    }


def cmd_list_mailboxes(client: ImapClient) -> list[dict[str, Any]]:
    if not client.conn:
        raise RuntimeError("Not connected")

    status, data = client.conn.list()
    if status != "OK":
        raise RuntimeError("Failed to list mailboxes")

    result: list[dict[str, Any]] = []
    for line in data or []:
        if line is None:
            continue
        if isinstance(line, tuple):
            line = line[-1]
        if isinstance(line, bytes):
            item = parse_mailbox_line(line)
            item["account"] = client.name
            result.append(item)
    return result


def run_for_accounts(
    accounts: list[dict[str, Any]],
    account_name: str | None,
    worker,
) -> Any:
    if account_name and account_name != "all":
        targets = [find_account(accounts, account_name)]
    else:
        targets = accounts

    if not targets:
        raise RuntimeError("No IMAP accounts configured")

    all_results: list[Any] = []
    for account in targets:
        client = ImapClient(account)
        try:
            client.connect()
            current = worker(client)
            if isinstance(current, list):
                all_results.extend(current)
            else:
                all_results.append(current)
        finally:
            client.close()

    return all_results


def choose_account_for_uid(accounts: list[dict[str, Any]], account_name: str | None, uid_or_id: str) -> tuple[dict[str, Any], str]:
    prefixed_account, uid = split_account_uid(uid_or_id)
    key = account_name or prefixed_account
    if key:
        return find_account(accounts, key), uid

    if len(accounts) == 1:
        return accounts[0], uid

    raise RuntimeError("Multiple accounts configured. Use --account or account-prefixed id (account:uid)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="IMAP Email CLI (Python)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="Check unread emails")
    p_check.add_argument("--account", default=None, help="Account name/email. Omit to run on all accounts")
    p_check.add_argument("--mailbox", default=None)
    p_check.add_argument("--limit", type=int, default=10)
    p_check.add_argument("--recent", default=None)

    p_fetch = sub.add_parser("fetch", help="Fetch full email by UID")
    p_fetch.add_argument("uid", help="UID or account:uid from prior results")
    p_fetch.add_argument("--account", default=None)
    p_fetch.add_argument("--mailbox", default=None)

    p_search = sub.add_parser("search", help="Search emails")
    p_search.add_argument("--account", default=None, help="Account name/email. Omit to run on all accounts")
    p_search.add_argument("--unseen", action="store_true")
    p_search.add_argument("--seen", action="store_true")
    p_search.add_argument("--from", dest="from_filter", default=None)
    p_search.add_argument("--subject", dest="subject_filter", default=None)
    p_search.add_argument("--recent", default=None)
    p_search.add_argument("--since", default=None)
    p_search.add_argument("--before", default=None)
    p_search.add_argument("--limit", type=int, default=20)
    p_search.add_argument("--mailbox", default=None)

    p_mark_read = sub.add_parser("mark-read", help="Mark message(s) as read")
    p_mark_read.add_argument("uids", nargs="+")
    p_mark_read.add_argument("--account", default=None)
    p_mark_read.add_argument("--mailbox", default=None)

    p_mark_unread = sub.add_parser("mark-unread", help="Mark message(s) as unread")
    p_mark_unread.add_argument("uids", nargs="+")
    p_mark_unread.add_argument("--account", default=None)
    p_mark_unread.add_argument("--mailbox", default=None)

    p_list = sub.add_parser("list-mailboxes", help="List mailboxes")
    p_list.add_argument("--account", default=None, help="Account name/email. Omit to run on all accounts")

    sub.add_parser("list-accounts", help="List configured accounts")

    p_auth_outlook = sub.add_parser("auth-outlook", help="Run Outlook OAuth device-code login and store token")
    p_auth_outlook.add_argument("--account", default="outlook", help="Account name in config (default: outlook)")
    p_auth_outlook.add_argument("--client-id", required=True, help="Azure app client id")
    p_auth_outlook.add_argument("--tenant", default="common", help="Tenant id/name (default: common)")
    p_auth_outlook.add_argument("--scope", default=OUTLOOK_DEFAULT_SCOPE)
    p_auth_outlook.add_argument(
        "--no-open-browser",
        action="store_true",
        help="Do not attempt to open browser automatically",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    accounts = load_accounts()
    try:
        if args.command == "check":
            result = run_for_accounts(
                accounts,
                args.account,
                lambda c: cmd_check(c, args.mailbox, args.limit, args.recent),
            )
        elif args.command == "fetch":
            account, uid = choose_account_for_uid(accounts, args.account, args.uid)
            client = ImapClient(account)
            try:
                client.connect()
                result = cmd_fetch(client, uid, args.mailbox)
            finally:
                client.close()
        elif args.command == "search":
            result = run_for_accounts(
                accounts,
                args.account,
                lambda c: cmd_search(
                    c,
                    args.mailbox,
                    args.unseen,
                    args.seen,
                    args.from_filter,
                    args.subject_filter,
                    args.recent,
                    args.since,
                    args.before,
                    args.limit,
                ),
            )
        elif args.command == "mark-read":
            grouped: dict[str, list[str]] = {}
            for token in args.uids:
                account, uid = choose_account_for_uid(accounts, args.account, token)
                grouped.setdefault(account["name"], []).append(uid)

            outputs: list[dict[str, Any]] = []
            for key, uid_list in grouped.items():
                account = find_account(accounts, key)
                client = ImapClient(account)
                try:
                    client.connect()
                    outputs.append(cmd_mark(client, args.mailbox, uid_list, unread=False))
                finally:
                    client.close()
            result = outputs
        elif args.command == "mark-unread":
            grouped = {}
            for token in args.uids:
                account, uid = choose_account_for_uid(accounts, args.account, token)
                grouped.setdefault(account["name"], []).append(uid)

            outputs = []
            for key, uid_list in grouped.items():
                account = find_account(accounts, key)
                client = ImapClient(account)
                try:
                    client.connect()
                    outputs.append(cmd_mark(client, args.mailbox, uid_list, unread=True))
                finally:
                    client.close()
            result = outputs
        elif args.command == "list-mailboxes":
            result = run_for_accounts(accounts, args.account, lambda c: cmd_list_mailboxes(c))
        elif args.command == "list-accounts":
            result = [
                {
                    "name": account["name"],
                    "imap_user": account.get("imap_user"),
                    "imap_host": account.get("imap_host"),
                    "imap_port": account.get("imap_port"),
                    "imap_auth_method": account.get("imap_auth_method"),
                    "imap_mailbox": account.get("imap_mailbox"),
                }
                for account in accounts
            ]
        elif args.command == "auth-outlook":
            result = cmd_auth_outlook(
                args.account,
                args.client_id,
                args.tenant,
                args.scope,
                open_browser=not args.no_open_browser,
            )
        else:
            raise RuntimeError(f"Unknown command: {args.command}")

        print(json.dumps(to_jsonable(result), ensure_ascii=False, indent=2))
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
