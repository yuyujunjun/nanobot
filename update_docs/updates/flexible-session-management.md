# Flexible Session Management

## 🎯 What is a Session?

An **isolated conversation workspace** that persists:

| Data                      | Details                                         |
| ------------------------- | ----------------------------------------------- |
| **Message History** | Conversation with agent (compressed for tokens) |
| **Model Config**    | Which LLM to use (Claude, GPT-4, Llama, etc.)   |
| **Permissions**     | Commands agent is allowed to execute            |
| **Metadata**        | Created, updated, message count                 |

**Why use multiple sessions?** Task-based isolation — one per project, one for research, one for coding. Each keeps its own context, model, and permissions. Switch anytime with `/session list` (you'll see all session IDs and pick one).

---

## 🌐 Cross-Channel Persistence

Start on **Telegram** → switch to **TUI** → continue on **Discord** — full context preserved.

Each channel has one default session, can create more with `/new`.

---

## 📋 Command Cheat Sheet

| Command           | Effect                              |
| ----------------- | ----------------------------------- |
| `/new`          | Create new session (generates UUID) |
| `/session list` | Pick a session by ID                |
| `/session info` | Show current session stats          |
| `/reset`        | Clear all messages (keep config)    |
| `/model list`   | Switch model for this session       |

---

## 💾 Storage

Sessions saved to `~/.nanobot/sessions/` in **JSONL format** (one file per session UUID):

```
~/.nanobot/sessions/
├── a1b2c3d4.jsonl
├── e5f6g7h8.jsonl
└── session_table.json  (maps channel:chat_id → session UUID)
```

Survives app restart — all context persists.

---

## 🔗 Session + Permissions

Permissions can be **persistent** (all commands in session) or **one-time** (single command). Session reset clears messages but preserves granted permissions.

use `/help` for more information.
