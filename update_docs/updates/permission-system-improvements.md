# Permission System Improvements

## 🎯 What Changed

### 1. Smarter Permission Detection

- **Before**: Regex patterns → false positives/negatives
- **Now**: `bashlex` parser → accurate command analysis

### 2. Proactive Permission Requests

- **Before**: Agent retries blindly, wasting tokens on variations
- **Now**: Agent asks user explicitly, retries exact same command with **zero extra tokens**

---

## 📊 Before vs After

| Scenario          | Before                                       | After                               |
| ----------------- | -------------------------------------------- | ----------------------------------- |
| Permission denied | Agent tries many variations (wastes tokens) | Agent requests permission (instant) |
| User response     | Not aware of retries                         | Simple "yes/no" → command executes |
| Token cost        | High (re-planning)                           | Zero (context preserved)            |

---

## 🔧 Quick Reference

**Permission Modes:**

| Mode       | Scope               | Duration            |
| ---------- | ------------------- | ------------------- |
| Persistent | All future commands | Across all sessions |
| One-time   | Single command      | This execution only |

**Parser:** `bashlex` for shell command analysis
**UI:** Simple yes/no prompts across all channels (TUI, Telegram, Discord, etc.)
