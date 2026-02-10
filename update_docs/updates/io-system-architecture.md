# Architecture Improvements

| Component            | Before                                             | After                                   |
| -------------------- | -------------------------------------------------- | --------------------------------------- |
| **I/O System** | Input → Agent (mixed concerns)                    | Input → IOSystem → Agent (separation) |
| **Agent Loop** | 3× duplicated code (Agent, SubAgent, SystemAgent) | 1× unified `agent_utils.py`          |

---

## 🔄 I/O System: Before vs After

### Before

```
User Input (Channel) 
    ↓
  Agent
```

### After

```
User Input (Channel)
    ↓
IOSystem ✅ (filters & routes)
├─ /session, /model → handle here
├─ yes/no → grant/deny & signal
└─ other → forward to agent
    ↓
  Agent (clean business logic)
```

**Result:** Agent cleanly waits for permission via `wait_for_permission()` while IOSystem handles user responses independently.

---

## 🔁 Agent Loop: Code Unification

### Before: 3× Duplicate Implementations

```
Agent.run()          SubAgent.run()      SystemAgent.run()
  ├─ build_msg()       ├─ build_msg()       ├─ build_msg()
  ├─ call_llm() ◄──────┼─ call_llm() ◄──────┼─ call_llm()
  ├─ exec_tool() ◄─────┼─ exec_tool() ◄─────┼─ exec_tool()
  └─ loop logic ◄──────┴─ loop logic ◄──────┴─ loop logic
                          (100% duplicated)
```

### After: Unified Loop

```
shared: AgentLoopCommon [agent_utils.py]
├─ call_llm()
├─ exec_tool()
└─ loop logic

Agent.run()          SubAgent.run()      SystemAgent.run()
  ├─ build_msg()       ├─ build_msg()       ├─ build_msg()
  └─ call AgentLoopCommon() 
```

**Benefits:**

- Single source of truth: bug fixes apply instantly to all agent types
- ~200 lines of duplicated code eliminated
- Easy to add new agent types: just build different messages

---

## ✅ What This Enables

- **Permission system** with zero token waste (no re-planning on approval)
- **Session management** independent of agent logic
- **Model switching** per-session without agent involvement
- **Cross-channel consistency** (Telegram, Discord, TUI behave identically)
