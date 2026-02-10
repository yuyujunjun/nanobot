"""TUI (Terminal User Interface) channel for interactive console input."""

import asyncio
import httpx

from loguru import logger

from nanobot.bus.events import OutboundMessage
from nanobot.bus.queue import MessageBus
from nanobot.channels.base import BaseChannel
from nanobot.config.schema import TUIAppConfig


class TUIChannel(BaseChannel):
    """
    TUI channel that handles HTTP API for remote input/output.
    
    Receives messages via HTTP API and routes them through the message bus.
    """
    
    name = "tui"
    
    def __init__(self, config: TUIAppConfig | None, bus: MessageBus):
        super().__init__(config, bus)
        self.port = config.port if config else 18790
        self._http_runner = None
        # Use asyncio.Queue to collect responses per session_id
        # Queues are persistent and never cleaned up
        self._response_queues = {}  # {session_id: asyncio.Queue}
        self._running = False
    
    async def start(self) -> None:
        """Start the TUI channel HTTP API server."""
        from aiohttp import web
        
        async def handle_send(request: web.Request) -> web.Response:
            """Handle message send (non-blocking, returns immediately)."""
            try:
                data = await request.json()
                message = data.get("message", "")
                session_id = data.get("session_id", "tui:interactive")
                
                if not message:
                    return web.json_response({"error": "No message provided"}, status=400)
                
                # Create queue if not exists
                if session_id not in self._response_queues:
                    self._response_queues[session_id] = asyncio.Queue()
                
                # Send message through the bus (non-blocking)
                await self._handle_message(
                    sender_id="tui",
                    chat_id=session_id,
                    content=message,
                )
                
                return web.json_response({"status": "sent"})
            
            except Exception as e:
                logger.error(f"Error handling send request: {e}")
                return web.json_response({"error": str(e)}, status=500)
        
        async def handle_receive(request: web.Request) -> web.Response:
            """Handle message receive (returns immediately if message available)."""
            try:
                session_id = request.query.get("session_id", "tui:interactive")
                timeout = float(request.query.get("timeout", "30.0"))
                
                # Create queue if not exists
                if session_id not in self._response_queues:
                    self._response_queues[session_id] = asyncio.Queue()
                
                response_queue = self._response_queues[session_id]
                
                # Get all immediately available messages without waiting
                messages = []
                
                # Try to get messages that are already in queue (non-blocking)
                while not response_queue.empty():
                    try:
                        msg = response_queue.get_nowait()
                        messages.append(msg)
                    except asyncio.QueueEmpty:
                        break
                
                # If we got messages, return immediately
                if messages:
                    return web.json_response({"messages": messages})
                
                # Otherwise, wait for at least one message (long polling)
                try:
                    first_msg = await asyncio.wait_for(response_queue.get(), timeout=timeout)
                    messages.append(first_msg)
                    
                    # Check if there are more messages available immediately
                    while not response_queue.empty():
                        try:
                            msg = response_queue.get_nowait()
                            messages.append(msg)
                        except asyncio.QueueEmpty:
                            break
                    
                    return web.json_response({"messages": messages})
                except asyncio.TimeoutError:
                    # No messages within timeout
                    return web.json_response({"messages": []})
            
            except Exception as e:
                logger.error(f"Error handling receive request: {e}")
                return web.json_response({"error": str(e)}, status=500)
        
        async def handle_chat(request: web.Request) -> web.Response:
            """Handle chat message requests (legacy blocking endpoint)."""
            try:
                data = await request.json()
                message = data.get("message", "")
                session_id = data.get("session_id", "tui:interactive")
                
                if not message:
                    return web.json_response({"error": "No message provided"}, status=400)
                
                # Create or reuse queue for this session (persistent)
                if session_id not in self._response_queues:
                    self._response_queues[session_id] = asyncio.Queue()
                response_queue = self._response_queues[session_id]
                
                # Send message through the bus
                await self._handle_message(
                    sender_id="tui",
                    chat_id=session_id,
                    content=message,
                )
                
                # Collect responses with timeout
                timeout = 300.0  # 5 minutes
                collection_window = 0.1  # 100ms window to collect multiple messages
                responses = []
                
                # Get first response (blocks until available)
                try:
                    first_msg = await asyncio.wait_for(response_queue.get(), timeout=timeout)
                    responses.append(first_msg)
                except asyncio.TimeoutError:
                    return web.json_response({"error": "Request timeout"}, status=500)
                
                # Try to collect additional messages within the collection window
                while True:
                    try:
                        next_msg = await asyncio.wait_for(
                            response_queue.get(),
                            timeout=collection_window
                        )
                        responses.append(next_msg)
                    except asyncio.TimeoutError:
                        # No more messages within the window
                        break
                
                # Combine responses
                if len(responses) == 1:
                    response_content = responses[0]
                else:
                    response_content = "\n\n".join(responses)
                
                return web.json_response({"response": response_content})
            
            except Exception as e:
                logger.error(f"Error handling chat request: {e}")
                return web.json_response({"error": str(e)}, status=500)
        
        async def handle_health(request: web.Request) -> web.Response:
            """Health check endpoint."""
            return web.json_response({"status": "ok"})
        
        app = web.Application()
        app.router.add_post("/send", handle_send)  # Non-blocking send
        app.router.add_get("/receive", handle_receive)  # Long polling receive
        app.router.add_post("/chat", handle_chat)  # Legacy blocking endpoint
        app.router.add_get("/health", handle_health)
        
        self._http_runner = web.AppRunner(app)
        await self._http_runner.setup()
        site = web.TCPSite(self._http_runner, "127.0.0.1", self.port)
        await site.start()
        
        logger.info(f"TUI HTTP API started on port {self.port}")
        self._running = True
        
        # Keep running
        try:
            while self._running:
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            pass
    
    async def stop(self) -> None:
        """Stop the TUI channel."""
        self._running = False
        if self._http_runner:
            await self._http_runner.cleanup()
    
    async def send(self, msg: OutboundMessage) -> None:
        """
        Send response to waiting HTTP request via queue.
        
        Messages are queued and will be collected until the collection window closes.
        """
        session_id = msg.chat_id
        if session_id in self._response_queues:
            # Queue the message (non-blocking)
            await self._response_queues[session_id].put(msg.content)
            # content_preview = str(msg.content)[:50]
            # logger.debug(f"Message queued for session {session_id}, {content_preview}")
        else:
            # Session not waiting
            logger.debug(f"No queue for session {session_id} (ignoring message)")

import asyncio
import httpx
import json
from typing import Any
from datetime import datetime
from textual.app import App, ComposeResult
from textual import events
from textual.containers import Container, Vertical
from textual.widgets import Header, Footer, RichLog, Input, Label, Static, ListView, ListItem
from textual.screen import ModalScreen
from textual.binding import Binding
from textual.message import Message
from textual.worker import Worker, WorkerState
from rich.markdown import Markdown

# --- Message for gateway responses ---
class GatewayResponse(Message):
    """Message to notify main thread of gateway response."""
    def __init__(self, data: Any) -> None:
        super().__init__()
        self.data = data

# --- 1. Interactive Selection Dialog (replaces questionary) ---
class SelectDialog(ModalScreen):
    """Modal dialog displayed when receiving type='select' JSON response"""
    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def __init__(self, message: str, options: list, action_type: str = None):
        super().__init__()
        self.message = message
        self.options = options
        self.action_type = action_type
        # Map safe button ids to raw option values to avoid invalid ids (e.g., session keys with ':').
        self._option_values = {}

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(self.message, id="dialog_title")
            items = []
            for idx, opt in enumerate(self.options):
                # Handle dict or str type options
                label = opt.get("label", opt.get("name", str(opt))) if isinstance(opt, dict) else str(opt)
                val = opt.get("value", opt) if isinstance(opt, dict) else opt
                item_id = f"opt_{idx}"
                self._option_values[item_id] = val
                items.append(ListItem(Label(label), id=item_id))
            yield ListView(*items, id="option_list")
            yield Label("Enter to select, Esc to cancel", id="dialog_footer")

    def on_mount(self) -> None:
        self.query_one(ListView).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        # Extract value
        raw_val = self._option_values.get(event.item.id, "")
        # Build command for session/model types, otherwise return raw value
        if self.action_type == "session":
            result = f"/session {raw_val}"
        elif self.action_type == "model":
            result = f"/model {raw_val}"
        else:
            result = raw_val
        self.dismiss(result)

# --- 2. Main Application ---
class NanobotTUI(App):
    CSS = """
    RichLog {
        height: 1fr;
        border: tall $primary;
        background: $surface;
        padding: 1 2;
    }
    Input {
        dock: bottom;
        width: 100%;
        border: double $accent;
    }
    #dialog {
        width: 60;
        height: auto;
        max-height: 80%;
        background: $surface;
        border: round $primary;
        padding: 1;
        align: center middle;
    }
    #dialog_title { text-align: left; text-style: bold; margin: 0 0 1 0; }
    #option_list { height: auto; max-height: 20; overflow-y: auto; }
    #dialog_footer { text-align: right; text-style: dim; }
    """

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=True),
        Binding("ctrl+l", "clear_log", "Clear", show=True),
    ]

    def __init__(self, gateway_url: str, session_id: str):
        super().__init__()
        self.gateway_url = gateway_url
        self.session_id = session_id
        self.history = []
        self.history_index = 0
        self._poll_worker = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield RichLog(id="chat_log", wrap=True, markup=True, auto_scroll=True)
        yield Input(placeholder="Enter command or message...", id="user_input")
        yield Footer()

    def on_mount(self) -> None:
        self.chat_log = self.query_one("#chat_log", RichLog)
        self.chat_log.write("🤖 [bold green]System ready, live sync enabled...[/bold green]")
        # Start background polling worker
        self._poll_worker = self.run_worker(self.poll_loop(), exclusive=False)

    def on_unmount(self) -> None:
        if self._poll_worker:
            self._poll_worker.cancel()

    # --- Arrow keys for command history ---
    def on_key(self, event: events.Key) -> None:
        input_widget = self.query_one("#user_input", Input)
        if self.focused is not input_widget:
            return
        if event.key == "up":
            if self.history:
                self.history_index = max(0, self.history_index - 1)
                input_widget.value = self.history[self.history_index]
                input_widget.cursor_position = len(input_widget.value)
        elif event.key == "down":
            if self.history:
                self.history_index = min(len(self.history), self.history_index + 1)
                input_widget.value = self.history[self.history_index] if self.history_index < len(self.history) else ""
                input_widget.cursor_position = len(input_widget.value)

    # --- Send message ---
    async def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text: return
        
        self.history.append(text)
        self.history_index = len(self.history)
        self.chat_log.write(f"👉 [bold blue]You:[/bold blue] {text}")
        event.input.clear()

        async with httpx.AsyncClient() as client:
            try:
                # Use /send for non-blocking dispatch, responses via long-poll
                await client.post(
                    f"{self.gateway_url}/send",
                    json={"message": text, "session_id": self.session_id},
                    timeout=5.0
                )
            except Exception as e:
                self.chat_log.write(f"[red]Send failed: {e}[/red]")



    # --- Background polling loop (worker ensures thread safety) ---
    async def poll_loop(self) -> None:
        """Background polling loop running in worker thread."""
        async with httpx.AsyncClient() as client:
            while True:
                try:
                    response = await client.get(
                        f"{self.gateway_url}/receive",
                        params={"session_id": self.session_id, "timeout": "5"},
                        timeout=10.0
                    )
                    if response.status_code == 200:
                        messages = response.json().get("messages", [])
                        # if messages:
                        #     self.chat_log.write(f"[dim]DEBUG: Received {len(messages)} message(s)[/dim]")
                        for m in messages:
                            # Post to main thread via message queue
                            self.post_message(GatewayResponse(m))
                except Exception as e:
                    # self.chat_log.write(f"[dim red]DEBUG: Poll error {e}[/dim red]")
                    await asyncio.sleep(0.5)
    
    def on_gateway_response(self, message: GatewayResponse) -> None:
        """Handle gateway response in main thread (thread-safe UI update)."""
        # self.chat_log.write("[dim]DEBUG: on_gateway_response invoked[/dim]")
        data = message.data
        
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except:
                self.chat_log.write(Markdown(data))
                return

        if isinstance(data, dict):
            msg_type = data.get("type", "message")
            # self.chat_log.write(f"[dim]DEBUG: Message type {msg_type}[/dim]")
            
            if msg_type == "select":
                def handle_selected(choice):
                    if choice:
                        input_w = self.query_one(Input)
                        input_w.value = str(choice)
                        input_w.focus()

                self.push_screen(
                    SelectDialog(data.get("message", "Please select:"), data.get("options", []), data.get("action")),
                    handle_selected
                )
            
            elif msg_type == "message":
                content = data.get("content") or data.get("message")
                if content: 
                    self.chat_log.write(Markdown(content))
        else:
            self.chat_log.write(str(data))

    def action_clear_log(self):
        self.query_one(RichLog).clear()


class TUIInput:
    """Maintain original interface, internally using mature Textual RichLog component."""
    
    def __init__(self, gateway_url: str = "http://localhost:18790"):
        self.gateway_url = gateway_url
        self._session_id = "tui:richlog:stable"

    async def start(self) -> None:
        app = NanobotTUI(gateway_url=self.gateway_url, session_id=self._session_id)
        await app.run_async()