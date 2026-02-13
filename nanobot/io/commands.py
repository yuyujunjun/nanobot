"""Command handler for meta commands."""

import argparse
import sys
from io import StringIO
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from nanobot.session.manager import SessionManager
    from nanobot.channels.manager import ChannelManager


class CommandArgumentParser(argparse.ArgumentParser):
    """Custom ArgumentParser that doesn't exit on error."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, add_help=False, **kwargs)
        self.error_message = None
    
    def error(self, message):
        """Override error to capture message instead of exiting."""
        self.error_message = message
        raise argparse.ArgumentError(None, message)
    
    def format_help(self):
        """Format help message."""
        return super().format_help()


class CommandHandler:
    """
    Handles meta commands like /model, /session, /help, /status.
    
    Uses argparse for robust command parsing with subcommands support.
    CommandHandler does NOT directly operate on sessions.
    Instead, it interacts with SessionManager and ChannelManager.
    """
    
    def __init__(self, sessions: "SessionManager"):
        """
        Initialize the command handler.
        
        Args:
            sessions: The SessionManager instance to interact with
            channels: The ChannelManager instance (optional, for session switching)
        """
        self.sessions = sessions
        # self.channels = channels
        self._setup_parsers()
    
    def _setup_parsers(self):
        """Setup argparse parsers for all commands."""
        # Main parser
        self.parser = CommandArgumentParser(
            prog='/',
            description='nanobot commands'
        )
        subparsers = self.parser.add_subparsers(dest='command', help='Available commands')
        #
        
        # /model command
        model_parser = subparsers.add_parser(
            'model', 
            help='📦 Model Management',
            description='Show or switch AI model for this session'
        )
        model_parser.add_argument(
            'action', 
            nargs='?', 
            help='list - show available models, <name> - switch to model, empty - show current model'
        )
        model_parser.epilog = 'Example: /model anthropic/claude-opus-4-5'
        
        # /session command
        session_parser = subparsers.add_parser(
            'session', 
            help='💬 Session Management',
            description='Manage conversation sessions'
        )
        session_parser.add_argument(
            'action', 
            nargs='?', 
            default='info', 
            help='info - show current session, list - show all sessions, switch <id> - switch to session'
        )
        session_parser.epilog = 'Example: /session switch abc123'
        
        # /reset command
        reset_parser = subparsers.add_parser(
            'reset', 
            help='🔄 Reset Session',
            description='Clear all messages in current session (preserves configuration)'
        )
        
        # /new command
        subparsers.add_parser(
            'new', 
            help='🆕 Create New Session',
            description='Create a new conversation session'
        )
        
        # /status command
        subparsers.add_parser(
            'status', 
            help='📊 Bot Status',
            description='Show current bot and session status'
        )
        
        # Note: /grant and /deny are handled by IOManager, not by CommandHandler
        # /help command
        subparsers.add_parser(
            'help', 
            help='❓ Help',
            description='Show available commands and usage'
        )
    
    async def process(self, msg) -> str:
        """
        Process a command and return response.
        
        Args:
            command: Command name (without '/')
            args: Command arguments
        
        Returns:
            Response string to send back to user
        """
        # Build command line
        cmd_content = msg.content.strip()[1:]  # Remove leading '/'
        cmd_parts = cmd_content.split(maxsplit=1)
        command = cmd_parts[0]
        args = cmd_parts[1] if len(cmd_parts) > 1 else ""
        cmd_line = f"{command} {args}".strip()
        logger.info(f"Processing command: /{cmd_line}")
        user_key = f"{msg.channel}:{msg.chat_id}"
        try:
            # Parse command
            parsed_args = self.parser.parse_args(cmd_line.split())
            
            # Dispatch to handler
            if parsed_args.command == 'model':
                return await self.handle_model(parsed_args, user_key)
            elif parsed_args.command == 'session':
                return await self.handle_session(parsed_args, user_key)
            elif parsed_args.command == 'reset':
                return await self.handle_reset(parsed_args, user_key)
            elif parsed_args.command == 'new':
                return await self.handle_new(user_key)
            elif parsed_args.command == 'status':
                return self.handle_status(user_key)
            elif parsed_args.command == 'help':
                return self.handle_help()
            else:
                return self.handle_help()
                
        except (argparse.ArgumentError, SystemExit) as e:
            # Parse error - show help for that command
            if hasattr(self.parser, 'error_message') and self.parser.error_message:
                return f"❌ Error: {self.parser.error_message}\n\n{self.handle_help()}"
            return f"❌ Invalid command syntax\n\n{self.handle_help()}"
        except Exception as e:
            logger.error(f"Command processing error: {e}")
            return f"❌ Error processing command: {str(e)}\n\nType /help for usage"
    
    async def handle_model(self, args: argparse.Namespace, user_key: str) -> str:
        if args.action is None:
            # Show current model
            model = self.sessions.get_session_model(user_key)
            session = self.sessions.get_or_create(user_key)
            is_custom = session.config.model is not None
            
            if is_custom:
                return f"📦 Current model: {model} (session-specific)"
            else:
                return f"📦 Current model: {model} (using agent default)"
        elif args.action == 'list':
            # List available models
            models = self.sessions.models
            if not models:
                return "📋 No models available"
            if user_key.startswith("tui:"):
                options = []
                for model in models:
                    options.append({
                        "label": model,
                        "value": model
                    })
                return {
                    "type": "select",
                    "message": "📋 Select a model:",
                    "action": "model",
                    "options": options
                }

            model_list = "\n".join(f"  • {model}" for model in models)
            return f"📋 **Available Models:**\n{model_list}"
        else:
            # Switch model
            model = args.action
            self.sessions.set_session_model(user_key, model)
            return f"✅ Model switched to: {model}\n💡 This change only affects the current session"
    
    async def handle_session(self, args: argparse.Namespace, user_key: str) -> str:
        """Handle session commands: info, list, or switch to <id>."""
        action = args.action
        
        if action == 'list':
            return self._handle_session_list(user_key)
        elif action == 'info' or action is None:
            return self._handle_session_info(user_key)
        else:
            # Treat as session ID to switch to
            return self._handle_session_switch(user_key,action)
    
    def _handle_session_list(self,user_key) -> str | dict:
        """List all sessions with interactive selection."""
        sessions = self.sessions.list_sessions()
        
        if not sessions:
            return {"type": "message", "content": "📋 No sessions found"}
        
        # Build options for interactive menu
        options = []
        for session in sessions[:10]:  # Show top 10
            key = session.get('key', 'unknown')
            updated = session.get('updated_at', 'unknown')
            options.append({
                "label": f"{key} (updated: {updated})",
                "value": key  # Just the session key, TUIInput will handle the command
            })
        
        # Add "more" option if there are more than 10
        if len(sessions) > 10:
            options.append({
                "label": f"... and {len(sessions) - 10} more sessions",
                "value": "more"
            })
        if user_key.startswith("tui:"):
            return {
                "type": "select",
                "message": "📋 Select a session:",
                "action": "session",  # Direct session switch action
                "options": options
            }
        else:
            return options
    
    def _handle_session_info(self, user_key: str) -> str:
        """Show current session info."""
        info = self.sessions.get_session_info(user_key)
        
        model_display = info["model"]
        if info["is_custom_model"]:
            model_display += " (session-specific)"
        else:
            model_display += " (using agent default)"
        
        lines = [
            f"💬 **Session Info**",
            f"\nSession id: `{info['session_id']}`",
            f"\nKey: `{info['user_key']}`",
            f"\nMessages: {info['message_count']}",
            f"\nCreated: {info['created_at']}",
            f"\nUpdated: {info['updated_at']}",
            f"\n",
            f"\n**Configuration:**",
            f"\nModel: {model_display}",
        ]
        
        # Add permissions info
        permissions = info.get("permissions", {})
        persistent_perms = permissions.get("persistent", [])
        one_time_perms = permissions.get("one_time", {})
        
        if persistent_perms or one_time_perms:
            lines.append("")
            lines.append("**Granted Permissions:**")
            
            if persistent_perms:
                perms_str = ", ".join(f"`{p}`" for p in sorted(persistent_perms))
                lines.append(f"Persistent: {perms_str}")
            else:
                lines.append("Persistent: none")
            
            if one_time_perms:
                lines.append(f"One-time: {len(one_time_perms)} command(s)")
            else:
                lines.append("One-time: none")
        
        return "\n".join(lines)
    
    def _handle_session_switch(self, user_key: str, session_id: str) -> str:
        """Switch to another session."""
        # Note: In current architecture, session switching is handled by channel/client
        # This is more of an informational command
        results = self.sessions.switch_session(user_key, session_id)
        if results is True:
            return (
                f"ℹ️ **Session Switching**\n\n"
                f"User Key: `{user_key}`\n"
                f"Switch to session: `{session_id}`\n\n"
            )
        else:
            return f"❌ Session `{session_id}` not found. Use `/session list` to see available sessions."
    async def handle_new(self, user_key: str) -> str:
        """
        Handle /new command - create a new session.
        
        Returns:
            Response message
        """
        # Create new session with memory consolidation
        new_session = await self.sessions.create_new_session(user_key, consolidate_old=True)
        return (
            f"🆕 **New Session Created**\n\n"
            f"🐈 Memory from previous session has been consolidated.\n"
            f"New session key: `{new_session.key}`"
        )
    async def handle_reset(self, args: argparse.Namespace, user_key: str) -> str:
        """
        Handle /reset command - reset current session.
        
        Args:
            args: Parsed arguments
        
        Returns:
            Response message
        """
        # if not args.confirm:
        #     return (
        #         "⚠️ **Reset Session**\n\n"
        #         "This will clear all messages in the current session.\n"
        #         "Configuration (model) will be preserved.\n\n"
        #         "To confirm, use: `/reset --confirm`"
        #     )
        
        # Clear session messages
        session = self.sessions.get_or_create(user_key)
        session.clear()
        self.sessions.save(session)
        
        return "✅ Session reset! All messages cleared. Configuration preserved."
    
    def handle_help(self) -> str:
        """
        Handle /help command - show available commands.
        Dynamically generates help text from argparse definitions.
        
        Returns:
            Help text with all available commands
        """
        lines = ["🤖 **Available Commands**", ""]
        
        # Get all subparsers
        subparsers_actions = [
            action for action in self.parser._actions 
            if isinstance(action, argparse._SubParsersAction)
        ]
        
        if subparsers_actions:
            for subparsers_action in subparsers_actions:
                for choice, subparser in subparsers_action.choices.items():
                    # Get help text from the subparsers_action, not from subparser
                    help_text = subparsers_action.choices[choice].description or choice
                    
                    # Format command
                    lines.append(f"**/{choice}** - {help_text}")
                    
                    # Add argument details if any
                    for action in subparser._actions:
                        if action.dest not in ['help', 'command']:
                            if action.dest == 'action' and action.help:
                                lines.append(f"\n  • {action.help}")
                            elif action.option_strings:
                                opt_str = '/'.join(action.option_strings)
                                lines.append(f"\n  • `{opt_str}` - {action.help}")
                    
                    # Add example if available
                    if hasattr(subparser, 'epilog') and subparser.epilog:
                        lines.append(f"\n  • {subparser.epilog}")
                    
                    lines.append("")  # Empty line between commands
        
        # Add permission management commands (handled by IOManager)
        lines.extend([
            "**Permission Management:**",
            "🔐 `/grant <request_id> <permission> [--mode one-time|persistent]` - Grant command permissions",
            "   Example: `/grant abc123 net file_write --mode persistent`",
            "🔐 `/deny <request_id>` - Deny permission request",
            "   Example: `/deny abc123`",
            ""
        ])
        
        # Add tips
        lines.extend([
            "**Tips:**",
            "• Commands must start with `/`",
            "• Model changes only affect the current session",
            "• Each conversation can use a different model",
            "• Use `--help` after any command for detailed usage",
            "• Permissions can be granted one-time (per command) or persistent (entire session)"
        ])
        
        return "\n".join(lines)
    

