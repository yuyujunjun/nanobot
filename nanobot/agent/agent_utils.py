
"""Common agent loop utilities."""

import json
import uuid
import asyncio
from typing import Any
from loguru import logger
from dataclasses import dataclass, field
import uuid
from nanobot.session.manager import Session,SessionManager
from nanobot.bus.events import OutboundMessage
from nanobot.bus.queue import MessageBus
def _is_permission_request(result: Any) -> bool:
    """检测工具执行结果是否是权限申请。"""
    return isinstance(result, dict) and result.get("type") == "permission_request"

@dataclass
class PermissionRequest:
    """Represents a pending permission request."""
    request_id: str
    channel: str
    chat_id: str
    command: str
    command_hash: str | None
    required_permissions: set[str]
    event: asyncio.Event
    default_grant_mode: str = "persistent"
    granted: bool = False
    granted_permissions: set[str] = field(default_factory=set)
    mode: str = "persistent"  # or "one-time"
    created_at: float = field(default_factory=lambda: __import__('time').time())
    
    @property
    def is_timed_out(self, timeout: int = 300) -> bool:
        """Check if request has timed out (5 minutes default)."""
        import time
        return time.time() - self.created_at > timeout

async def create_permission_request(
    session:Session,
    bus:MessageBus,
    channel: str,
    chat_id: str,
    command: str,
    command_hash: str | None,
    required_permissions: set[str],
    permission_details: str,
    default_grant_mode: str = "persistent",
) -> str:
    """Create a permission request and notify user.
    
    This method returns immediately without blocking.
    
    Returns:
        request_id that can be used with wait_for_permission()
    """
    # Generate unique request ID
    request_id = str(uuid.uuid4())[:8]
    
    # Create event for waiting
    event = asyncio.Event()
    
    # Create permission request
    request = PermissionRequest(
        request_id=request_id,
        channel=channel,
        chat_id=chat_id,
        command=command,
        command_hash=command_hash,
        required_permissions=required_permissions,
        default_grant_mode=default_grant_mode,
        event=event,
    )
    
    # Add to session's pending permissions
    session.pending_permissions[request_id] = request
    
    # Send permission request to user
    quick_mode = "one-time" if default_grant_mode == "one-time" else "persistent"
    message_content = permission_details + (
        f"\n\n**Quick response:** Reply `yes` to grant all permissions ({quick_mode}), or `no` to deny.\n"
        f"**Request ID:** `{request_id}`\n\n"
        f"**Advanced:** Use `/grant {request_id} <permission> [--mode one-time|persistent]` or `/deny {request_id}`"
    )
    
    try:
        await bus.publish_outbound(OutboundMessage(
            channel=channel,
            chat_id=chat_id,
            content=message_content
        ))
        logger.info(f"Permission request {request_id} sent to {channel}:{chat_id}: {required_permissions}")
    except Exception as e:
        logger.error(f"Failed to send permission request {request_id}: {e}", exc_info=True)
        raise
    
    return request_id
    


async def wait_for_permission(
    session:Session,
    request_id: str,
    timeout: int = 300,
) -> tuple[bool, set[str], str]:
    """Wait for a permission request to be resolved.
    
    This method blocks the caller (typically the tool execution)
    but does NOT block the agent loop.
    
    Note: Permissions are updated by IOSystem when processing user response.
          This function only waits for the result.
    
    Returns:
        (granted, permissions, mode)
    """
    request = session.pending_permissions.get(request_id)
    
    if not request:
        return False, set(), ""
    
    try:
        # Wait for user response (with timeout)
        await asyncio.wait_for(request.event.wait(), timeout=timeout)
        
        # IOSystem has already updated session.granted_permissions
        # Just return the result
        if request.granted:
            logger.info(f"Permission granted: {request.granted_permissions} (mode: {request.mode})")
            return True, request.granted_permissions, request.mode
        else:
            logger.info(f"Permission denied for request {request_id}")
            return False, set(), ""
    
    except asyncio.TimeoutError:
        logger.warning(f"Permission request {request_id} timed out")
        session.pending_permissions.pop(request_id, None)
        return False, set(), ""

async def AgentLoopCommon(
    provider,
    messages: list[dict[str, Any]],
    tools,
    session,
    context_builder=None,
    task_id: str | None = None,
    bus=None,
    origin_channel: str = "cli",
    origin_chat_id: str = "direct",
) -> tuple[str | None, list[dict[str, Any]]]:
    """
    Common agent loop logic shared by main agent and subagent.
    
    Args:
        provider: LLM provider instance
        messages: Initial messages list
        tools: ToolRegistry instance
        session: Session object for configuration
        context_builder: Optional ContextBuilder for main agent (if None, uses raw append)
        task_id: Optional task ID for subagent logging
        bus: Optional MessageBus for permission request handling (deprecated)
        origin_channel: Original channel for routing permission responses
        origin_chat_id: Original chat_id for routing permission responses
    
    Returns:
        Tuple of (final_content, final_messages)
    
    Note:
        权限请求由独立的 IOSystem 在 gateway 中处理，
        Agent 只处理已经过滤的消息。
        此函数不再处理权限请求。
    """
    # Get model and max_iterations from session
    model = session.config.model if session and session.config.model else provider.get_default_model()
    max_iterations = session.config.max_iterations if session and session.config.max_iterations else 50
    
    iteration = 0
    final_content = None
    tools_used = []
    while iteration < max_iterations:
        iteration += 1
        preview = messages[-1]["content"][:40] + "..." if len(messages[-1]["content"]) > 40 else messages[-1]["content"]
        logger.info(f"Processing message from {origin_channel}:{origin_chat_id}: {preview}")
        
        # Call LLM with session-specific model
        response = await provider.chat(
            messages=messages,
            tools=tools.get_definitions() if hasattr(tools, 'get_definitions') else tools,
            model=model
        )
        
        if response.has_tool_calls:
            tool_call_dicts = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": json.dumps(tc.arguments)
                    }
                }
                for tc in response.tool_calls
            ]
            
            # Use ContextBuilder if available, otherwise raw append
            if context_builder:
                messages = context_builder.add_assistant_message(
                    messages, response.content, tool_call_dicts
                )
            else:
                messages.append({
                    "role": "assistant",
                    "content": response.content or "",
                    "tool_calls": tool_call_dicts,
                })
            
            # Execute tools
            for tool_call in response.tool_calls:
                args_str = json.dumps(tool_call.arguments, ensure_ascii=False)
                tools_used.append(tool_call.name)
                # Log with appropriate level and format
                if task_id:
                    logger.debug(f"Subagent [{task_id}] executing: {tool_call.name} with arguments: {args_str}")
                else:
                    logger.info(f"Tool call: {tool_call.name}({args_str[:50]})")
                
                result = await tools.execute(tool_call.name, tool_call.arguments, session=session)
                
                # 检查是否是权限申请
                if _is_permission_request(result) and bus:
                    logger.info(f"Permission request detected")
                    
                    # 从字典中提取权限信息
                    required_permissions = set(result.get("required_permissions", []))
                    command = result.get("command", tool_call.name)
                    command_hash = result.get("command_hash")
                    default_grant_mode = result.get("default_grant_mode", "persistent")
                    
                    # 简化权限请求消息
                    risk_emoji = {'none': '✅', 'low': '🟢', 'medium': '🟡', 'high': '🟠', 'critical': '🔴'}
                    emoji = risk_emoji.get(result.get('risk_level', 'medium'), '⚠️')
                    
                    perms_list = ', '.join(f"`{p}`" for p in sorted(required_permissions))
                    
                    permission_details = (
                        f"{emoji} **Permission Required**\n\n"
                        f"Command: `{command}`\n"
                        f"Permissions: {perms_list}"
                    )
                    
                    logger.info(f"Using IOManager for permission request")
                    permission_request_id = await create_permission_request(
                        session = session,
                        bus =bus,
                        channel=origin_channel,
                        chat_id=origin_chat_id,
                        command=command,
                        command_hash=command_hash,
                        required_permissions=required_permissions,
                        permission_details=permission_details,
                        default_grant_mode=default_grant_mode,
                    )
                    
 
                    permission_granted, granted_perms, mode = await wait_for_permission(
                        session= session,
                        request_id=permission_request_id,
                        timeout=300,
                    )
                    
                    if permission_granted:
                        # 重新执行命令
                        logger.info(f"Re-executing {tool_call.name} with granted permissions {granted_perms}")
                        result = await tools.execute(tool_call.name, tool_call.arguments, session=session)
                    else:
                        result = f"⛔ Permission denied or request timed out. Command execution cancelled.\n\nOriginal request:\n{result}"
                    
                    
                logger.info(f"Tool call result: {result if isinstance(result, str) else str(result)[:200]}")
                # Add tool result
                if context_builder:
                    messages = context_builder.add_tool_result(
                        messages, tool_call.id, tool_call.name, result
                    )
                else:
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "name": tool_call.name,
                        "content": result,
                    })
        else:
            # logger.info(f"No tool call, the response is {origin_channel}:{origin_chat_id}: { response.content[:40] + '...' if response.content and len(response.content) > 40 else response.content}")
            # No tool calls, we're done
            final_content = response.content
            break
    if iteration >= max_iterations:
        final_content = final_content or f"Max iterations {max_iterations} reached without completion."
        logger.warning(f"Max iterations reached in agent loop for {origin_channel}:{origin_chat_id}")
    
    return final_content, messages, tools_used
async def _run_agent_loop(self, initial_messages: list[dict]) -> tuple[str | None, list[str]]:
        """
        Run the agent iteration loop.

        Args:
            initial_messages: Starting messages for the LLM conversation.

        Returns:
            Tuple of (final_content, list_of_tools_used).
        """
        messages = initial_messages
        iteration = 0
        final_content = None
        tools_used: list[str] = []

        while iteration < self.max_iterations:
            iteration += 1

            response = await self.provider.chat(
                messages=messages,
                tools=self.tools.get_definitions(),
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )

            if response.has_tool_calls:
                tool_call_dicts = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments)
                        }
                    }
                    for tc in response.tool_calls
                ]
                messages = self.context.add_assistant_message(
                    messages, response.content, tool_call_dicts,
                    reasoning_content=response.reasoning_content,
                )

                for tool_call in response.tool_calls:
                    tools_used.append(tool_call.name)
                    args_str = json.dumps(tool_call.arguments, ensure_ascii=False)
                    logger.info(f"Tool call: {tool_call.name}({args_str[:200]})")
                    result = await self.tools.execute(tool_call.name, tool_call.arguments)
                    messages = self.context.add_tool_result(
                        messages, tool_call.id, tool_call.name, result
                    )
                messages.append({"role": "user", "content": "Reflect on the results and decide next steps."})
            else:
                final_content = response.content
                break

        return final_content, tools_used