"""
独立的 I/O 处理系统

负责：
1. 独立消费 MessageBus 的 inbound 消息
2. 处理所有权限相关的逻辑
3. 将处理后的消息转发给 Agent
4. 不阻塞 Agent 的主处理流程
"""

import asyncio
from typing import Optional
from loguru import logger

from nanobot.bus.events import InboundMessage, OutboundMessage
from nanobot.bus.queue import MessageBus

from nanobot.io.commands import CommandHandler
from nanobot.session.manager import SessionManager,Session





class IOSystem:
    """
    独立的 I/O 系统层
    
    负责在 gateway 层独立处理所有 I/O 和权限逻辑，
    避免阻塞 Agent 的主处理流程。
    
    消息流：
    Channel → MessageBus.publish_inbound()
                ↓
            IOSystem (独立消费和处理)
                ├─ 系统命令 → IOManager 处理 → 直接回复用户
                ├─ 权限响应 → IOManager 处理 → 触发权限事件
                └─ 普通消息 → 转发给 Agent
                ↓
            Agent (仅处理业务逻辑)
    """
    
    def __init__(self, sessions:SessionManager,bus: MessageBus):
        """
        初始化 IOSystem
        
        Args:
            bus: MessageBus 实例
        """
        self.bus = bus
        self.sessions = sessions
        self.command_handler = CommandHandler(self.sessions)
        self._running = False
        
    async def start(self):
        """启动独立的 I/O 处理循环"""
        logger.info("🚀 IOSystem 启动...")
        self._running = True
        
        try:
            await self._message_loop()
        except asyncio.CancelledError:
            logger.info("IOSystem 被取消")
        except Exception as e:
            logger.error(f"IOSystem 错误: {e}", exc_info=True)
        finally:
            self._running = False
            logger.info("IOSystem 已停止")
    async def _handle_permission_response(
        self,
        msg: InboundMessage,
        session: Session,
        user_reply: str
    ) -> OutboundMessage:

        # Get the first (and typically only) pending request
        request_id, request = next(iter(session.pending_permissions.items()))
        
        if user_reply in ['yes', 'y']:
            # Grant all required permissions (persistent mode)
            # Update session.granted_permissions directly here
            session.granted_permissions['persistent'].update(request.required_permissions)
            
            # Mark request as granted
            request.granted = True
            request.granted_permissions = request.required_permissions
            request.mode = "persistent"
            
            # Trigger event to wake up wait_for_permission
            request.event.set()
            
            # Clean up pending request
            session.pending_permissions.pop(request_id, None)
            
            logger.info(f"Permission granted (yes) for request {request_id}: {request.required_permissions}")
            logger.info(f"Updated session.granted_permissions['persistent']: {session.granted_permissions['persistent']}")
            
            return OutboundMessage(
                channel=msg.channel,
                chat_id=msg.chat_id,
                content=f"✅ Permissions granted: {', '.join(request.required_permissions)} (persistent)"
            )
        else:  # no, n
            # Deny all permissions
            request.granted = False
            request.event.set()
            
            # Clean up pending request
            session.pending_permissions.pop(request_id, None)
            
            logger.info(f"Permission denied (no) for request {request_id}")
            
            return OutboundMessage(
                channel=msg.channel,
                chat_id=msg.chat_id,
                content=f"⛔ Permission request denied"
            )
    async def _message_loop(self):
        """独立的消息消费循环"""
        while self._running:
            try:
                msg = await self.bus.consume_inbound()
                await self._process_message(msg)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"IO system handling error: {e}", exc_info=True)
                if 'msg' in locals():
                    await self.bus.publish_outbound(OutboundMessage(
                        channel=msg.channel,
                        chat_id=msg.chat_id,
                        content=f"❌ IO system handling error: {str(e)}"
                    ))

    
    async def _process_message(self, msg: InboundMessage) -> None:
        """
        处理消息
        
        处理步骤：
        1. 检查是否是系统命令
        2. 检查是否是权限响应
        3. 其他消息转发给 Agent
        """
        user_key = f"{msg.channel}:{msg.chat_id}"
        session = self.sessions.get_or_create(user_key)
                
        # Handle slash commands
        
        # 1. Check if it's a system command
        if msg.content.strip().startswith('/'):
            logger.info(f"IOSystem: Processing system command: {msg.content[:50]} from {msg.channel}:{msg.chat_id}")
            content = await self.command_handler.process(msg)
            return await self.bus.publish_outbound(OutboundMessage(
                channel=msg.channel,
                chat_id=msg.chat_id,
                content=content
            ))
        
        # 2. Check if it's a permission response (yes/no)
        if session.pending_permissions:
            user_reply = msg.content.strip().lower()
            if user_reply in ['yes', 'y', 'no', 'n']:
                logger.info(f"IOSystem: Processing permission response '{user_reply}' for {len(session.pending_permissions)} pending requests")
                content = await self._handle_permission_response(msg, session, user_reply)
                return await self.bus.publish_outbound(OutboundMessage(
                    channel=msg.channel,
                    chat_id=msg.chat_id,
                    content=content.content
                ))
        
        # 3. Forward regular messages to Agent
        logger.debug(f"IOSystem: Forwarding message to Agent from {msg.channel}:{msg.chat_id}")
        await self.bus.publish_agent(msg)
