"""Shell execution tool."""

import asyncio
import os
import re
from pathlib import Path
from typing import Any

from nanobot.agent.tools.base import Tool
from nanobot.agent.tools.permissions import PermissionGate

import bashlex
import ast

class SecurityAnalyzer:
    """Analyze commands for required permissions."""
    
    def __init__(self):
        # 定义敏感操作对应的权限标签和描述
        self.permission_info = {
            'net': {
                'commands': ['curl', 'wget', 'nc', 'netcat', 'telnet', 'ssh', 'scp', 'ftp'],
                'description': 'Network access (downloading files, making HTTP requests)',
                'risk_level': 'medium'
            },
            'disk_write': {
                'commands': ['rm', 'dd', 'mkfs', 'fdisk', 'parted', 'del', 'rmdir'],
                'patterns': [
                    r'\brm\s+-[rf]{1,2}\b',  # rm -r, rm -rf, rm -fr
                    r'\bdel\s+/[fq]\b',       # del /f, del /q
                    r'\brmdir\s+/s\b',        # rmdir /s
                    r'>\s*/dev/sd',           # write to disk device
                ],
                'description': 'Disk write operations (file deletion, disk formatting)',
                'risk_level': 'high'
            },
            'sys_admin': {
                'commands': ['shutdown', 'reboot', 'poweroff', 'halt', 'mount', 'umount', 'chown', 'chmod', 'diskpart'],
                'description': 'System administration (power control, mount operations)',
                'risk_level': 'critical'
            },
            'proc_exec': {
                'commands': ['sh', 'bash', 'zsh', 'python', 'perl', 'ruby', 'node'],
                'description': 'Process execution (running scripts or subshells)',
                'risk_level': 'medium'
            },
            'file_write': {
                'commands': ['tee', 'sed', 'awk', 'mv', 'cp'],
                'patterns': [r'>>', r'(?<!-)>', r'\|\s*tee'],  # Redirections (avoid -> arrow)
                'description': 'File modifications (creating, moving, or modifying files)',
                'risk_level': 'low'
            },
            'sudo': {
                'commands': ['sudo', 'su', 'doas'],
                'description': 'Elevated privileges (running commands as superuser)',
                'risk_level': 'critical'
            },
            'dangerous': {
                'patterns': [
                    r':\(\)\s*\{.*\};\s*:',  # fork bomb
                ],
                'description': 'Dangerous operations (fork bombs, malicious patterns)',
                'risk_level': 'critical'
            }
        }

    def analyze_shell(self, command: str) -> dict[str, Any]:
        """分析 shell 命令需要的权限。
        
        Returns:
            dict with:
                - permissions: set of permission names
                - details: dict mapping permission -> reason
                - risk_level: str (low/medium/high/critical)
        """
        needed_permissions = set()
        details = {}
        
        # 首先检查所有模式（包括危险模式）
        for perm, info in self.permission_info.items():
            if 'patterns' in info:
                for pattern in info['patterns']:
                    if re.search(pattern, command, re.IGNORECASE):
                        needed_permissions.add(perm)
                        if perm not in details:
                            details[perm] = f"Pattern matched: {info['description']}"
        
        try:
            parts = bashlex.parse(command)
            for part in parts:
                # 递归查找命令节点
                for node in self._find_commands(part):
                    cmd_name = node.word
                    for perm, info in self.permission_info.items():
                        if 'commands' in info and cmd_name in info['commands']:
                            # 特殊判断：避免误判
                            if cmd_name == 'format' and '=' in command:
                                continue
                            needed_permissions.add(perm)
                            if perm not in details:
                                details[perm] = f"Command '{cmd_name}' requires: {info['description']}"
        except Exception as e:
            # 解析失败，尝试简单的字符串匹配
            for perm, info in self.permission_info.items():
                if 'commands' in info:
                    for cmd in info['commands']:
                        if re.search(rf'\b{re.escape(cmd)}\b', command, re.IGNORECASE):
                            needed_permissions.add(perm)
                            if perm not in details:
                                details[perm] = f"Command '{cmd}' detected: {info['description']}"
        
        # 计算最高风险等级
        risk_levels = ['none','low', 'medium', 'high', 'critical']
        max_risk = 'none'
        for perm in needed_permissions:
            perm_risk = self.permission_info.get(perm, {}).get('risk_level', 'low')
            if risk_levels.index(perm_risk) > risk_levels.index(max_risk):
                max_risk = perm_risk
        
        return {
            'permissions': needed_permissions,
            'details': details,
            'risk_level': max_risk
        }

    def _find_commands(self, node):
        """递归查找 bashlex AST 中的命令节点。"""
        if node.kind == 'command':
            if hasattr(node, 'parts') and node.parts:
                yield node.parts[0]
        if hasattr(node, 'parts'):
            for p in node.parts:
                if hasattr(p, 'kind'):
                    yield from self._find_commands(p)

    def analyze_python(self, code: str) -> dict[str, Any]:
        """分析 Python 代码需要的权限。"""
        needed_permissions = set()
        details = {}
        
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                # 检查导入
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [n.name for n in node.names]
                    for name in names:
                        if any(net_mod in name for net_mod in ['urllib', 'requests', 'socket', 'http']):
                            needed_permissions.add('net')
                            details['net'] = f"Network module '{name}' imported"
                        if any(proc_mod in name for proc_mod in ['os', 'subprocess', 'multiprocessing']):
                            needed_permissions.add('proc_exec')
                            details['proc_exec'] = f"Process module '{name}' imported"
                
                # 检查函数调用
                if isinstance(node, ast.Call):
                    func_name = ""
                    if hasattr(node.func, 'id'):
                        func_name = node.func.id
                    elif hasattr(node.func, 'attr'):
                        func_name = node.func.attr
                    
                    if func_name in ['system', 'run', 'Popen', 'call', 'check_output']:
                        needed_permissions.add('proc_exec')
                        details['proc_exec'] = f"Process execution function '{func_name}' used"
                    
                    if func_name == 'open':
                        # 检查打开模式
                        for arg in node.args:
                            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                                if any(mode in arg.value for mode in ['w', 'a', 'x', '+']):
                                    needed_permissions.add('file_write')
                                    details['file_write'] = "File write operation detected"
        except Exception as e:
            # 语法错误或解析失败
            needed_permissions.add('unknown')
            details['unknown'] = f"Code analysis failed: {str(e)}"
        
        # 计算风险等级
        risk_level = 'low'
        if 'proc_exec' in needed_permissions:
            risk_level = 'medium'
        if 'net' in needed_permissions:
            risk_level = 'medium'
        
        return {
            'permissions': needed_permissions,
            'details': details,
            'risk_level': risk_level
        }
class ExecTool(Tool):
    """Tool to execute shell commands."""
    
    def __init__(
        self,
        timeout: int = 60,
        working_dir: str | None = None,
        restrict_to_workspace: bool = False,
        workspace_roots: list[str] | None = None,
    ):
        self.timeout = timeout
        self.working_dir = working_dir
        self.restrict_to_workspace = restrict_to_workspace
        self.workspace_roots = self._resolve_workspace_roots(
            configured_roots=workspace_roots,
            working_dir=working_dir,
        )
        self.security_analyzer = SecurityAnalyzer()
        self.permission_gate = PermissionGate()
    
    @property
    def name(self) -> str:
        return "exec"
    
    @property
    def description(self) -> str:
        return "Execute a shell command and return its output. Use with caution."
    
    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute"
                },
                "working_dir": {
                    "type": "string",
                    "description": "Optional working directory for the command"
                }
            },
            "required": ["command"]
        }
    
    async def execute(self, command: str, working_dir: str | None = None, session=None, **kwargs: Any) -> str:
        cwd = working_dir or self.working_dir or os.getcwd()
        
        # 1. 检查工作区路径限制（尽力而为的静态检查）
        if self.restrict_to_workspace:
            path_error = self._check_workspace_paths(command, cwd)
            if path_error:
                # 如果是 Warning，转换为需要权限
                if path_error.startswith("Warning:"):
                    permission_request = self.permission_gate.check_or_request(
                        session=session,
                        subject=command,
                        required_permissions={"path_outside_workspace"},
                        details={
                            "path_outside_workspace": (
                                path_error.replace("Warning:", "").strip()
                            )
                        },
                        risk_level="medium",
                        default_grant_mode="one-time",
                    )
                    if permission_request:
                        return permission_request
                else:
                    # Error 直接阻止
                    return path_error
        
        # 2. 检查是否是危险的脚本执行
        is_dangerous, danger_reason = self._is_dangerous_command(command)
        if is_dangerous:
            dangerous_request = self.permission_gate.check_or_request(
                session=session,
                subject=command,
                required_permissions={"proc_exec"},
                details={
                    "proc_exec": (
                        f"{danger_reason}. This command executes code dynamically and may access "
                        "any file path at runtime."
                    )
                },
                risk_level="high",
            )
            if dangerous_request:
                return dangerous_request
        
        # 3. 权限分析（常规检查）
        analysis = self.security_analyzer.analyze_shell(command)
        if analysis['permissions']:
            permission_request = self.permission_gate.check_or_request(
                session=session,
                subject=command,
                required_permissions=analysis['permissions'],
                details=analysis['details'],
                risk_level=analysis['risk_level'],
            )
            if permission_request:
                return permission_request
        
        # 4. 执行命令
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                return f"Error: Command timed out after {self.timeout} seconds"
            
            output_parts = []
            
            if stdout:
                output_parts.append(stdout.decode("utf-8", errors="replace"))
            
            if stderr:
                stderr_text = stderr.decode("utf-8", errors="replace")
                if stderr_text.strip():
                    output_parts.append(f"STDERR:\n{stderr_text}")
            
            if process.returncode != 0:
                output_parts.append(f"\nExit code: {process.returncode}")
            
            result = "\n".join(output_parts) if output_parts else "(no output)"
            
            # Truncate very long output
            max_len = 10000
            if len(result) > max_len:
                result = result[:max_len] + f"\n... (truncated, {len(result) - max_len} more chars)"
            
            return result
            
        except Exception as e:
            return f"Error executing command: {str(e)}"

    def _is_dangerous_command(self, command: str) -> tuple[bool, str | None]:
        """检测命令是否可能包含危险的脚本执行。
        
        这是一个启发式检查，无法保证100%准确，但可以捕获常见的危险模式。
        真正的安全应该依赖容器化/沙箱环境。
        
        Returns:
            (is_dangerous, reason)
        """
        cmd = command.strip().lower()
        
        # 检测可能执行脚本代码的命令
        SCRIPT_EXECUTION_PATTERNS = [
            (r'\bpython\s+(-c|--command)\s+', 'Python inline code execution'),
            (r'\bperl\s+-e\s+', 'Perl inline code execution'),
            (r'\bruby\s+-e\s+', 'Ruby inline code execution'),
            (r'\bnode\s+-e\s+', 'Node.js inline code execution'),
            (r'\bsh\s+-c\s+', 'Shell command execution'),
            (r'\bbash\s+-c\s+', 'Bash command execution'),
            (r'\beval\s+', 'Eval command (dynamic code execution)'),
            (r'\bexec\s+', 'Exec command (command execution)'),
        ]
        
        for pattern, reason in SCRIPT_EXECUTION_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                return True, f"Detected {reason} - requires 'proc_exec' permission"
        
        return False, None
    
    def _resolve_workspace_roots(
        self,
        *,
        configured_roots: list[str] | None,
        working_dir: str | None,
    ) -> tuple[Path, ...]:
        """Resolve and deduplicate workspace roots used by static path checks."""
        candidates: list[Path] = []

        if configured_roots:
            for root in configured_roots:
                if root:
                    candidates.append(Path(root).expanduser())
        else:
            if working_dir:
                candidates.append(Path(working_dir).expanduser())
            candidates.append(Path.home() / ".nanobot" / "workspace")

        unique_roots: list[Path] = []
        seen: set[str] = set()
        for root in candidates:
            try:
                resolved = root.resolve()
            except (ValueError, OSError):
                continue

            key = str(resolved)
            if key in seen:
                continue
            seen.add(key)
            unique_roots.append(resolved)

        return tuple(unique_roots)

    def _is_in_workspace_roots(self, path: Path, cwd_path: Path) -> bool:
        """Check whether a path is inside any allowed workspace root."""
        roots = list(self.workspace_roots)
        if cwd_path not in roots:
            roots.append(cwd_path)

        for root in roots:
            if root == path or root in path.parents:
                return True
        return False

    def _check_workspace_paths(self, command: str, cwd: str) -> str | None:
        """检查命令是否访问工作区外的路径。
        - 无法检测脚本内部的路径访问（如 python script.py 内部行为）
        - 无法理解字符串的语义（搜索文本 vs 真实路径）
        """
        cmd = command.strip()
        
        # 黑名单：明显危险的路径模式（高置信度）
        DANGEROUS_PATTERNS = [
            (r'\.\./', 'Directory traversal (../)'),
            (r'\.\.[/\\]', 'Directory traversal'),
            (r'/etc/passwd', 'System password file'),
            (r'/etc/shadow', 'System shadow file'),
            (r'/root/\.ssh', 'Root SSH keys'),
            (r'/boot/', 'Boot directory'),
            (r'C:\\Windows\\System32', 'Windows system directory'),
        ]
        
        # 检查明显危险的模式
        for pattern, reason in DANGEROUS_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                return f"Error: {reason} detected - this is blocked for security"
        
        # 对于 restrict_to_workspace 模式，进行额外的路径检查
        # 但要注意这只是尽力而为的检查，不是完全可靠的
        if not self.restrict_to_workspace:
            return None  # 非限制模式，只检查危险模式
        
        cwd_path = Path(cwd).resolve()
        
        # 白名单：始终允许的系统路径
        ALLOWED_SYSTEM_PATHS = [
            '/dev/null', '/dev/zero', '/dev/random', '/dev/urandom',  # 常用设备
            '/tmp/', '/var/tmp/',  # 临时目录
            '/proc/', '/sys/',     # 进程和系统信息
        ]
        
        # 先移除 URL 和引号内的字符串，减少误判
        # 移除 URL
        cmd_clean = re.sub(r'\b(?:https?|ftp|file)://[^\s<>"\']+', '__URL__', cmd)
        # 移除双引号字符串（可能是搜索文本）
        cmd_clean = re.sub(r'"[^"]*"', '__STRING__', cmd_clean)
        # 移除单引号字符串
        cmd_clean = re.sub(r"'[^']*'", '__STRING__', cmd_clean)
        
        # 提取疑似路径（更保守的策略）
        potential_paths = []
        
        # Windows绝对路径
        potential_paths.extend(re.findall(r'[A-Za-z]:[\\\/][^\s\'"<>|]+', cmd_clean))
        
        # POSIX绝对路径（排除选项）
        posix_matches = re.findall(r'(?<![=:])(/[a-zA-Z0-9_\-./]+)', cmd_clean)
        
        for match in posix_matches:
            # 过滤误判
            if (match.startswith('//') or match == '__URL__' or match == '__STRING__' or
                any(match.startswith(allowed) for allowed in ALLOWED_SYSTEM_PATHS) or
                match in ['/', '/dev', '/tmp', '/proc', '/sys'] or
                len(match) < 3):  # 太短
                continue
            potential_paths.append(match)
        
        # 检查路径是否在工作区外
        for raw_path in potential_paths:
            clean_path = raw_path.rstrip('.,;:)')
            
            try:
                resolved = Path(clean_path).resolve()
                if not self._is_in_workspace_roots(resolved, cwd_path):
                    # 可能在工作区外，但给出警告而不是直接阻止
                    # 因为可能是误判（搜索文本等）
                    return f"Warning: Path '{clean_path}' may be outside workspace. If this is text/search content, request 'path_outside_workspace' permission to override."
            except (ValueError, OSError):
                continue
        
        return None

