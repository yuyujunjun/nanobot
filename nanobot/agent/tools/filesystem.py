"""File system tools: read, write, edit."""

from pathlib import Path
from typing import Any

from nanobot.agent.tools.base import Tool
from nanobot.agent.tools.permissions import PermissionGate


def _resolve_path(
    path: str,
    allowed_dir: Path | None = None,
    enforce_allowed_dir: bool = True,
) -> Path:
    """Resolve path and optionally enforce directory restriction."""
    resolved = Path(path).expanduser().resolve()
    if enforce_allowed_dir and allowed_dir and not str(resolved).startswith(str(allowed_dir.resolve())):
        raise PermissionError(f"Path {path} is outside allowed directory {allowed_dir}")
    return resolved


def _is_outside_allowed_dir(path: str, allowed_dir: Path | None) -> bool:
    if not allowed_dir:
        return False
    resolved = Path(path).expanduser().resolve()
    return not str(resolved).startswith(str(allowed_dir.resolve()))


def _should_request_permission(path: str, allowed_dir: Path | None) -> bool:
    if allowed_dir is None:
        return True
    return _is_outside_allowed_dir(path, allowed_dir)


class ReadFileTool(Tool):
    """Tool to read file contents."""
    
    def __init__(self, allowed_dir: Path | None = None):
        self._allowed_dir = allowed_dir
        self._permission_gate = PermissionGate()

    @property
    def name(self) -> str:
        return "read_file"
    
    @property
    def description(self) -> str:
        return "Read the contents of a file at the given path."
    
    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "The file path to read"
                }
            },
            "required": ["path"]
        }
    
    async def execute(self, path: str, session=None, **kwargs: Any) -> str:
        try:
            outside_allowed_dir = _is_outside_allowed_dir(path, self._allowed_dir)
            if _should_request_permission(path, self._allowed_dir):
                permission_request = self._permission_gate.check_or_request(
                    session=session,
                    subject=f"read_file:{path}",
                    required_permissions=(
                        {"file_read", "path_outside_allowed_dir"}
                        if outside_allowed_dir
                        else {"file_read"}
                    ),
                    details={
                        "file_read": "Read file content from filesystem",
                        "path_outside_allowed_dir": (
                            "Path is outside configured allowed_dir, requires explicit override"
                        ),
                    },
                    risk_level="low",
                    default_grant_mode="one-time" if outside_allowed_dir else "persistent",
                )
                if permission_request:
                    return permission_request

            file_path = _resolve_path(
                path,
                self._allowed_dir,
                enforce_allowed_dir=not outside_allowed_dir,
            )
            if not file_path.exists():
                return f"Error: File not found: {path}"
            if not file_path.is_file():
                return f"Error: Not a file: {path}"
            
            content = file_path.read_text(encoding="utf-8")
            return content
        except PermissionError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Error reading file: {str(e)}"


class WriteFileTool(Tool):
    """Tool to write content to a file."""
    
    def __init__(self, allowed_dir: Path | None = None):
        self._allowed_dir = allowed_dir
        self._permission_gate = PermissionGate()

    @property
    def name(self) -> str:
        return "write_file"
    
    @property
    def description(self) -> str:
        return "Write content to a file at the given path. Creates parent directories if needed."
    
    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "The file path to write to"
                },
                "content": {
                    "type": "string",
                    "description": "The content to write"
                }
            },
            "required": ["path", "content"]
        }
    
    async def execute(self, path: str, content: str, session=None, **kwargs: Any) -> str:
        try:
            outside_allowed_dir = _is_outside_allowed_dir(path, self._allowed_dir)
            if _should_request_permission(path, self._allowed_dir):
                permission_request = self._permission_gate.check_or_request(
                    session=session,
                    subject=f"write_file:{path}",
                    required_permissions=(
                        {"file_write", "path_outside_allowed_dir"}
                        if outside_allowed_dir
                        else {"file_write"}
                    ),
                    details={
                        "file_write": "Write file content to filesystem",
                        "path_outside_allowed_dir": (
                            "Path is outside configured allowed_dir, requires explicit override"
                        ),
                    },
                    risk_level="medium",
                    default_grant_mode="one-time" if outside_allowed_dir else "persistent",
                )
                if permission_request:
                    return permission_request

            file_path = _resolve_path(
                path,
                self._allowed_dir,
                enforce_allowed_dir=not outside_allowed_dir,
            )
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content, encoding="utf-8")
            return f"Successfully wrote {len(content)} bytes to {path}"
        except PermissionError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Error writing file: {str(e)}"


class EditFileTool(Tool):
    """Tool to edit a file by replacing text."""
    
    def __init__(self, allowed_dir: Path | None = None):
        self._allowed_dir = allowed_dir
        self._permission_gate = PermissionGate()

    @property
    def name(self) -> str:
        return "edit_file"
    
    @property
    def description(self) -> str:
        return "Edit a file by replacing old_text with new_text. The old_text must exist exactly in the file."
    
    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "The file path to edit"
                },
                "old_text": {
                    "type": "string",
                    "description": "The exact text to find and replace"
                },
                "new_text": {
                    "type": "string",
                    "description": "The text to replace with"
                }
            },
            "required": ["path", "old_text", "new_text"]
        }
    
    async def execute(self, path: str, old_text: str, new_text: str, session=None, **kwargs: Any) -> str:
        try:
            outside_allowed_dir = _is_outside_allowed_dir(path, self._allowed_dir)
            if _should_request_permission(path, self._allowed_dir):
                permission_request = self._permission_gate.check_or_request(
                    session=session,
                    subject=f"edit_file:{path}",
                    required_permissions=(
                        {"file_write", "path_outside_allowed_dir"}
                        if outside_allowed_dir
                        else {"file_write"}
                    ),
                    details={
                        "file_write": "Modify file content on filesystem",
                        "path_outside_allowed_dir": (
                            "Path is outside configured allowed_dir, requires explicit override"
                        ),
                    },
                    risk_level="medium",
                    default_grant_mode="one-time" if outside_allowed_dir else "persistent",
                )
                if permission_request:
                    return permission_request

            file_path = _resolve_path(
                path,
                self._allowed_dir,
                enforce_allowed_dir=not outside_allowed_dir,
            )
            if not file_path.exists():
                return f"Error: File not found: {path}"
            
            content = file_path.read_text(encoding="utf-8")
            
            if old_text not in content:
                return f"Error: old_text not found in file. Make sure it matches exactly."
            
            # Count occurrences
            count = content.count(old_text)
            if count > 1:
                return f"Warning: old_text appears {count} times. Please provide more context to make it unique."
            
            new_content = content.replace(old_text, new_text, 1)
            file_path.write_text(new_content, encoding="utf-8")
            
            return f"Successfully edited {path}"
        except PermissionError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Error editing file: {str(e)}"


class ListDirTool(Tool):
    """Tool to list directory contents."""
    
    def __init__(self, allowed_dir: Path | None = None):
        self._allowed_dir = allowed_dir
        self._permission_gate = PermissionGate()

    @property
    def name(self) -> str:
        return "list_dir"
    
    @property
    def description(self) -> str:
        return "List the contents of a directory."
    
    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "The directory path to list"
                }
            },
            "required": ["path"]
        }
    
    async def execute(self, path: str, session=None, **kwargs: Any) -> str:
        try:
            outside_allowed_dir = _is_outside_allowed_dir(path, self._allowed_dir)
            if _should_request_permission(path, self._allowed_dir):
                permission_request = self._permission_gate.check_or_request(
                    session=session,
                    subject=f"list_dir:{path}",
                    required_permissions=(
                        {"file_read", "path_outside_allowed_dir"}
                        if outside_allowed_dir
                        else {"file_read"}
                    ),
                    details={
                        "file_read": "List directory entries from filesystem",
                        "path_outside_allowed_dir": (
                            "Path is outside configured allowed_dir, requires explicit override"
                        ),
                    },
                    risk_level="low",
                    default_grant_mode="one-time" if outside_allowed_dir else "persistent",
                )
                if permission_request:
                    return permission_request

            dir_path = _resolve_path(
                path,
                self._allowed_dir,
                enforce_allowed_dir=not outside_allowed_dir,
            )
            if not dir_path.exists():
                return f"Error: Directory not found: {path}"
            if not dir_path.is_dir():
                return f"Error: Not a directory: {path}"
            
            items = []
            for item in sorted(dir_path.iterdir()):
                prefix = "📁 " if item.is_dir() else "📄 "
                items.append(f"{prefix}{item.name}")
            
            if not items:
                return f"Directory {path} is empty"
            
            return "\n".join(items)
        except PermissionError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Error listing directory: {str(e)}"
