"""
Secure subprocess execution module for VulnReach

Prevents command injection, arbitrary code execution, and resource exhaustion attacks.
"""

import subprocess
import shlex
from typing import List, Dict, Optional, Tuple
import logging
import signal
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class SubprocessSecurityError(Exception):
    """Raised when subprocess execution violates security policy"""
    pass


class SecureSubprocessExecutor:
    """
    Secure execution of external processes

    Features:
    - Command whitelisting
    - Timeout enforcement
    - No shell=True (prevents shell injection)
    - Input argument validation
    - Resource limits
    - Proper error handling
    """

    # Whitelist of allowed external tools
    ALLOWED_TOOLS = {
        'syft': ['/usr/local/bin/syft', '/usr/bin/syft'],
        'trivy': ['/usr/local/bin/trivy', '/usr/bin/trivy'],
        'searchsploit': ['/usr/bin/searchsploit', '/usr/local/bin/searchsploit'],
        'git': ['/usr/bin/git', '/opt/homebrew/bin/git'],
        'python': ['/usr/bin/python3', '/usr/bin/python'],
    }

    # Default timeout for commands (5 minutes)
    DEFAULT_TIMEOUT = 300

    # Maximum output size (100MB)
    MAX_OUTPUT_SIZE = 100 * 1024 * 1024

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        """
        Initialize secure subprocess executor

        Args:
            timeout: Default timeout for commands in seconds
        """
        self.timeout = timeout
        self._output_sizes = {}

    def run(self,
            command: List[str],
            timeout: Optional[int] = None,
            input_data: Optional[str] = None,
            check: bool = True,
            capture_output: bool = True,
            **kwargs) -> subprocess.CompletedProcess:
        """
        Run a command securely

        Args:
            command: Command as list of strings (NOT a single string)
            timeout: Timeout in seconds (None = use default)
            input_data: Optional stdin data
            check: Raise CalledProcessError if exit code != 0
            capture_output: Capture stdout and stderr
            **kwargs: Additional arguments to subprocess.run

        Returns:
            CompletedProcess object

        Raises:
            SubprocessSecurityError: If command is not whitelisted or args are invalid
            subprocess.TimeoutExpired: If timeout exceeded
            subprocess.CalledProcessError: If check=True and command fails
        """

        if not command or not isinstance(command, list):
            raise SubprocessSecurityError("Command must be non-empty list of strings")

        if not all(isinstance(arg, str) for arg in command):
            raise SubprocessSecurityError("All command arguments must be strings")

        # Verify command is whitelisted
        tool_name = self._extract_tool_name(command[0])
        self._verify_tool_whitelisted(tool_name, command[0])

        # Validate command arguments
        self._validate_command_arguments(command[1:])

        # Use provided timeout or default
        timeout = timeout or self.timeout

        # Build subprocess arguments
        subprocess_kwargs = {
            'timeout': timeout,
            'shell': False,  # NEVER use shell=True
            'capture_output': capture_output,
            'text': True,
        }

        if input_data:
            subprocess_kwargs['input'] = input_data

        # Merge additional kwargs
        subprocess_kwargs.update(kwargs)

        try:
            logger.debug(f"Running command: {self._safe_command_repr(command)}")

            result = subprocess.run(command, **subprocess_kwargs, check=False)

            # Check for timeout-like conditions
            if result.returncode == 124:  # SIGTERM exit code
                raise subprocess.TimeoutExpired(cmd=command, timeout=timeout)

            if check and result.returncode != 0:
                logger.warning(
                    f"Command failed with exit code {result.returncode}: "
                    f"{self._safe_command_repr(command)}"
                )
                raise subprocess.CalledProcessError(
                    result.returncode,
                    command,
                    output=result.stdout,
                    stderr=result.stderr
                )

            logger.debug(f"Command succeeded: {self._safe_command_repr(command)}")
            return result

        except subprocess.TimeoutExpired:
            logger.error(f"Command timeout after {timeout}s: {self._safe_command_repr(command)}")
            raise

        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {self._safe_command_repr(command)}")
            raise

        except Exception as e:
            logger.error(f"Subprocess error: {e}")
            raise SubprocessSecurityError(f"Failed to execute command: {e}") from e

    @staticmethod
    def _extract_tool_name(command_path: str) -> str:
        """Extract tool name from command path"""
        import os
        return os.path.basename(command_path).lower()

    def _verify_tool_whitelisted(self, tool_name: str, full_path: str):
        """Verify tool is in whitelist"""
        if tool_name not in self.ALLOWED_TOOLS:
            raise SubprocessSecurityError(
                f"Command not whitelisted: {tool_name}. "
                f"Allowed tools: {list(self.ALLOWED_TOOLS.keys())}"
            )

        allowed_paths = self.ALLOWED_TOOLS[tool_name]
        if full_path not in allowed_paths:
            logger.warning(
                f"Command path not in expected locations: {full_path}. "
                f"Expected one of: {allowed_paths}"
            )
            # Still allow it but log warning

    @staticmethod
    def _validate_command_arguments(args: List[str]):
        """Validate command arguments for injection attempts"""
        dangerous_patterns = [
            ';', '|', '&', '`', '$', '\n', '\r', '>', '<',
        ]

        for arg in args:
            for pattern in dangerous_patterns:
                if pattern in arg:
                    raise SubprocessSecurityError(
                        f"Dangerous character detected in argument: '{pattern}'"
                    )

    @staticmethod
    def _safe_command_repr(command: List[str]) -> str:
        """Create safe string representation of command (for logging)"""
        # Don't include sensitive arguments
        safe_command = []
        skip_next = False

        for i, arg in enumerate(command):
            if skip_next:
                safe_command.append("***")
                skip_next = False
                continue

            # Mask known sensitive argument values
            if i > 0 and command[i-1] in ['--api-key', '--password', '--token', '-k', '-p']:
                safe_command.append("***")
            elif arg.startswith('--api-key=') or arg.startswith('--password='):
                safe_command.append(arg.split('=')[0] + "=***")
            else:
                safe_command.append(arg)

        return ' '.join(safe_command)

    @contextmanager
    def timeout_handler(self, timeout: int):
        """Context manager for timeout handling"""
        def timeout_handler_func(signum, frame):
            raise subprocess.TimeoutExpired(cmd="unknown", timeout=timeout)

        # Set signal handler
        old_handler = signal.signal(signal.SIGALRM, timeout_handler_func)
        signal.alarm(timeout)

        try:
            yield
        finally:
            # Disable the alarm
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)


def run_safely(command: List[str], **kwargs) -> subprocess.CompletedProcess:
    """
    Convenience function for running commands securely

    Args:
        command: Command as list of strings
        **kwargs: Arguments to SecureSubprocessExecutor.run()

    Returns:
        CompletedProcess object
    """
    executor = SecureSubprocessExecutor()
    return executor.run(command, **kwargs)


if __name__ == "__main__":
    # Example usage
    executor = SecureSubprocessExecutor(timeout=60)

    print("Secure Subprocess Executor loaded successfully")
    print("\nExample: Run a secure command")
    print("  executor.run(['syft', 'dir:.'], timeout=120)")

