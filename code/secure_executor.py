"""Algorithm 4: Parameterized Secure Execution Wrapper."""

import subprocess
import shlex
from typing import List, Dict, Any, Tuple
from pathlib import Path
import logging
from . import config

class SecureExecutor:
    """Executes PowerShell commands safely from Python."""

    def __init__(self, pwsh_path: str = None, sandbox_dir: Path = None):
        self.pwsh_path = pwsh_path or config.POWERSHELL_EXECUTABLE
        self.sandbox_dir = sandbox_dir or config.SANDBOX_DIR
        self.sandbox_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

    def execute(self, cmdlet: str, parameters: Dict[str, Any], context: str = "default") -> Tuple[int, str, str]:
        """
        Execute a PowerShell cmdlet with parameters.

        Args:
            cmdlet: PowerShell cmdlet name (e.g., 'Get-Process').
            parameters: Dictionary of parameter names to values.
            context: Identifier for logging.

        Returns:
            (exit_code, stdout, stderr)
        """
        # Sanitize each parameter
        sanitized_params = []
        for k, v in parameters.items():
            # Convert to string and escape
            if isinstance(v, str):
                v_escaped = shlex.quote(v)
            else:
                v_escaped = str(v)
            sanitized_params.append(f"-{k} {v_escaped}")

        # Build the PowerShell command
        ps_cmd = f"{cmdlet} " + " ".join(sanitized_params)
        # Add security flags
        full_cmd = [
            self.pwsh_path,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "RemoteSigned",
            "-Command", ps_cmd
        ]

        self.logger.info(f"Executing: {full_cmd} (context={context})")

        # Run with shell=False to prevent injection
        proc = subprocess.Popen(
            full_cmd,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = proc.communicate()
        exit_code = proc.returncode

        if exit_code != 0:
            self.logger.warning(f"Execution failed: {stderr}")

        return exit_code, stdout, stderr

    def execute_script(self, script_content: str, context: str = "sandbox") -> Tuple[int, str, str]:
        """
        Execute an arbitrary PowerShell script (use with caution).

        For sandboxed testing only.
        """
        script_path = self.sandbox_dir / f"temp_{context}.ps1"
        script_path.write_text(script_content)

        cmd = [
            self.pwsh_path,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "RemoteSigned",
            "-File", str(script_path)
        ]
        proc = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate()
        script_path.unlink(missing_ok=True)
        return proc.returncode, stdout, stderr
