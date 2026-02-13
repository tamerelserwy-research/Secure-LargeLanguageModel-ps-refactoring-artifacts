"""Algorithm 1: Risk-Based Input Profiling and Sanitization."""

import shlex
from typing import Tuple
from .security_patterns import SecurityPatterns

class RiskProfiler:
    """Implements Layer 1 of the defense architecture."""

    def __init__(self):
        self.patterns = SecurityPatterns()

    def profile_and_sanitize(self, command: str) -> Tuple[int, str]:
        """
        Perform risk profiling and sanitization.

        Args:
            command: Raw PowerShell command.

        Returns:
            Tuple of (risk_score, sanitized_command).
        """
        risk = self.patterns.calculate_risk(command)
        sanitized = command

        # Apply transformations for high-risk patterns
        if self.patterns.contains_critical(command):
            # Critical patterns trigger enhanced sanitization
            for pat in self.patterns.critical_patterns:
                if pat in command:
                    sanitized = self.patterns.apply_parameterized_transformation(sanitized, pat)
                    # Mark for manual review
                    self._log_critical(command)

        elif self.patterns.contains_high(command):
            # High-risk patterns get transformed
            for pat in self.patterns.high_patterns:
                if pat in command:
                    sanitized = self.patterns.apply_parameterized_transformation(sanitized, pat)

        # Always escape special characters to prevent injection
        sanitized = self._escape_special_characters(sanitized)

        return risk, sanitized

    def _escape_special_characters(self, cmd: str) -> str:
        """Escape characters that could break out of quotes."""
        # Use shlex.quote for shell safety, but we are in PowerShell context
        # We'll just ensure proper quoting for PowerShell arguments.
        # This is a simplified version.
        return cmd.replace('"', '`"').replace("'", "''")

    def _log_critical(self, cmd: str):
        """Log a critical pattern for manual review."""
        # In production, write to a secure log
        print(f"CRITICAL ALERT: Manual review required for command: {cmd[:100]}")
