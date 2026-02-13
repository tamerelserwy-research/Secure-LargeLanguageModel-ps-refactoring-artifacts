"""Definitions of security patterns and risk scoring (Equation 1)."""

import re
from typing import List, Tuple, Set
from . import config

class SecurityPatterns:
    """Encapsulates security pattern definitions and risk scoring."""

    def __init__(self):
        self.critical_patterns = config.CRITICAL_PATTERNS
        self.high_patterns = config.HIGH_RISK_PATTERNS
        self.medium_patterns = config.MEDIUM_RISK_PATTERNS
        self.low_patterns = config.LOW_RISK_PATTERNS

    def calculate_risk(self, command: str) -> int:
        """
        Compute risk score for a PowerShell command (Equation 1).

        Args:
            command: PowerShell command string.

        Returns:
            Integer risk score (0-10+).
        """
        score = 0
        for pat in self.critical_patterns:
            if re.search(pat, command, re.IGNORECASE):
                score += config.CRITICAL_WEIGHT
        for pat in self.high_patterns:
            if re.search(pat, command, re.IGNORECASE):
                score += config.HIGH_WEIGHT
        for pat in self.medium_patterns:
            if re.search(pat, command, re.IGNORECASE):
                score += config.MEDIUM_WEIGHT
        for pat in self.low_patterns:
            if re.search(pat, command, re.IGNORECASE):
                score += config.LOW_WEIGHT
        return min(score, 10)  # Cap at 10 for normalization

    def contains_critical(self, command: str) -> bool:
        """Check if command contains any critical pattern."""
        for pat in self.critical_patterns:
            if re.search(pat, command, re.IGNORECASE):
                return True
        return False

    def contains_high(self, command: str) -> bool:
        """Check if command contains any high-risk pattern."""
        for pat in self.high_patterns:
            if re.search(pat, command, re.IGNORECASE):
                return True
        return False

    def get_all_patterns(self) -> List[str]:
        """Return all patterns for matching."""
        return (self.critical_patterns + self.high_patterns +
                self.medium_patterns + self.low_patterns)

    def apply_parameterized_transformation(self, command: str, pattern: str) -> str:
        """
        Transform a dangerous pattern into a secure parameterized equivalent.
        (Placeholder – actual implementation would be more sophisticated.)
        """
        # Example: Replace "Invoke-Expression \"Get-Process -Id $pid\""
        # with direct cmdlet invocation.
        if "Invoke-Expression" in pattern or "IEX" in pattern:
            # Extract the inner command if possible (simplistic)
            match = re.search(r'["\'](.+?)["\']', command)
            if match:
                inner = match.group(1)
                return f"& {{ {inner} }}"  # Use script block invocation
        # For DownloadString, we might replace with Invoke-RestMethod + hash verification
        if "DownloadString" in pattern:
            # Simplified: replace with Invoke-RestMethod
            return re.sub(r'DownloadString', 'Invoke-RestMethod', command)
        return command
