"""Configuration settings for the framework."""

import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
RESULTS_DIR = BASE_DIR / "results"

# LLM settings
DEFAULT_LLM_MODEL = "gpt-4o"  # or "codellama-7b", "deepseek-coder-v2-lite"
LLM_TEMPERATURE = 0.2
LLM_MAX_TOKENS = 1024

# RAG settings
RAG_TOP_K = 5
RAG_ALPHA = 0.6   # weight for semantic similarity
RAG_BETA = 0.4    # weight for security (1/(1+risk))

# Security pattern definitions
CRITICAL_PATTERNS = ["Invoke-Expression", "IEX", "Invoke-Mimikatz"]
HIGH_RISK_PATTERNS = ["DownloadString", "ExecutionPolicy Bypass", "Bypass"]
MEDIUM_RISK_PATTERNS = ["WindowStyle Hidden", "EncodedCommand", "EncodedCommand", "-EncodedCommand"]
LOW_RISK_PATTERNS = ["Get-Process", "Get-Service", "Get-ChildItem", "Get-Content"]

# Risk weights
CRITICAL_WEIGHT = 3
HIGH_WEIGHT = 2
MEDIUM_WEIGHT = 1
LOW_WEIGHT = 0

# Execution settings
POWERSHELL_EXECUTABLE = "pwsh"  # or "powershell.exe" on Windows
SANDBOX_DIR = RESULTS_DIR / "sandbox"
