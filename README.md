# Automated Security-Centric Refactoring of PowerShell Commands Using Large Language Models

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18636114.svg)](https://doi.org/10.5281/zenodo.18636114)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This repository contains the official implementation of the paper:

**"Automated Security-Centric Refactoring of PowerShell Commands Using Large Language Models: A Python-Based Framework for Cross-Language Automation"**  
*Tamer Bahgat Elserwy, Basma E. El-Demerdash*  

The framework leverages Large Language Models (LLMs) combined with Retrieval-Augmented Generation (RAG), static analysis, and secure execution wrappers to refactor PowerShell commands into safe, parameterized Python orchestration code while preserving functionality and mitigating vulnerabilities.

.
├── README.md
├── LICENSE
├── requirements.txt
├── paper/
│   └── main.tex                 # LaTeX source of the paper
├── code/
│   ├── __init__.py
│   ├── config.py                 # Configuration settings
│   ├── security_patterns.py       # Pattern definitions and risk scoring
│   ├── risk_profiler.py           # Algorithm 1: Input sanitization
│   ├── rag_retriever.py           # Algorithm 2: Security-weighted retrieval
│   ├── ast_validator.py           # Algorithm 3: AST-based validation
│   ├── secure_executor.py         # Algorithm 4: Safe execution wrapper
│   ├── prompt_defense.py          # Algorithm 5: Spotlighting injection defense
│   ├── compliance.py              # Algorithm 6: Multi-layer verification
│   ├── llm_client.py              # LLM interface (supports Qwen/CodeLlama/DeepSeek)
│   ├── metrics.py                 # Evaluation metrics (VIR, SCR, CodeBLEU)
│   ├── evaluate.py                # Main evaluation script
│   └── utils.py                   # Utility functions
├── data/
│   ├── dataset_sample.json        # Sample of 100 entries (full dataset on Zenodo)
│   ├── knowledge_base.json         # Secure patterns for RAG
│   └── mitre_mapping.csv           # MITRE ATT&CK category mappings
├── results/
│   └── (placeholders for generated outputs)
└── tests/
    └── test_pipeline.py           # Unit tests
