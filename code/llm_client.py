"""Interface to various LLMs (GPT, CodeLlama, DeepSeek, Qwen)."""

import os
from typing import List, Dict, Any, Optional
import openai
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

class LLMClient:
    """Unified client for multiple LLMs."""

    def __init__(self, model_name: str = "gpt-4o", api_key: Optional[str] = None):
        self.model_name = model_name
        self.is_local = model_name not in ["gpt-4o", "gpt-3.5-turbo"]
        if not self.is_local:
            openai.api_key = api_key or os.getenv("OPENAI_API_KEY")
        else:
            self._load_local_model()

    def _load_local_model(self):
        """Load a local HuggingFace model."""
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_name,
            torch_dtype=torch.float16,
            device_map="auto"
        )

    def generate(self, prompt: str, max_tokens: int = 1024, temperature: float = 0.2) -> str:
        """Generate text from prompt."""
        if not self.is_local:
            return self._generate_openai(prompt, max_tokens, temperature)
        else:
            return self._generate_local(prompt, max_tokens, temperature)

    def _generate_openai(self, prompt: str, max_tokens: int, temperature: float) -> str:
        response = openai.ChatCompletion.create(
            model=self.model_name,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=temperature
        )
        return response.choices[0].message.content

    def _generate_local(self, prompt: str, max_tokens: int, temperature: float) -> str:
        inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)
        outputs = self.model.generate(
            **inputs,
            max_new_tokens=max_tokens,
            temperature=temperature,
            do_sample=True,
            pad_token_id=self.tokenizer.eos_token_id
        )
        return self.tokenizer.decode(outputs[0], skip_special_tokens=True)[len(prompt):].strip()

    def generate_with_rag(self, prompt: str, retrieved_patterns: List[Dict[str, Any]]) -> str:
        """Inject retrieved patterns into prompt."""
        context = "\n\n".join([f"Secure pattern: {p['code']}" for p in retrieved_patterns])
        full_prompt = (
            f"Context - secure examples:\n{context}\n\n"
            f"Task: {prompt}\n\n"
            "Generate a secure PowerShell command based on the context. "
            "Avoid dangerous patterns like Invoke-Expression, DownloadString without hash verification, etc."
        )
        return self.generate(full_prompt)
