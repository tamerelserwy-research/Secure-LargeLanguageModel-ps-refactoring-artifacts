"""Algorithm 2: Security-Weighted Semantic Retrieval."""

import json
import numpy as np
from sentence_transformers import SentenceTransformer
import faiss
from typing import List, Dict, Any
from . import config
from .security_patterns import SecurityPatterns

class RAGRetriever:
    """Retrieves secure patterns using semantic similarity weighted by security risk."""

    def __init__(self, knowledge_base_path: str):
        """
        Args:
            knowledge_base_path: Path to JSON file containing secure patterns.
        """
        with open(knowledge_base_path, 'r') as f:
            self.kb = json.load(f)  # List of dicts with 'nl', 'code', 'risk'
        self.model = SentenceTransformer('microsoft/codebert-base')
        self.patterns = SecurityPatterns()
        self._build_index()

    def _build_index(self):
        """Build FAISS index over knowledge base embeddings."""
        texts = [item['code'] for item in self.kb]
        self.embeddings = self.model.encode(texts, convert_to_numpy=True)
        dim = self.embeddings.shape[1]
        self.index = faiss.IndexFlatIP(dim)  # Inner product = cosine if normalized
        faiss.normalize_L2(self.embeddings)
        self.index.add(self.embeddings)

    def retrieve(self, query: str, top_k: int = None) -> List[Dict[str, Any]]:
        """
        Retrieve top_k secure patterns.

        Args:
            query: Natural language query.
            top_k: Number of patterns to return (default from config).

        Returns:
            List of retrieved items with scores.
        """
        if top_k is None:
            top_k = config.RAG_TOP_K
        query_emb = self.model.encode([query], convert_to_numpy=True)
        faiss.normalize_L2(query_emb)
        # Retrieve more candidates then re-rank with security weight
        scores, indices = self.index.search(query_emb, top_k * 5)
        candidates = []
        for idx, sim in zip(indices[0], scores[0]):
            item = self.kb[idx]
            risk = item.get('risk', self.patterns.calculate_risk(item['code']))
            # Relevance score (Equation 3)
            score = config.RAG_ALPHA * sim + config.RAG_BETA * (1.0 / (1.0 + risk))
            candidates.append((score, item))
        candidates.sort(reverse=True, key=lambda x: x[0])
        # Apply diversity filter (simplified: return top_k after dedup)
        seen = set()
        results = []
        for score, item in candidates:
            code = item['code']
            if code not in seen:
                seen.add(code)
                results.append({**item, 'retrieval_score': score})
            if len(results) >= top_k:
                break
        return results
