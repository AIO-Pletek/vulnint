"""Full reindex of all CVEs into OpenSearch.

Usage: python -m app.scripts.reindex_opensearch
"""
from __future__ import annotations

from app.workers.tasks.opensearch import reindex_all

if __name__ == "__main__":
    result = reindex_all()
    print(result)
