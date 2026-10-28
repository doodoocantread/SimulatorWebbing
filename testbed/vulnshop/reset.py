"""Rebuild data/ (database, token key, sandbox files, empty oracle log)."""
from vulnshop import config, store

if __name__ == "__main__":
    store.reset()
    print(f"reset complete: {config.DATA_DIR}")
