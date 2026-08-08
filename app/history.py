"""
history.py
In-memory-only session history. Nothing here is ever written to disk,
a database, or a log file. History is lost when the app closes.
"""

from collections import deque
from datetime import datetime


class SessionHistory:
    def __init__(self, max_items=5):
        self._items = deque(maxlen=max_items)
        self._generated_count = 0

    def add(self, password, strength_label):
        self._items.appendleft({
            "password": password,
            "strength": strength_label,
            "length": len(password),
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        })
        self._generated_count += 1

    def all(self):
        return list(self._items)

    def clear(self):
        self._items.clear()

    def stats(self):
        """Session stats that do NOT expose actual password values."""
        items = self.all()
        avg_len = sum(i["length"] for i in items) / len(items) if items else 0
        strength_counts = {"Weak": 0, "Medium": 0, "Strong": 0}
        for i in items:
            if i["strength"] in strength_counts:
                strength_counts[i["strength"]] += 1
        return {
            "total_generated_this_session": self._generated_count,
            "retained_in_history": len(items),
            "average_length_in_history": round(avg_len, 1),
            "strength_breakdown": strength_counts,
        }
