import time
from contextlib import contextmanager
from typing import Dict, List, Optional


class LatencyProfiler:
    def __init__(self):
        self.records: Dict[str, List[float]] = {}

    @contextmanager
    def measure(self, component: str):
        t0 = time.perf_counter()
        yield
        elapsed_ms = (time.perf_counter() - t0) * 1000
        self.records.setdefault(component, []).append(elapsed_ms)

    def record(self, component: str, latency_ms: float):
        self.records.setdefault(component, []).append(latency_ms)

    def summary(self) -> Dict[str, Dict[str, float]]:
        result = {}
        for comp, values in self.records.items():
            if not values:
                continue
            sorted_v = sorted(values)
            n = len(sorted_v)
            result[comp] = {
                "mean_ms": sum(values) / n,
                "median_ms": sorted_v[n // 2],
                "min_ms": sorted_v[0],
                "max_ms": sorted_v[-1],
                "p95_ms": sorted_v[int(n * 0.95)] if n > 1 else sorted_v[0],
                "count": n,
            }
        return result

    def paper_format(self) -> Dict[str, float]:
        s = self.summary()
        return {comp: stats["mean_ms"] for comp, stats in s.items()}

    def reset(self):
        self.records = {}


PROFILER = LatencyProfiler()