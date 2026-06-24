"""Performance benchmarks for EoMacca protocol."""

import statistics
import time

import pytest

from src.protocol_stack import EoMaccaStack


class TestPerformanceBenchmarks:
    """Performance benchmarks for the EoMacca protocol stack."""

    @pytest.fixture
    def stack(self) -> EoMaccaStack:
        """Provide a fresh EoMaccaStack instance."""
        return EoMaccaStack()

    def test_encapsulation_latency_small_payload(self, stack: EoMaccaStack) -> None:
        """Benchmark encapsulation latency for small payloads (1-100 bytes)."""
        payload = b"X" * 50
        iterations = 100

        latencies = []
        for _ in range(iterations):
            start = time.perf_counter()
            stack.encapsulate(payload)
            end = time.perf_counter()
            latencies.append((end - start) * 1000)

        avg_latency = statistics.mean(latencies)
        p95_latency = sorted(latencies)[int(iterations * 0.95)]

        assert avg_latency < 10, f"Average encapsulation too slow: {avg_latency:.2f}ms"
        assert p95_latency < 20, f"P95 encapsulation too slow: {p95_latency:.2f}ms"

    def test_decapsulation_latency_small_payload(self, stack: EoMaccaStack) -> None:
        """Benchmark decapsulation latency for small payloads."""
        payload = b"X" * 50
        packet = stack.encapsulate(payload)
        iterations = 100

        latencies = []
        for _ in range(iterations):
            start = time.perf_counter()
            stack.decapsulate(packet)
            end = time.perf_counter()
            latencies.append((end - start) * 1000)

        avg_latency = statistics.mean(latencies)
        p95_latency = sorted(latencies)[int(iterations * 0.95)]

        assert avg_latency < 10, f"Average decapsulation too slow: {avg_latency:.2f}ms"
        assert p95_latency < 20, f"P95 decapsulation too slow: {p95_latency:.2f}ms"

    def test_roundtrip_latency(self, stack: EoMaccaStack) -> None:
        """Benchmark full round-trip latency."""
        payload = b"X" * 100
        iterations = 50

        latencies = []
        for _ in range(iterations):
            start = time.perf_counter()
            packet = stack.encapsulate(payload)
            stack.decapsulate(packet)
            end = time.perf_counter()
            latencies.append((end - start) * 1000)

        avg_latency = statistics.mean(latencies)
        p95_latency = sorted(latencies)[int(iterations * 0.95)]

        assert avg_latency < 20, f"Average roundtrip too slow: {avg_latency:.2f}ms"
        assert p95_latency < 40, f"P95 roundtrip too slow: {p95_latency:.2f}ms"

    def test_throughput_small_payloads(self, stack: EoMaccaStack) -> None:
        """Benchmark throughput for small payloads."""
        payload = b"X" * 50
        duration_seconds = 1.0
        count = 0

        start = time.perf_counter()
        while time.perf_counter() - start < duration_seconds:
            packet = stack.encapsulate(payload)
            stack.decapsulate(packet)
            count += 1

        throughput = count / duration_seconds
        assert throughput > 100, f"Throughput too low: {throughput:.0f} ops/sec"

    def test_encapsulation_scaling(self, stack: EoMaccaStack) -> None:
        """Test that encapsulation time scales linearly with payload size."""
        sizes = [10, 100, 1000]
        latencies = []

        for size in sizes:
            payload = b"X" * size
            iterations = 50

            start = time.perf_counter()
            for _ in range(iterations):
                stack.encapsulate(payload)
            end = time.perf_counter()

            avg_latency = (end - start) / iterations * 1000
            latencies.append(avg_latency)

        assert latencies[1] < latencies[0] * 5, "Latency doesn't scale reasonably"
        assert latencies[2] < latencies[1] * 5, "Latency doesn't scale reasonably"

    def test_overhead_ratio_consistency(self, stack: EoMaccaStack) -> None:
        """Test that overhead ratio is consistent across payload sizes."""
        sizes = [10, 50, 100, 500, 1000]
        overhead_ratios = []

        for size in sizes:
            payload = b"X" * size
            stats = stack.get_overhead_stats(payload)
            overhead_ratios.append(stats["overhead_ratio"])

        assert all(r > 0 for r in overhead_ratios), "All overhead ratios should be positive"

        assert overhead_ratios[-1] < overhead_ratios[0], "Larger payloads should have lower overhead ratio"

    def test_memory_efficiency(self, stack: EoMaccaStack) -> None:
        """Test that packet sizes are reasonable."""
        payload = b"X" * 100
        packet = stack.encapsulate(payload)

        overhead_multiplier = len(packet) / len(payload)

        assert overhead_multiplier < 50, f"Overhead too high: {overhead_multiplier:.1f}x"

    @pytest.mark.parametrize("payload_size", [1, 10, 100, 1000])
    def test_encapsulation_decapsulation_various_sizes(
        self, stack: EoMaccaStack, payload_size: int
    ) -> None:
        """Test round-trip for various payload sizes."""
        payload = b"X" * payload_size

        packet = stack.encapsulate(payload)
        recovered = stack.decapsulate(packet)

        assert recovered == payload, f"Failed for payload size {payload_size}"

    def test_stats_calculation_performance(self, stack: EoMaccaStack) -> None:
        """Benchmark overhead statistics calculation."""
        payload = b"X" * 100
        iterations = 100

        start = time.perf_counter()
        for _ in range(iterations):
            stack.get_overhead_stats(payload)
        end = time.perf_counter()

        avg_latency = (end - start) / iterations * 1000
        assert avg_latency < 20, f"Stats calculation too slow: {avg_latency:.2f}ms"
