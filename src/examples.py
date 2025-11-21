"""Usage examples for the EoMacca protocol stack."""

from __future__ import annotations

try:
    from .protocol_stack import EoMaccaStack
except ImportError:
    # Running as script
    from protocol_stack import EoMaccaStack  # type: ignore[no-redef]


def example_basic_encapsulation() -> None:
    """Demonstrate basic encapsulation and decapsulation."""
    print("=" * 70)
    print("EoMacca Protocol Stack Example")
    print("=" * 70)

    # Create the protocol stack
    stack = EoMaccaStack()

    # Original payload
    payload = b"Hello, World! This is a test of the EoMacca protocol."
    print(f"\nOriginal payload: {payload.decode('ascii')}")
    print(f"Payload size: {len(payload)} bytes")

    # Encapsulate
    print("\nEncapsulating through 8 layers...")
    encapsulated = stack.encapsulate(payload)
    print(f"Encapsulated size: {len(encapsulated)} bytes")

    # Show overhead stats
    stats = stack.get_overhead_stats(payload)
    print("\nOverhead Statistics:")
    print(f"  Payload size:     {stats['payload_size']} bytes")
    print(f"  Header size:      {stats['header_size']} bytes")
    print(f"  Total size:       {stats['total_size']} bytes")
    print(f"  Overhead ratio:   {stats['overhead_ratio']:.2f}x")
    print(f"  Efficiency:       {stats['efficiency_percent']:.2f}%")

    # Decapsulate
    print("\nDecapsulating...")
    recovered = stack.decapsulate(encapsulated)
    print(f"Recovered payload: {recovered.decode('ascii')}")

    # Verify
    if payload == recovered:
        print("\n✓ Success! Payload matches original.")
    else:
        print("\n✗ Error! Payload does not match original.")

    print("=" * 70)


def example_efficiency_comparison() -> None:
    """Compare efficiency for different payload sizes."""
    print("\n" + "=" * 70)
    print("Efficiency Comparison for Different Payload Sizes")
    print("=" * 70)

    stack = EoMaccaStack()

    payload_sizes = [10, 50, 100, 500, 1000]

    print(
        f"\n{'Size':<10} {'Total':<10} {'Headers':<10} {'Efficiency':<12} {'Overhead'}"
    )
    print("-" * 70)

    for size in payload_sizes:
        payload = b"X" * size
        stats = stack.get_overhead_stats(payload)

        print(
            f"{stats['payload_size']:<10} "
            f"{stats['total_size']:<10} "
            f"{stats['header_size']:<10} "
            f"{stats['efficiency_percent']:>10.2f}% "
            f"{stats['overhead_ratio']:>8.2f}x"
        )

    print("=" * 70)


def example_visualize_layers() -> None:
    """Visualize the layer-by-layer encapsulation."""
    print("\n" + "=" * 70)
    print("Layer-by-Layer Encapsulation Visualization")
    print("=" * 70)

    try:
        from .encapsulation import (
            encapsulate_ethernet_in_ip,
            encapsulate_ip_in_tcp,
            encapsulate_tcp_in_dns,
            encapsulate_dns_in_http,
        )
    except ImportError:
        from encapsulation import (  # type: ignore[no-redef]
            encapsulate_ethernet_in_ip,
            encapsulate_ip_in_tcp,
            encapsulate_tcp_in_dns,
            encapsulate_dns_in_http,
        )

    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw

    payload = b"Secret message"
    print(f"\n0. Original payload: {len(payload)} bytes")

    # Layer 1: Inner Ethernet
    inner_eth = Ether(src="de:ad:be:ef:ca:fe", dst="fe:ed:fa:ce:de:ad") / Raw(
        load=payload
    )
    inner_eth_bytes = bytes(inner_eth)
    print(
        f"1. Inner Ethernet frame: {len(inner_eth_bytes)} bytes (+{len(inner_eth_bytes) - len(payload)} bytes)"
    )

    # Layer 2: Inner IP
    inner_ip = encapsulate_ethernet_in_ip(inner_eth_bytes)
    print(
        f"2. Inner IP packet: {len(inner_ip)} bytes (+{len(inner_ip) - len(inner_eth_bytes)} bytes)"
    )

    # Layer 3: Inner TCP
    inner_tcp = encapsulate_ip_in_tcp(inner_ip)
    print(
        f"3. Inner TCP segment: {len(inner_tcp)} bytes (+{len(inner_tcp) - len(inner_ip)} bytes)"
    )

    # Layer 4: DNS
    dns_msg = encapsulate_tcp_in_dns(inner_tcp)
    print(
        f"4. DNS message: {len(dns_msg)} bytes (+{len(dns_msg) - len(inner_tcp)} bytes, includes base64)"
    )

    # Layer 5: HTTP
    http_data = encapsulate_dns_in_http(dns_msg)
    print(
        f"5. HTTP request: {len(http_data)} bytes (+{len(http_data) - len(dns_msg)} bytes)"
    )

    # Layer 6: Outer TCP
    outer_tcp = (
        IP(src="192.168.1.100", dst="192.168.1.200")
        / TCP(sport=54321, dport=9999, flags="PA")
        / Raw(load=http_data)
    )
    outer_tcp_bytes = bytes(outer_tcp)
    print(
        f"6. Outer TCP segment: {len(outer_tcp_bytes)} bytes (+{len(outer_tcp_bytes) - len(http_data)} bytes)"
    )

    # Layer 7: Outer IP (already in outer_tcp)
    # Layer 8: Outer Ethernet
    outer_packet = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / outer_tcp
    outer_packet_bytes = bytes(outer_packet)
    print(
        f"7. Outer Ethernet frame: {len(outer_packet_bytes)} bytes (+{len(outer_packet_bytes) - len(outer_tcp_bytes)} bytes)"
    )

    print(f"\nTotal overhead: {len(outer_packet_bytes) - len(payload)} bytes")
    print(
        f"Overhead ratio: {(len(outer_packet_bytes) - len(payload)) / len(payload):.2f}x"
    )

    print("=" * 70)


def main() -> None:
    """Run all examples."""
    example_basic_encapsulation()
    example_efficiency_comparison()
    example_visualize_layers()


if __name__ == "__main__":
    main()
