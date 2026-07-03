"""Usage examples for the EoMacca protocol stack."""

from ethernet_over_macca.protocol_stack import EoMaccaStack

from ethernet_over_macca.encapsulation import EomWrangler


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
    print(f"  Payload size:     {stats.payload_size} bytes")
    print(f"  Header size:      {stats.header_size} bytes")
    print(f"  Total size:       {stats.total_size} bytes")
    print(f"  Overhead ratio:   {stats.overhead_ratio:.2f}x")
    print(f"  Efficiency:       {stats.efficiency_percent:.2f}%")

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
            f"{stats.payload_size:<10} "
            f"{stats.total_size:<10} "
            f"{stats.header_size:<10} "
            f"{stats.efficiency_percent:>10.2f}% "
            f"{stats.overhead_ratio:>8.2f}x"
        )

    print("=" * 70)


def example_visualize_layers() -> None:
    """Visualize the layer-by-layer encapsulation using the v2 clean API."""
    print("\n" + "=" * 70)
    print("Layer-by-Layer Encapsulation Visualization")
    print("=" * 70)

    wrangler = EomWrangler()

    payload = b"Secret message"
    print(f"\n0. Original payload: {len(payload)} bytes")

    # Layer 1: Inner Ethernet
    inner_eth = wrangler.encapsulate_ethernet(
        payload,
        src_mac="de:ad:be:ef:ca:fe",
        dst_mac="fe:ed:fa:ce:de:ad",
    )
    print(
        f"1. Inner Ethernet frame: {len(inner_eth)} bytes (+{len(inner_eth) - len(payload)} bytes)"
    )

    # Layer 2: Inner IP
    inner_ip = wrangler.encapsulate_ip(
        inner_eth, src_ip="10.255.255.1", dst_ip="10.255.255.2", proto=6
    )
    print(
        f"2. Inner IP packet: {len(inner_ip)} bytes (+{len(inner_ip) - len(inner_eth)} bytes)"
    )

    # Layer 3: Inner TCP+IP
    inner_tcp = wrangler.encapsulate_tcp(
        inner_ip,
        src_ip="10.255.255.1",
        dst_ip="10.255.255.2",
        src_port=31337,
        dst_port=31338,
    )
    print(
        f"3. Inner TCP/IP segment: {len(inner_tcp)} bytes (+{len(inner_tcp) - len(inner_ip)} bytes)"
    )

    # Layer 4: DNS
    dns_msg = wrangler.encapsulate_dns(inner_tcp)
    print(
        f"4. DNS message: {len(dns_msg)} bytes (+{len(dns_msg) - len(inner_tcp)} bytes, includes base64)"
    )

    # Layer 5: HTTP
    http_data = wrangler.encapsulate_http(dns_msg)
    print(
        f"5. HTTP request: {len(http_data)} bytes (+{len(http_data) - len(dns_msg)} bytes)"
    )

    # Layer 6: Outer TCP+IP
    outer_tcp = wrangler.encapsulate_tcp(
        http_data,
        src_ip="192.168.1.100",
        dst_ip="192.168.1.200",
        src_port=54321,
        dst_port=9999,
        seq=2000,
        ack=2000,
    )
    print(
        f"6. Outer TCP/IP segment: {len(outer_tcp)} bytes (+{len(outer_tcp) - len(http_data)} bytes)"
    )

    # Layer 7: Outer Ethernet (fixed transport)
    outer_packet = wrangler.encapsulate_outer_ethernet(
        outer_tcp, src_mac="00:11:22:33:44:55", dst_mac="aa:bb:cc:dd:ee:ff"
    )
    print(
        f"7. Outer Ethernet frame: {len(outer_packet)} bytes (+{len(outer_packet) - len(outer_tcp)} bytes)"
    )

    print(f"\nTotal overhead: {len(outer_packet) - len(payload)} bytes")
    print(f"Overhead ratio: {(len(outer_packet) - len(payload)) / len(payload):.2f}x")

    print("=" * 70)


def main() -> None:
    """Run all examples."""
    example_basic_encapsulation()
    example_efficiency_comparison()
    example_visualize_layers()


if __name__ == "__main__":
    main()
