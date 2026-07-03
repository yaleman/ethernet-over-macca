"""Main protocol stack implementation for EoMacca v2."""

from scapy.config import conf

from ethernet_over_macca.encapsulation import (
    OUTER_DST_MAC,
    OUTER_DST_PORT,
    OUTER_SRC_MAC,
    OUTER_SRC_PORT,
    OUTER_DST_IP,
    OUTER_SRC_IP,
    INNER_DST_IP,
    INNER_SRC_IP,
    INNER_DST_PORT,
    INNER_SRC_PORT,
    DEFAULT_LAYER_ORDER,
    EomWrangler,
    Layer,
    LayerConfig,
    parse_layer_order,
)
from ethernet_over_macca.stats import PayloadStats


# Keep scapy from padding Ether/IP/TCP layers when converting to bytes; this
# was the source of the 0xAAAAAAAA bug. v2's non-greedy decap does not depend
# on this, but encap still uses scapy to serialise, so the setting stays.
conf.padding = 0


class EoMaccaStack:
    """The EoMacca v2 protocol stack.

    Wire layout::

        [ Outer Ethernet (14 B, fixed) ]
        [ Outermost configurable layer (must contribute an outer
          IP envelope: Layer.TCP or Layer.IP) ]
        [ ...arbitrary inner layers in any order, any count... ]
        [ payload ]

    Per the v2 design, the outer Ethernet and the outer IP envelope are a
    hard transport limit. The outer IP is contributed by the outermost
    configurable layer (a ``Layer.TCP`` includes both IP and TCP headers; a
    ``Layer.IP`` includes just the IP header). The layer order is configured
    out-of-band; there is no in-band negotiation. The default config
    reproduces v1's ``"ETHDtie"`` wire format byte-for-byte.
    """

    def __init__(
        self,
        *,
        inner_src_ip: str = INNER_SRC_IP,
        inner_dst_ip: str = INNER_DST_IP,
        inner_src_port: int = INNER_SRC_PORT,
        inner_dst_port: int = INNER_DST_PORT,
        outer_src_ip: str = OUTER_SRC_IP,
        outer_dst_ip: str = OUTER_DST_IP,
        outer_src_port: int = OUTER_SRC_PORT,
        outer_dst_port: int = OUTER_DST_PORT,
        outer_src_mac: str = OUTER_SRC_MAC,
        outer_dst_mac: str = OUTER_DST_MAC,
        layers: list[LayerConfig] | None = None,
        layer_order: list[Layer] | str | None = None,
    ) -> None:
        """Initialise an EoMacca stack.

        Args:
            layers: Explicit per-layer config list, decapsulation order
                (outer -> inner). Defaults to :func:`default_layer_configs`
                which reproduces v1 bytes. Use this when you want per-instance
                addresses for repeated layers.
            layer_order: Alternative to ``layers`` when default addresses are
                acceptable. Decap order (outer -> inner). Accepts either a
                ``list[Layer]`` or a v2 layer-order string like ``"THDtIE"``
                (see :func:`parse_layer_order`); a ``str`` is parsed into a
                ``list[Layer]`` and the per-instance addresses are assigned
                heuristically (outermost TCP/IP get outer addresses, others
                get inner).
            outer_src_mac / outer_dst_mac: Fixed outer Ethernet MACs.
            other address args: Override defaults used by ``layer_order``
                constructed configs; ignored if ``layers`` is supplied.

        Raises:
            ValueError: If the configuration is structurally invalid
                (empty, or outermost configurable layer cannot carry an outer
                IP envelope).
        """
        self.outer_src_mac = outer_src_mac
        self.outer_dst_mac = outer_dst_mac

        if layers is not None and layer_order is not None:
            raise ValueError("Pass either `layers` or `layer_order`, not both")

        if layers is not None:
            self.layers = list(layers)
        else:
            if layer_order is None:
                order = list(DEFAULT_LAYER_ORDER)
            elif isinstance(layer_order, str):
                order = parse_layer_order(layer_order)
            else:
                order = list(layer_order)
            self.layers = self._configs_from_order(
                order,
                inner_src_ip=inner_src_ip,
                inner_dst_ip=inner_dst_ip,
                inner_src_port=inner_src_port,
                inner_dst_port=inner_dst_port,
                outer_src_ip=outer_src_ip,
                outer_dst_ip=outer_dst_ip,
                outer_src_port=outer_src_port,
                outer_dst_port=outer_dst_port,
                outer_src_mac=outer_src_mac,
                outer_dst_mac=outer_dst_mac,
            )

        if not self.layers:
            raise ValueError("EoMacca stack must have at least one configurable layer")

        if not _layer_contributes_ip(self.layers[0]):
            raise ValueError(
                "The outermost configurable layer must contribute an outer "
                "IP envelope (Layer.TCP or Layer.IP); got "
                f"{self.layers[0].kind!r}"
            )

        self.wrangler = EomWrangler(
            inner_src_ip=inner_src_ip,
            inner_dst_ip=inner_dst_ip,
            inner_src_port=inner_src_port,
            inner_dst_port=inner_dst_port,
            outer_src_ip=outer_src_ip,
            outer_dst_ip=outer_dst_ip,
            outer_src_port=outer_src_port,
            outer_dst_port=outer_dst_port,
            outer_src_mac=outer_src_mac,
            outer_dst_mac=outer_dst_mac,
        )

    @staticmethod
    def _configs_from_order(
        order: list[Layer],
        *,
        inner_src_ip: str,
        inner_dst_ip: str,
        inner_src_port: int,
        inner_dst_port: int,
        outer_src_ip: str,
        outer_dst_ip: str,
        outer_src_port: int,
        outer_dst_port: int,
        outer_src_mac: str,
        outer_dst_mac: str,
    ) -> list[LayerConfig]:
        """Build a list of LayerConfigs from a plain layer order.

        Heuristic address assignment: the first (outermost) ``Layer.TCP`` uses
        outer addresses; subsequent TCP layers use inner addresses. The first
        ``Layer.IP`` uses inner addresses; if it is the outermost layer instead,
        it gets outer addresses (so it can serve as the outer IP envelope).
        Ethernet layers use the outer MACs.
        """
        configs: list[LayerConfig] = []
        seen_outer_tcp = False
        seen_outer_ip = False
        for i, kind in enumerate(order):
            is_outermost = i == 0
            if kind is Layer.TCP:
                if is_outermost or not seen_outer_tcp:
                    configs.append(
                        LayerConfig(
                            kind=Layer.TCP,
                            src_ip=outer_src_ip,
                            dst_ip=outer_dst_ip,
                            src_port=outer_src_port,
                            dst_port=outer_dst_port,
                            tcp_seq=2000,
                            tcp_ack=2000,
                        )
                    )
                    seen_outer_tcp = True
                else:
                    configs.append(
                        LayerConfig(
                            kind=Layer.TCP,
                            src_ip=inner_src_ip,
                            dst_ip=inner_dst_ip,
                            src_port=inner_src_port,
                            dst_port=inner_dst_port,
                        )
                    )
            elif kind is Layer.IP:
                if is_outermost and not seen_outer_ip:
                    configs.append(
                        LayerConfig(
                            kind=Layer.IP,
                            src_ip=outer_src_ip,
                            dst_ip=outer_dst_ip,
                            proto=6,
                        )
                    )
                    seen_outer_ip = True
                else:
                    configs.append(
                        LayerConfig(
                            kind=Layer.IP,
                            src_ip=inner_src_ip,
                            dst_ip=inner_dst_ip,
                            proto=6,
                        )
                    )
            elif kind is Layer.ETHERNET:
                configs.append(
                    LayerConfig(
                        kind=Layer.ETHERNET,
                        src_mac=outer_src_mac,
                        dst_mac=outer_dst_mac,
                    )
                )
            else:
                configs.append(LayerConfig(kind=kind))
        return configs

    # --- encap / decap public API -----------------------------------------

    def encapsulate(self, payload: bytes) -> bytes:
        """Encapsulate ``payload`` through the configured layers + outer Eth.

        Encapsulation order is the reverse of the decapsulation order, so the
        last element of ``self.layers`` is wrapped first (around the bare
        payload), and the first element ends up outermost — providing the
        outer IP envelope that the outer Ethernet then wraps.
        """
        result = payload
        for cfg in reversed(self.layers):
            result = self.wrangler.encapsulate_layer(cfg, result)
        return self.wrangler.encapsulate_outer_ethernet(
            result, src_mac=self.outer_src_mac, dst_mac=self.outer_dst_mac
        )

    def decapsulate(self, frame: bytes) -> bytes:
        """Decapsulate an outer Ethernet frame back to the original payload.

        Args:
            frame: Raw bytes of the outer Ethernet frame (as received on the
                wire).

        Returns:
            The original payload bytes.

        Raises:
            EomError: Typed variant describing the failure point
                (``BadFrame``, ``Truncated``, ``MalformedLayer``,
                ``WrongLayerType``, ``NoPayload``).
        """
        result = self.wrangler.decapsulate_outer_ethernet(frame)
        for cfg in self.layers:
            result = self.wrangler.decapsulate_layer(cfg, result)
        return result

    def get_overhead_stats(self, payload: bytes) -> PayloadStats:
        """Calculate overhead statistics for a given payload."""
        encapsulated = self.encapsulate(payload)

        payload_size = len(payload)
        total_size = len(encapsulated)
        header_size = total_size - payload_size
        overhead_ratio = (header_size / payload_size) if payload_size > 0 else 0.0
        efficiency = (payload_size / total_size * 100) if total_size > 0 else 0.0

        return PayloadStats(
            payload_size=payload_size,
            total_size=total_size,
            header_size=header_size,
            overhead_ratio=overhead_ratio,
            efficiency_percent=efficiency,
        )


def _layer_contributes_ip(cfg: LayerConfig) -> bool:
    """Whether a configurable layer contributes an outer IP envelope when applied."""
    return cfg.kind in (Layer.TCP, Layer.IP)
