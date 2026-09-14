"""把 DNS answer、实际端点和 TLS SNI 关联为可审计事实。"""

from __future__ import annotations

from collections import defaultdict

from contracts.traffic_intelligence import FlowDirection, ObservedFlow, ObservedFrame


class DnsCorrelationIndex:
    def __init__(self) -> None:
        self.address_names: dict[str, set[str]] = defaultdict(set)
        self.name_addresses: dict[str, set[str]] = defaultdict(set)
        self.name_cnames: dict[str, set[str]] = defaultdict(set)
        self.name_frame_refs: dict[str, set[int]] = defaultdict(set)

    @staticmethod
    def _name(value: str) -> str:
        return value.strip().casefold().rstrip(".")

    def add(self, frame: ObservedFrame) -> None:
        names = {self._name(value) for value in frame.dns_names if self._name(value)}
        cnames = {self._name(value) for value in frame.dns_cnames if self._name(value)}
        for name in names:
            self.name_frame_refs[name].add(frame.frame_number)
            self.name_cnames[name].update(cnames)
            for address in frame.dns_answers:
                self.name_addresses[name].add(address)
                self.address_names[address].add(name)
        for cname in cnames:
            self.name_frame_refs[cname].add(frame.frame_number)
            for address in frame.dns_answers:
                self.name_addresses[cname].add(address)
                self.address_names[address].add(cname)

    def names_for_flow(self, flow: ObservedFlow) -> set[str]:
        if flow.direction_relative_to_dut == FlowDirection.OUTBOUND:
            addresses = (flow.dst_ip,)
        elif flow.direction_relative_to_dut == FlowDirection.INBOUND:
            addresses = (flow.src_ip,)
        else:
            addresses = (flow.src_ip, flow.dst_ip)
        return {
            name
            for address in addresses
            for name in self.address_names.get(address, set())
        }

    def enrich_flow(self, flow: ObservedFlow) -> ObservedFlow:
        names = sorted(set(flow.dns_names) | self.names_for_flow(flow))
        return flow if names == flow.dns_names else flow.model_copy(update={"dns_names": names})

    def correlations(self, flows: list[ObservedFlow]) -> list[dict]:
        flow_ids_by_name: dict[str, set[str]] = defaultdict(set)
        sni_by_name: dict[str, set[str]] = defaultdict(set)
        endpoint_by_name: dict[str, set[str]] = defaultdict(set)
        for flow in flows:
            associated = set(flow.dns_names) | {self._name(value) for value in flow.sni}
            endpoint = (
                flow.dst_ip
                if flow.direction_relative_to_dut == FlowDirection.OUTBOUND
                else flow.src_ip
                if flow.direction_relative_to_dut == FlowDirection.INBOUND
                else None
            )
            for name in associated:
                flow_ids_by_name[name].add(flow.flow_id)
                sni_by_name[name].update(
                    self._name(value) for value in flow.sni if self._name(value)
                )
                if endpoint:
                    endpoint_by_name[name].add(endpoint)

        all_names = set(self.name_addresses) | set(flow_ids_by_name) | set(sni_by_name)
        rows: list[dict] = []
        for name in sorted(all_names):
            bases: list[str] = []
            if self.name_addresses.get(name):
                bases.append("dns_answer")
            if flow_ids_by_name.get(name):
                bases.append("endpoint_flow")
            if name in sni_by_name.get(name, set()):
                bases.append("sni_equals_dns_name")
            elif sni_by_name.get(name):
                bases.append("flow_sni")
            rows.append({
                "hostname": name,
                "resolved_addresses": sorted(self.name_addresses.get(name, set())),
                "observed_endpoint_addresses": sorted(endpoint_by_name.get(name, set())),
                "cnames": sorted(self.name_cnames.get(name, set())),
                "flow_ids": sorted(flow_ids_by_name.get(name, set())),
                "sni_names": sorted(sni_by_name.get(name, set())),
                "dns_frame_refs": sorted(self.name_frame_refs.get(name, set()))[:40],
                "basis": bases,
            })
        return rows


__all__ = ["DnsCorrelationIndex"]
