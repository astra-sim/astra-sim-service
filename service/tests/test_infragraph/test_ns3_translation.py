"""
MIT License

Copyright (c) 2025 Keysight Technologies

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import astra_sim_sdk.astra_sim_sdk as astra_sim
from astra_server.infrastructure.ns3_topology import NS3Topology

from infragraph.blueprints.devices.generic.generic_switch import Switch
from infragraph import Component, InfrastructureEdge
from infragraph.infragraph_service import InfraGraphService
from infragraph.blueprints.devices.nvidia.dgx import NvidiaDGX
from infragraph.blueprints.devices.generic.server import Server
from infragraph.blueprints.fabrics.clos_fat_tree_fabric import ClosFatTreeFabric
from infragraph.blueprints.fabrics.single_tier_fabric import SingleTierFabric
from infragraph.blueprints.devices.ironwood_rack import IronwoodRack
from astra_sim_sdk.astra_sim_sdk import Device
from infragraph import Infrastructure
import pytest


def test_single_host_eight_npus(infra_multi_gpu_server_factory):
    # infrastructure - infragraph
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "ns3"
    # load infrastructure and annotation?
    server = infra_multi_gpu_server_factory(4)
    configuration.infragraph.infrastructure.name = "1host-8ranks"
    configuration.infragraph.infrastructure.devices.append(server)
    configuration.infragraph.infrastructure.instances.add(
        name="host", device=server.name, count=1
    )

    # annotation
    node = configuration.infragraph.annotations.nodes.add("host")
    node.attributes.add(attribute="device_bandwidth_gbps", value="1000")
    node.attributes.add(attribute="device_latency_ms", value="0.005")
    node.attributes.add(attribute="device_name", value="server")
    node.attributes.add(attribute="device_type", value="host")

    NS3Topology.generate_topology(configuration)

    assert configuration.network_backend.ns3.topology.nc_topology.total_nodes == 9
    assert configuration.network_backend.ns3.topology.nc_topology.total_links == 8
    assert len(configuration.network_backend.ns3.topology.nc_topology.switch_ids) == 1
    assert configuration.network_backend.ns3.topology.nc_topology.switch_ids[0] == 8


def test_single_tier_four_server(infra_single_gpu_server_factory, infra_switch_factory):
    # infrastructure - infragraph
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "ns3"
    # load infrastructure and annotation?
    server = infra_single_gpu_server_factory()
    switch = infra_switch_factory()
    configuration.infragraph.infrastructure.name = "single-tier-four-servers"
    configuration.infragraph.infrastructure.devices.append(server).append(switch)
    hosts = configuration.infragraph.infrastructure.instances.add(
        name="host", device=server.name, count=4
    )
    rack_switch = configuration.infragraph.infrastructure.instances.add(
        name="rack_switch", device=switch.name, count=1
    )

    rack_link = configuration.infragraph.infrastructure.links.add(
        name="rack-link",
        description="Link characteristics for connectivity between servers and rack switch",
    )
    rack_link.physical.bandwidth.gigabits_per_second = 100

    host_component = InfraGraphService.get_component(server, Component.NIC)
    switch_component = InfraGraphService.get_component(switch, Component.PORT)

    # link each host to one leaf switch
    for idx in range(hosts.count):
        edge = configuration.infragraph.infrastructure.edges.add(
            scheme=InfrastructureEdge.ONE2ONE, link=rack_link.name  # type: ignore
        )
        edge.ep1.instance = f"{hosts.name}[{idx}]"
        edge.ep1.component = host_component.name
        edge.ep2.instance = f"{rack_switch.name}[0]"
        edge.ep2.component = f"{switch_component.name}[{idx}]"

    # annotation
    node = configuration.infragraph.annotations.nodes.add("host")
    node.attributes.add(attribute="device_bandwidth_gbps", value="1000")
    node.attributes.add(attribute="device_latency_ms", value="0.005")
    node.attributes.add(attribute="device_name", value="server")
    node.attributes.add(attribute="device_type", value="host")

    node = configuration.infragraph.annotations.nodes.add("rack_switch")
    node.attributes.add(attribute="device_bandwidth_gbps", value="1000")
    node.attributes.add(attribute="device_latency_ms", value="0.005")
    node.attributes.add(attribute="device_name", value="switch")
    node.attributes.add(attribute="device_type", value="switch")

    NS3Topology.generate_topology(configuration)

    assert configuration.network_backend.ns3.topology.nc_topology.total_nodes == 5
    assert configuration.network_backend.ns3.topology.nc_topology.total_links == 4
    assert len(configuration.network_backend.ns3.topology.nc_topology.switch_ids) == 1
    assert configuration.network_backend.ns3.topology.nc_topology.switch_ids[0] == 4


@pytest.mark.parametrize(
    "dgx_variant, nodes_count, links_count, switch_count",
    [
        ("dgx1", 8, 16, 0),
        # ("dgx2", 16, 1, 1),
        ("dgx_a100", 14, 48, 6),
        ("dgx_h100", 12, 32, 4),
        # ("dgx_gb200", 4, 1, 1),
    ],
)
def test_dgx(dgx_variant, nodes_count, links_count, switch_count):
    # infrastructure - infragraph
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "analytical_congestion_unaware"
    # load infrastructure and annotation?
    server = NvidiaDGX(dgx_variant)
    infra = Infrastructure()
    infra.devices.append(server)
    infra.instances.add(name=server.name, device=server.name, count=1)

    configuration.infragraph.infrastructure.name = "dgx"
    configuration.infragraph.infrastructure.deserialize(infra.serialize())

    # configuration.infragraph.infrastructure.devices.append(server)
    # configuration.infragraph.infrastructure.instances.add(name=server.name, device=server.name, count=1)

    # annotation
    node = configuration.infragraph.annotations.nodes.add(server.name)
    node.attributes.add(attribute="device_bandwidth_gbps", value="1000")
    node.attributes.add(attribute="device_latency_ms", value="0.005")
    node.attributes.add(attribute="device_name", value=server.name)
    node.attributes.add(attribute="device_type", value="host")

    NS3Topology.generate_topology(configuration)

    assert (
        configuration.network_backend.ns3.topology.nc_topology.total_nodes
        == nodes_count
    )
    assert (
        configuration.network_backend.ns3.topology.nc_topology.total_links
        == links_count
    )
    assert (
        len(configuration.network_backend.ns3.topology.nc_topology.switch_ids)
        == switch_count
    )
    # assert configuration.network_backend.ns3.topology.nc_topology.switch_ids[0] == 8


def test_single_ironwood():
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "ns3"

    server = IronwoodRack()
    infra = Infrastructure()
    infra.devices.append(server)
    infra.instances.add(name=server.name, device=server.name, count=1)

    configuration.infragraph.infrastructure.name = "ironwood"
    configuration.infragraph.infrastructure.deserialize(infra.serialize())

    node = configuration.infragraph.annotations.nodes.add(server.name)
    node.attributes.add(attribute="device_bandwidth_gbps", value="100")
    node.attributes.add(attribute="device_latency_ms", value="0.05")
    node.attributes.add(attribute="device_name", value=server.name)
    node.attributes.add(attribute="device_type", value="host")

    NS3Topology.generate_topology(configuration)

    assert configuration.network_backend.ns3.topology.nc_topology.total_nodes == 64
    assert configuration.network_backend.ns3.topology.nc_topology.total_links == 192
    assert len(configuration.network_backend.ns3.topology.nc_topology.switch_ids) == 0


def test_single_tier_single_host_eight_npus(
    infra_multi_gpu_server_factory, infra_switch_factory
):
    # infrastructure - infragraph
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "ns3"
    # load infrastructure and annotation?
    server = infra_multi_gpu_server_factory(4)
    switch = infra_switch_factory()
    configuration.infragraph.infrastructure.name = "single_tier_single_host_eight_npus"
    configuration.infragraph.infrastructure.devices.append(server).append(switch)
    hosts = configuration.infragraph.infrastructure.instances.add(
        name="host", device=server.name, count=1
    )
    rack_switch = configuration.infragraph.infrastructure.instances.add(
        name="rack_switch", device=switch.name, count=1
    )

    rack_link = configuration.infragraph.infrastructure.links.add(
        name="rack-link",
        description="Link characteristics for connectivity between servers and rack switch",
    )
    rack_link.physical.bandwidth.gigabits_per_second = 100

    host_component = InfraGraphService.get_component(server, Component.NIC)
    switch_component = InfraGraphService.get_component(switch, Component.PORT)

    # link each host to one leaf switch
    for idx in range(0, 8):
        edge = configuration.infragraph.infrastructure.edges.add(
            scheme=InfrastructureEdge.ONE2ONE, link=rack_link.name  # type: ignore
        )
        edge.ep1.instance = f"{hosts.name}[0]"
        edge.ep1.component = f"{host_component.name}[{idx}]"
        edge.ep2.instance = f"{rack_switch.name}[0]"
        edge.ep2.component = f"{switch_component.name}[{idx}]"

    # annotation
    node = configuration.infragraph.annotations.nodes.add("host")
    node.attributes.add(attribute="device_bandwidth_gbps", value="1000")
    node.attributes.add(attribute="device_latency_ms", value="0.005")
    node.attributes.add(attribute="device_name", value="server")
    node.attributes.add(attribute="device_type", value="host")

    node = configuration.infragraph.annotations.nodes.add("rack_switch")
    node.attributes.add(attribute="device_bandwidth_gbps", value="1000")
    node.attributes.add(attribute="device_latency_ms", value="0.005")
    node.attributes.add(attribute="device_name", value="switch")
    node.attributes.add(attribute="device_type", value="switch")

    NS3Topology.generate_topology(configuration)

    assert configuration.network_backend.ns3.topology.nc_topology.total_nodes == 10
    assert configuration.network_backend.ns3.topology.nc_topology.total_links == 16
    assert len(configuration.network_backend.ns3.topology.nc_topology.switch_ids) == 2
    assert configuration.network_backend.ns3.topology.nc_topology.switch_ids[0] == 8


def test_two_dgx_single_switch(infra_switch_factory):
    # infrastructure - infragraph
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "ns3"
    # load infrastructure and annotation?
    server = Device()
    server.deserialize(NvidiaDGX().serialize())
    switch = infra_switch_factory()
    configuration.infragraph.infrastructure.name = "two_dgx_single_switch"

    hosts = configuration.infragraph.infrastructure.instances.add(
        name="dgx_host", device=server.name, count=2
    )

    rack_switch = configuration.infragraph.infrastructure.instances.add(
        name="rack_switch", device=switch.name, count=1
    )
    configuration.infragraph.infrastructure.devices.append(server).append(switch)
    rack_switch = configuration.infragraph.infrastructure.instances.add(
        name="rack_switch", device=switch.name, count=1
    )

    rack_link = configuration.infragraph.infrastructure.links.add(
        name="rack-link",
        description="Link characteristics for connectivity between servers and rack switch",
    )
    rack_link.physical.bandwidth.gigabits_per_second = 200

    host_component = InfraGraphService.get_component(server, Component.NIC)
    switch_component = InfraGraphService.get_component(switch, Component.PORT)
    # link each host to one leaf switch
    for idx in range(16):
        dgx_index = 0 if idx < 8 else 1
        dgx_component_index = idx % 8
        edge = configuration.infragraph.infrastructure.edges.add(
            scheme=InfrastructureEdge.ONE2ONE, link=rack_link.name  # type: ignore
        )
        edge.ep1.instance = f"{hosts.name}[{dgx_index}]"
        edge.ep1.component = f"{host_component.name}[{dgx_component_index}]"
        edge.ep2.instance = f"{rack_switch.name}[0]"
        edge.ep2.component = f"{switch_component.name}[{idx}]"

    # annotation
    node = configuration.infragraph.annotations.nodes.add("dgx_host")
    node.attributes.add(attribute="device_bandwidth_gbps", value="200")
    node.attributes.add(attribute="device_latency_ms", value="0.05")
    node.attributes.add(attribute="device_name", value=server.name)
    node.attributes.add(attribute="device_type", value="host")

    node = configuration.infragraph.annotations.nodes.add("rack_switch")
    node.attributes.add(attribute="device_bandwidth_gbps", value="200")
    node.attributes.add(attribute="device_latency_ms", value="0.05")
    node.attributes.add(attribute="device_name", value=switch.name)
    node.attributes.add(attribute="device_type", value="switch")

    NS3Topology.generate_topology(configuration)

    assert configuration.network_backend.ns3.topology.nc_topology.total_nodes == 25
    assert configuration.network_backend.ns3.topology.nc_topology.total_links == 80
    assert len(configuration.network_backend.ns3.topology.nc_topology.switch_ids) == 9
    assert configuration.network_backend.ns3.topology.nc_topology.switch_ids[0] == 16


def test_two_tier_clos_fabric():
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "ns3"
    server = Server()
    switch = Switch(port_count=8)
    clos_fat_tree = ClosFatTreeFabric(switch, server, 2, [])
    configuration.infragraph.infrastructure.deserialize(clos_fat_tree.serialize())
    service = InfraGraphService()
    service.set_graph(clos_fat_tree)
    node = configuration.infragraph.annotations.nodes.add("server")
    node.attributes.add(attribute="device_bandwidth_gbps", value="100")
    node.attributes.add(attribute="device_latency_ms", value="0.05")
    node.attributes.add(attribute="device_name", value="server")
    node.attributes.add(attribute="device_type", value="host")

    node = configuration.infragraph.annotations.nodes.add("tier_0")
    node.attributes.add(attribute="device_bandwidth_gbps", value="100")
    node.attributes.add(attribute="device_latency_ms", value="0.05")
    node.attributes.add(attribute="device_name", value="switch")
    node.attributes.add(attribute="device_type", value="switch")

    node = configuration.infragraph.annotations.nodes.add("tier_1")
    node.attributes.add(attribute="device_bandwidth_gbps", value="100")
    node.attributes.add(attribute="device_latency_ms", value="0.05")
    node.attributes.add(attribute="device_name", value="switch")
    node.attributes.add(attribute="device_type", value="switch")
    NS3Topology.generate_topology(configuration)
    assert configuration.network_backend.ns3.topology.nc_topology.total_nodes == 76
    assert configuration.network_backend.ns3.topology.nc_topology.total_links == 128
    assert len(configuration.network_backend.ns3.topology.nc_topology.switch_ids) == 44


def test_three_tier_clos_fabric():
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "ns3"
    server = Server()
    switch = Switch(port_count=4)
    clos_fat_tree = ClosFatTreeFabric(switch, server, 3, [])
    configuration.infragraph.infrastructure.deserialize(clos_fat_tree.serialize())
    service = InfraGraphService()
    service.set_graph(clos_fat_tree)
    node = configuration.infragraph.annotations.nodes.add("server")
    node.attributes.add(attribute="device_bandwidth_gbps", value="100")
    node.attributes.add(attribute="device_latency_ms", value="0.05")
    node.attributes.add(attribute="device_name", value="server")
    node.attributes.add(attribute="device_type", value="host")

    node = configuration.infragraph.annotations.nodes.add("tier_0")
    node.attributes.add(attribute="device_bandwidth_gbps", value="100")
    node.attributes.add(attribute="device_latency_ms", value="0.05")
    node.attributes.add(attribute="device_name", value="switch")
    node.attributes.add(attribute="device_type", value="switch")

    node = configuration.infragraph.annotations.nodes.add("tier_1")
    node.attributes.add(attribute="device_bandwidth_gbps", value="100")
    node.attributes.add(attribute="device_latency_ms", value="0.05")
    node.attributes.add(attribute="device_name", value="switch")
    node.attributes.add(attribute="device_type", value="switch")

    node = configuration.infragraph.annotations.nodes.add("tier_2")
    node.attributes.add(attribute="device_bandwidth_gbps", value="100")
    node.attributes.add(attribute="device_latency_ms", value="0.05")
    node.attributes.add(attribute="device_name", value="switch")
    node.attributes.add(attribute="device_type", value="switch")
    NS3Topology.generate_topology(configuration)
    assert configuration.network_backend.ns3.topology.nc_topology.total_nodes == 52
    assert configuration.network_backend.ns3.topology.nc_topology.total_links == 80
