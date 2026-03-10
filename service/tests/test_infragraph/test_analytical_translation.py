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
from astra_server.infrastructure.analytical_topology import AnalyticalTopology


from infragraph import Component, InfrastructureEdge
from infragraph.blueprints.devices.ironwood_rack import IronwoodRack
from infragraph.blueprints.devices.nvidia.dgx import NvidiaDGX
from infragraph.infragraph_service import InfraGraphService
from infragraph import Infrastructure


def test_single_tier_single_host_eight_ranks(infra_multi_gpu_server_factory):
    # infrastructure - infragraph
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "ns3"
    # load infrastructure and annotation?
    server = infra_multi_gpu_server_factory(4)
    configuration.infragraph.infrastructure.name = "single_tier_single_host_eight_ranks"
    configuration.infragraph.infrastructure.devices.append(server)
    configuration.infragraph.infrastructure.instances.add(
        name="host", device=server.name, count=1
    )

    # annotation
    host_device_spec = astra_sim.AnnotationDeviceSpecifications()
    host_device_spec.device_bandwidth_gbps = 1000
    host_device_spec.device_latency_ms = 0.005
    host_device_spec.device_name = "server"
    host_device_spec.device_type = "host"
    configuration.infragraph.annotations.device_specifications.append(host_device_spec)

    AnalyticalTopology.generate_topology(configuration)

    print(configuration.network_backend.analytical_congestion_unaware.topology.network)
    assert (
        len(
            configuration.network_backend.analytical_congestion_unaware.topology.network
        )
        > 0
    )


def test_single_tier_single_host_four_rank(
    infra_single_gpu_server_factory, infra_switch_factory
):
    # infrastructure - infragraph
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "analytical_congestion_unaware"
    # load infrastructure and annotation?
    server = infra_single_gpu_server_factory()
    switch = infra_switch_factory()
    configuration.infragraph.infrastructure.name = "single_tier_single_host_four_rank"
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
    host_device_spec = astra_sim.AnnotationDeviceSpecifications()
    host_device_spec.device_bandwidth_gbps = 1000
    host_device_spec.device_latency_ms = 0.005
    host_device_spec.device_name = "server"
    host_device_spec.device_type = "host"
    configuration.infragraph.annotations.device_specifications.append(host_device_spec)

    switch_device_spec = astra_sim.AnnotationDeviceSpecifications()
    switch_device_spec.device_bandwidth_gbps = 1000
    switch_device_spec.device_latency_ms = 0.005
    switch_device_spec.device_name = "switch"
    switch_device_spec.device_type = "switch"
    configuration.infragraph.annotations.device_specifications.append(
        switch_device_spec
    )

    AnalyticalTopology.generate_topology(configuration)

    print(configuration.network_backend.analytical_congestion_unaware.topology.network)
    assert (
        len(
            configuration.network_backend.analytical_congestion_unaware.topology.network
        )
        > 0
    )


def test_single_dgx_h100():
    # infrastructure - infragraph
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "analytical_congestion_unaware"
    # load infrastructure and annotation?
    server = NvidiaDGX()
    infra = Infrastructure()
    infra.devices.append(server)
    infra.instances.add(name=server.name, device=server.name, count=1)

    configuration.infragraph.infrastructure.name = "dgx"
    configuration.infragraph.infrastructure.deserialize(infra.serialize())

    # configuration.infragraph.infrastructure.devices.append(server)
    # configuration.infragraph.infrastructure.instances.add(name=server.name, device=server.name, count=1)

    # annotation
    host_device_spec = astra_sim.AnnotationDeviceSpecifications()
    host_device_spec.device_bandwidth_gbps = 1000
    host_device_spec.device_latency_ms = 0.005
    host_device_spec.device_name = server.name
    host_device_spec.device_type = "host"
    configuration.infragraph.annotations.device_specifications.append(host_device_spec)

    link_spec = astra_sim.AnnotationLinkSpecifications()
    link_spec.link_error_rate = 0
    link_spec.link_name = "pcie"
    link_spec.packet_loss_rate = 0
    link_spec.link_bandwidth_gbps = 1600
    link_spec.link_latency_ms = 0.005
    configuration.infragraph.annotations.link_specifications.append(link_spec)

    AnalyticalTopology.generate_topology(configuration)

    print(configuration.network_backend.analytical_congestion_unaware.topology.network)
    assert (
        len(
            configuration.network_backend.analytical_congestion_unaware.topology.network
        )
        > 0
    )

    assert (
        configuration.network_backend.analytical_congestion_unaware.topology.network[
            0
        ].topology
        == "switch"
    )
    assert (
        configuration.network_backend.analytical_congestion_unaware.topology.network[
            0
        ].npus_count
        == 8
    )


def test_single_dgx1():
    # infrastructure - infragraph
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "analytical_congestion_unaware"
    # load infrastructure and annotation?
    server = NvidiaDGX("dgx1")
    infra = Infrastructure()
    infra.devices.append(server)
    infra.instances.add(name=server.name, device=server.name, count=1)

    configuration.infragraph.infrastructure.name = "dgx"
    configuration.infragraph.infrastructure.deserialize(infra.serialize())

    # configuration.infragraph.infrastructure.devices.append(server)
    # configuration.infragraph.infrastructure.instances.add(name=server.name, device=server.name, count=1)

    # annotation
    host_device_spec = astra_sim.AnnotationDeviceSpecifications()
    host_device_spec.device_bandwidth_gbps = 1000
    host_device_spec.device_latency_ms = 0.005
    host_device_spec.device_name = server.name
    host_device_spec.device_type = "host"
    configuration.infragraph.annotations.device_specifications.append(host_device_spec)

    link_spec = astra_sim.AnnotationLinkSpecifications()
    link_spec.link_error_rate = 0
    link_spec.link_name = "xpu_fabric"
    link_spec.packet_loss_rate = 0
    link_spec.link_bandwidth_gbps = 1600
    link_spec.link_latency_ms = 0.005
    configuration.infragraph.annotations.link_specifications.append(link_spec)

    AnalyticalTopology.generate_topology(configuration)

    print(configuration.network_backend.analytical_congestion_unaware.topology.network)
    assert (
        len(
            configuration.network_backend.analytical_congestion_unaware.topology.network
        )
        == 2
    )

    assert (
        configuration.network_backend.analytical_congestion_unaware.topology.network[
            0
        ].topology
        == "fullyconnected"
    )
    assert (
        configuration.network_backend.analytical_congestion_unaware.topology.network[
            1
        ].topology
        == "ring"
    )
    assert (
        configuration.network_backend.analytical_congestion_unaware.topology.network[
            0
        ].npus_count
        == 4
    )
    assert (
        configuration.network_backend.analytical_congestion_unaware.topology.network[
            1
        ].npus_count
        == 2
    )


def test_single_dgx_gb200():
    # infrastructure - infragraph
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "analytical_congestion_unaware"
    # load infrastructure and annotation?
    server = NvidiaDGX("dgx_gb200")
    infra = Infrastructure()
    infra.devices.append(server)
    infra.instances.add(name=server.name, device=server.name, count=1)

    configuration.infragraph.infrastructure.name = "dgx"
    configuration.infragraph.infrastructure.deserialize(infra.serialize())

    # configuration.infragraph.infrastructure.devices.append(server)
    # configuration.infragraph.infrastructure.instances.add(name=server.name, device=server.name, count=1)

    # annotation
    host_device_spec = astra_sim.AnnotationDeviceSpecifications()
    host_device_spec.device_bandwidth_gbps = 1000
    host_device_spec.device_latency_ms = 0.005
    host_device_spec.device_name = server.name
    host_device_spec.device_type = "host"
    configuration.infragraph.annotations.device_specifications.append(host_device_spec)

    link_spec = astra_sim.AnnotationLinkSpecifications()
    link_spec.link_error_rate = 0
    link_spec.link_name = "xpu_fabric"
    link_spec.packet_loss_rate = 0
    link_spec.link_bandwidth_gbps = 1600
    link_spec.link_latency_ms = 0.005
    configuration.infragraph.annotations.link_specifications.append(link_spec)

    AnalyticalTopology.generate_topology(configuration)

    print(configuration.network_backend.analytical_congestion_unaware.topology.network)
    assert (
        len(
            configuration.network_backend.analytical_congestion_unaware.topology.network
        )
        == 1
    )

    assert (
        configuration.network_backend.analytical_congestion_unaware.topology.network[
            0
        ].topology
        == "switch"
    )
    assert (
        configuration.network_backend.analytical_congestion_unaware.topology.network[
            0
        ].npus_count
        == 4
    )


def test_single_dgx_a100():
    # infrastructure - infragraph
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "analytical_congestion_unaware"
    # load infrastructure and annotation?
    server = NvidiaDGX("dgx_a100")
    infra = Infrastructure()
    infra.devices.append(server)
    infra.instances.add(name=server.name, device=server.name, count=1)

    configuration.infragraph.infrastructure.name = "dgx"
    configuration.infragraph.infrastructure.deserialize(infra.serialize())

    # configuration.infragraph.infrastructure.devices.append(server)
    # configuration.infragraph.infrastructure.instances.add(name=server.name, device=server.name, count=1)

    # annotation
    host_device_spec = astra_sim.AnnotationDeviceSpecifications()
    host_device_spec.device_bandwidth_gbps = 1000
    host_device_spec.device_latency_ms = 0.005
    host_device_spec.device_name = server.name
    host_device_spec.device_type = "host"
    configuration.infragraph.annotations.device_specifications.append(host_device_spec)

    link_spec = astra_sim.AnnotationLinkSpecifications()
    link_spec.link_error_rate = 0
    link_spec.link_name = "xpu_fabric"
    link_spec.packet_loss_rate = 0
    link_spec.link_bandwidth_gbps = 1600
    link_spec.link_latency_ms = 0.005
    configuration.infragraph.annotations.link_specifications.append(link_spec)

    AnalyticalTopology.generate_topology(configuration)

    print(configuration.network_backend.analytical_congestion_unaware.topology.network)
    assert (
        len(
            configuration.network_backend.analytical_congestion_unaware.topology.network
        )
        == 1
    )

    assert (
        configuration.network_backend.analytical_congestion_unaware.topology.network[
            0
        ].topology
        == "switch"
    )
    assert (
        configuration.network_backend.analytical_congestion_unaware.topology.network[
            0
        ].npus_count
        == 8
    )


def test_single_ironwood_rack():
    # infrastructure - infragraph
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "analytical_congestion_unaware"
    # load infrastructure and annotation?
    server = IronwoodRack()
    infra = Infrastructure()
    infra.devices.append(server)
    infra.instances.add(name=server.name, device=server.name, count=1)

    configuration.infragraph.infrastructure.name = "ironwood"
    configuration.infragraph.infrastructure.deserialize(infra.serialize())

    # configuration.infragraph.infrastructure.devices.append(server)
    # configuration.infragraph.infrastructure.instances.add(name=server.name, device=server.name, count=1)

    # annotation
    host_device_spec = astra_sim.AnnotationDeviceSpecifications()
    host_device_spec.device_bandwidth_gbps = 1000
    host_device_spec.device_latency_ms = 0.005
    host_device_spec.device_name = server.name
    host_device_spec.device_type = "host"
    configuration.infragraph.annotations.device_specifications.append(host_device_spec)

    AnalyticalTopology.generate_topology(configuration)

    print(configuration.network_backend.analytical_congestion_unaware.topology.network)
    assert (
        len(
            configuration.network_backend.analytical_congestion_unaware.topology.network
        )
        == 3
    )

    assert (
        configuration.network_backend.analytical_congestion_unaware.topology.network[
            0
        ].topology
        == "ring"
    )
    assert (
        configuration.network_backend.analytical_congestion_unaware.topology.network[
            1
        ].topology
        == "ring"
    )
    assert (
        configuration.network_backend.analytical_congestion_unaware.topology.network[
            2
        ].topology
        == "ring"
    )
    assert (
        configuration.network_backend.analytical_congestion_unaware.topology.network[
            0
        ].npus_count
        == 4
    )
    assert (
        configuration.network_backend.analytical_congestion_unaware.topology.network[
            1
        ].npus_count
        == 4
    )
    assert (
        configuration.network_backend.analytical_congestion_unaware.topology.network[
            2
        ].npus_count
        == 4
    )


def test_single_tier_single_host_eight_ranks(
    infra_multi_gpu_server_factory, infra_switch_factory
):
    # infrastructure - infragraph
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "analytical_congestion_unaware"
    # load infrastructure and annotation?
    server = infra_multi_gpu_server_factory(4)
    switch = infra_switch_factory()
    configuration.infragraph.infrastructure.name = "single_tier_single_host_eight_ranks"
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
    host_device_spec = astra_sim.AnnotationDeviceSpecifications()
    host_device_spec.device_bandwidth_gbps = 1000
    host_device_spec.device_latency_ms = 0.005
    host_device_spec.device_name = "server"
    host_device_spec.device_type = "host"
    configuration.infragraph.annotations.device_specifications.append(host_device_spec)

    switch_device_spec = astra_sim.AnnotationDeviceSpecifications()
    switch_device_spec.device_bandwidth_gbps = 1000
    switch_device_spec.device_latency_ms = 0.005
    switch_device_spec.device_name = "switch"
    switch_device_spec.device_type = "switch"
    configuration.infragraph.annotations.device_specifications.append(
        switch_device_spec
    )

    AnalyticalTopology.generate_topology(configuration)

    print(configuration.network_backend.analytical_congestion_unaware.topology.network)
    assert (
        len(
            configuration.network_backend.analytical_congestion_unaware.topology.network
        )
        > 0
    )
