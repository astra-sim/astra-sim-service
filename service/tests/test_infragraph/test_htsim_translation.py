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
from astra_server.infrastructure.htsim_topology import HTSimTopology
from infragraph.blueprints.fabrics.clos_fat_tree_fabric import ClosFatTreeFabric
from infragraph.blueprints.devices.generic_switch import Switch
from infragraph.blueprints.devices.server import Server
from infragraph import Component, InfrastructureEdge
from infragraph.infragraph_service import InfraGraphService
from astra_server.configuration_handler import ConfigurationHandler


def test_3tier_8host_1npu(infra_single_gpu_server_factory, infra_switch_factory):
    # infrastructure - infragraph
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "htsim"
    # load infrastructure and annotation?
    server = infra_single_gpu_server_factory()
    switch = infra_switch_factory(4)

    configuration.infragraph.infrastructure.name = "3tier-8host-1npu"
    configuration.infragraph.infrastructure.devices.append(server).append(switch)

    hosts = configuration.infragraph.infrastructure.instances.add(
        name="host", device=server.name, count=8
    )

    rack_switch = configuration.infragraph.infrastructure.instances.add(
        name="rack_switch", device=switch.name, count=4
    )
    pod_switch = configuration.infragraph.infrastructure.instances.add(
        name="pod_switch", device=switch.name, count=4
    )
    spine_switch = configuration.infragraph.infrastructure.instances.add(
        name="spine_switch", device=switch.name, count=2
    )

    rack_link = configuration.infragraph.infrastructure.links.add(
        name="rack-link",
        description="Link characteristics for connectivity between servers and rack switch",
    )
    rack_link.physical.bandwidth.gigabits_per_second = 100
    rack_link.physical.latency.ms = 0.005

    pod_link = configuration.infragraph.infrastructure.links.add(
        name="pod-link",
        description="Link characteristics for connectivity between rack switch and pod switch",
    )
    pod_link.physical.bandwidth.gigabits_per_second = 200
    pod_link.physical.latency.ms = 0.005

    spine_link = configuration.infragraph.infrastructure.links.add(
        name="spine-link",
        description="Link characteristics for connectivity between pod switch and spine switch",
    )
    spine_link.physical.bandwidth.gigabits_per_second = 400
    spine_link.physical.latency.ms = 0.005

    host_component = InfraGraphService.get_component(server, Component.NIC)
    switch_component = InfraGraphService.get_component(switch, Component.PORT)

    # link two host to one rack switch
    host_index = 0
    for idx in range(rack_switch.count):
        edge = configuration.infragraph.infrastructure.edges.add(
            scheme=InfrastructureEdge.ONE2ONE, link=rack_link.name  # type: ignore
        )
        edge.ep1.instance = f"{hosts.name}[{host_index}]"
        edge.ep1.component = host_component.name
        edge.ep2.instance = f"{rack_switch.name}[{idx}]"
        edge.ep2.component = f"{switch_component.name}[0]"
        host_index = host_index + 1
        edge = configuration.infragraph.infrastructure.edges.add(
            scheme=InfrastructureEdge.ONE2ONE, link=rack_link.name  # type: ignore
        )
        edge.ep1.instance = f"{hosts.name}[{host_index}]"
        edge.ep1.component = host_component.name
        edge.ep2.instance = f"{rack_switch.name}[{idx}]"
        edge.ep2.component = f"{switch_component.name}[1]"
        host_index = host_index + 1

    # tier0.0 and tier0.1 -> tier1.0 and tier1.1
    for i in [0, 1]:
        edge = configuration.infragraph.infrastructure.edges.add(
            scheme=InfrastructureEdge.ONE2ONE, link=pod_link.name  # type: ignore
        )
        edge.ep1.instance = f"{rack_switch.name}[{i}]"
        edge.ep1.component = f"{switch_component.name}[{host_component.count + 1}]"
        edge.ep2.instance = f"{pod_switch.name}[0]"
        edge.ep2.component = f"{switch_component.name}[{i}]"

        edge = configuration.infragraph.infrastructure.edges.add(
            scheme=InfrastructureEdge.ONE2ONE, link=pod_link.name  # type: ignore
        )
        edge.ep1.instance = f"{rack_switch.name}[{i}]"
        edge.ep1.component = f"{switch_component.name}[{host_component.count + 2}]"
        edge.ep2.instance = f"{pod_switch.name}[1]"
        edge.ep2.component = f"{switch_component.name}[{i}]"

    # tier0.2 and tier0.3 -> tier1.2 and tier1.3
    for i in [2, 3]:
        edge = configuration.infragraph.infrastructure.edges.add(
            scheme=InfrastructureEdge.ONE2ONE, link=pod_link.name  # type: ignore
        )
        edge.ep1.instance = f"{rack_switch.name}[{i}]"
        edge.ep1.component = f"{switch_component.name}[{host_component.count + 1}]"
        edge.ep2.instance = f"{pod_switch.name}[2]"
        edge.ep2.component = f"{switch_component.name}[{i - 2}]"

        edge = configuration.infragraph.infrastructure.edges.add(
            scheme=InfrastructureEdge.ONE2ONE, link=pod_link.name  # type: ignore
        )
        edge.ep1.instance = f"{rack_switch.name}[{i}]"
        edge.ep1.component = f"{switch_component.name}[{host_component.count + 2}]"
        edge.ep2.instance = f"{pod_switch.name}[3]"
        edge.ep2.component = f"{switch_component.name}[{i - 2}]"

    # link every pod switch to every spine switch
    pod_component_count = 2
    for spine_idx in range(spine_switch.count):
        for pod_idx in range(pod_switch.count):
            edge = configuration.infragraph.infrastructure.edges.add(
                scheme=InfrastructureEdge.ONE2ONE, link=spine_link.name  # type: ignore
            )
            edge.ep1.instance = f"{spine_switch.name}[{spine_idx}]"
            edge.ep1.component = f"{switch_component.name}[{pod_idx}]"
            edge.ep2.instance = f"{pod_switch.name}[{pod_idx}]"
            edge.ep2.component = f"{switch_component.name}[{pod_component_count}]"
        pod_component_count = pod_component_count + 1

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

    HTSimTopology.generate_topology(configuration)
    assert (
        configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.podsize
        == 4
    )
    assert (
        configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.nodes
        == 8
    )
    assert (
        configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tiers
        == 3
    )
    assert (
        configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.radix_down
        == 2
    )


def test_3tier_16host_1npu(infra_single_gpu_server_factory, infra_switch_factory):
    # infrastructure - infragraph
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "htsim"
    # load infrastructure and annotation?
    server = infra_single_gpu_server_factory()
    rack_switch_dev = infra_switch_factory(8)
    pod_switch_dev = infra_switch_factory(12)
    spine_switch_dev = infra_switch_factory(8)

    configuration.infragraph.infrastructure.name = "3tier-8host-1npu"
    configuration.infragraph.infrastructure.devices.append(server).append(
        rack_switch_dev
    ).append(pod_switch_dev).append(spine_switch_dev)

    hosts = configuration.infragraph.infrastructure.instances.add(
        name="host", device=server.name, count=16
    )

    rack_switch = configuration.infragraph.infrastructure.instances.add(
        name="rack_switch", device=rack_switch_dev.name, count=4
    )
    pod_switch = configuration.infragraph.infrastructure.instances.add(
        name="pod_switch", device=pod_switch_dev.name, count=2
    )
    spine_switch = configuration.infragraph.infrastructure.instances.add(
        name="spine_switch", device=spine_switch_dev.name, count=1
    )

    rack_link = configuration.infragraph.infrastructure.links.add(
        name="rack-link",
        description="Link characteristics for connectivity between servers and rack switch",
    )
    rack_link.physical.bandwidth.gigabits_per_second = 100
    rack_link.physical.latency.ms = 0.005

    pod_link = configuration.infragraph.infrastructure.links.add(
        name="pod-link",
        description="Link characteristics for connectivity between rack switch and pod switch",
    )
    pod_link.physical.bandwidth.gigabits_per_second = 200
    pod_link.physical.latency.ms = 0.005

    spine_link = configuration.infragraph.infrastructure.links.add(
        name="spine-link",
        description="Link characteristics for connectivity between pod switch and spine switch",
    )
    spine_link.physical.bandwidth.gigabits_per_second = 400
    spine_link.physical.latency.ms = 0.005

    host_component = InfraGraphService.get_component(server, Component.NIC)
    rack_switch_component = InfraGraphService.get_component(
        rack_switch_dev, Component.PORT
    )
    pod_switch_component = InfraGraphService.get_component(
        pod_switch_dev, Component.PORT
    )
    spine_switch_component = InfraGraphService.get_component(
        spine_switch_dev, Component.PORT
    )

    host_multiplier = 0
    # link two host to one rack switch
    for rack_index in range(rack_switch.count):
        for host_index in range(0, 4):
            edge = configuration.infragraph.infrastructure.edges.add(
                scheme=InfrastructureEdge.ONE2ONE, link=rack_link.name  # type: ignore
            )
            edge.ep1.instance = f"{hosts.name}[{host_index + host_multiplier}]"
            edge.ep1.component = f"{host_component.name}[0]"
            edge.ep2.instance = f"{rack_switch.name}[{rack_index}]"
            edge.ep2.component = f"{rack_switch_component.name}[{host_index}]"
        host_multiplier = host_multiplier + 4

    # tier0.0 and tier0.1 -> tier1.0 - 4 links each
    for rack_switch_index in [0, 1]:
        for index in range(0, 4):
            edge = configuration.infragraph.infrastructure.edges.add(
                scheme=InfrastructureEdge.ONE2ONE, link=pod_link.name  # type: ignore
            )
            edge.ep1.instance = f"{rack_switch.name}[{rack_switch_index}]"
            edge.ep1.component = f"{rack_switch_component.name}[{4 + index}]"
            edge.ep2.instance = f"{pod_switch.name}[0]"
            edge.ep2.component = (
                f"{pod_switch_component.name}[{index + rack_switch_index * 4}]"
            )

    # tier0.0 and tier0.1 -> tier1.0 - 4 links each
    for rack_switch_index in [2, 3]:
        for index in range(0, 4):
            edge = configuration.infragraph.infrastructure.edges.add(
                scheme=InfrastructureEdge.ONE2ONE, link=pod_link.name  # type: ignore
            )
            edge.ep1.instance = f"{rack_switch.name}[{rack_switch_index}]"
            edge.ep1.component = f"{rack_switch_component.name}[{4 + index}]"
            edge.ep2.instance = f"{pod_switch.name}[1]"
            edge.ep2.component = (
                f"{pod_switch_component.name}[{index + (rack_switch_index - 2) * 4}]"
            )

    # tier1.0 and tier1.1 -> tier2.0
    for index in range(0, 8):
        edge = configuration.infragraph.infrastructure.edges.add(
            scheme=InfrastructureEdge.ONE2ONE, link=spine_link.name  # type: ignore
        )
        if index < 4:
            edge.ep1.instance = f"{pod_switch.name}[{0}]"
            edge.ep1.component = f"{pod_switch_component.name}[{8 + index}]"
        else:
            edge.ep1.instance = f"{pod_switch.name}[{1}]"
            edge.ep1.component = f"{pod_switch_component.name}[{4 + index}]"

        edge.ep2.instance = f"{spine_switch.name}[0]"
        edge.ep2.component = f"{spine_switch_component.name}[{index}]"

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

    HTSimTopology.generate_topology(configuration)
    assert (
        configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.podsize
        == 8
    )
    assert (
        configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.nodes
        == 16
    )
    assert (
        configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tiers
        == 3
    )
    assert (
        configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.radix_down
        == 4
    )


def dump_yaml(clos_fabric, filename):
    import yaml

    with open(filename + ".yaml", "w") as file:
        data = clos_fabric.serialize("dict")
        yaml.dump(data, file, default_flow_style=False, indent=4)
    pass


def test_clos_fabric_2_tier():
    # infrastructure - infragraph
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "htsim"
    # load infrastructure and annotation?
    server = Server()
    switch = Switch(port_count=8)
    clos_fat_tree = ClosFatTreeFabric(switch, server, 2, [])
    # dump_yaml(clos_fat_tree, "clos_fabric")
    configuration.infragraph.infrastructure.deserialize(clos_fat_tree.serialize())

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

    HTSimTopology.generate_topology(configuration)
    configuration.network_backend.htsim.htsim_protocol.choice = "tcp"
    # ConfigurationHandler()._generate_htsim_topology(
    #     configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology,
    #     "htsim.topo",
    # )
    assert (
        configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.podsize
        == 16
    )
    assert (
        configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.nodes
        == 16
    )
    assert (
        configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tiers
        == 2
    )
    assert (
        configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.radix_down
        == 4
    )


def test_clos_fabric_3_tier():
    # infrastructure - infragraph
    configuration = astra_sim.Config()
    configuration.network_backend.choice = "htsim"
    # load infrastructure and annotation?
    server = Server()
    switch = Switch(port_count=8)
    clos_fat_tree = ClosFatTreeFabric(switch, server, 3, [])
    # dump_yaml(clos_fat_tree, "clos_fabric")
    configuration.infragraph.infrastructure.deserialize(clos_fat_tree.serialize())

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

    HTSimTopology.generate_topology(configuration)
    configuration.network_backend.htsim.htsim_protocol.choice = "tcp"
    # ConfigurationHandler()._generate_htsim_topology(
    #     configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology,
    #     "htsim.topo",
    # )
    assert (
        configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.podsize
        == 8
    )
    assert (
        configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.nodes
        == 64
    )
    assert (
        configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tiers
        == 3
    )
    assert (
        configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.radix_down
        == 4
    )
