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
from infragraph.infragraph_service import InfraGraphService
import grpc

if __package__ is None or __package__ == "":
    from errors import InfragraphError
    from infrastructure.infra_utils import Annotation, TimeUnit
    from infrastructure.analytical_topology import AnalyticalTopology

else:
    from astra_server.errors import InfragraphError
    from astra_server.infrastructure.infra_utils import Annotation, TimeUnit
    from astra_server.infrastructure.analytical_topology import AnalyticalTopology


class Tier:
    """
    Stores the Tier data for htsim fat tree topology
    """

    def __init__(self):
        self.downlink_speed_gbps = -1
        self.radix_up = -1
        self.radix_down = -1
        self.queue_up = -1
        self.queue_down = -1
        self.oversubscribed = -1
        self.bundle = -1
        self.switch_latency_ns = -1.0
        self.downlink_latency_ns = -1.0


class HTSimFatTree:
    """
    Class that helps in converting infragraph to htsim fat tree topology by using infragraph, the generated networkx graph and annotations
    """

    def __init__(
        self,
        configuration: astra_sim.Config,
    ):
        self.tier_device_instances = {
            "host": set(),
            "tier0": set(),
            "tier1": set(),
            "tier2": set(),
        }

        self.top_to_bottom_device_map = {}
        self.annotation = Annotation(configuration.infragraph.annotations)
        self.infragraph_service = InfraGraphService()
        self.infragraph_service.set_graph(
            configuration.infragraph.infrastructure.__str__()
        )
        # store the network graph
        self.graph = self.infragraph_service.get_networkx_graph()
        # self._print_graph()
        self._process_infra(configuration)

    def _print_graph(self):
        for node, attrs in self.graph.nodes(data=True):
            print(f"Node: {node}, Attributes: {attrs}")

        for u, v, attrs in self.graph.edges(data=True):
            print(f"Edge: ({u}, {v}), Attributes: {attrs}")

    def _process_infra(
        self,
        configuration: astra_sim.Config,
    ):
        # parse device
        # parse device instances
        # parse connections
        for device in configuration.infragraph.infrastructure.devices:
            self.annotation.add_device(device.name)
            for link in device.links:
                self.annotation.add_link(link)

        # add links
        for link in configuration.infragraph.infrastructure.links:
            self.annotation.add_link(link)

        for instance in configuration.infragraph.infrastructure.instances:
            self.annotation.add_device_instance(
                device_instance=instance.name, device_name=instance.device
            )
            for i in range(0, instance.count):
                self.annotation.add_device_instance(
                    device_instance=instance.name + "." + str(i),
                    device_name=instance.device,
                )

        self._get_host_instances(configuration.infragraph.infrastructure)
        self.parse_graph(configuration)

    def _get_host_instances(self, infrastructure: astra_sim.Infrastructure):
        # This fills the first level - hosts - all the instances
        # we will pass all the host instances and check for the upper tier

        for device_instance in infrastructure.instances:
            # get the type of device_instance
            device_name = self.annotation.instance_to_device_name[device_instance.name]
            if device_name in self.annotation.hosts:
                # so we got a host
                for i in range(0, device_instance.count):
                    self.tier_device_instances["host"].add(
                        device_instance.name + "." + str(i)
                    )

    def _edge_parser(self, source_key: str, destination_key: str):
        # source instances contain: host.0, host.1
        # here we need to get the next connection
        parsed_devices = set().union(*self.tier_device_instances.values())

        if len(self.tier_device_instances[source_key]) > 0:
            for source, destination, _ in self.graph.edges(data=True):
                source_split = source.split(".")
                destination_split = destination.split(".")
                source_device_index = source_split[0] + "." + source_split[1]
                destination_device_index = (
                    destination_split[0] + "." + destination_split[1]
                )

                if source_device_index != destination_device_index:
                    # two device are connected
                    if source_device_index in self.tier_device_instances[source_key]:
                        # check if destination device index is present in an tier
                        if (
                            destination_device_index
                            not in self.tier_device_instances[destination_key]
                            and destination_device_index not in parsed_devices
                        ):
                            self.tier_device_instances[destination_key].add(
                                destination_device_index
                            )
                        if (
                            destination_device_index
                            not in self.top_to_bottom_device_map
                        ):
                            self.top_to_bottom_device_map[
                                destination_device_index
                            ] = set()
                            self.top_to_bottom_device_map[destination_device_index].add(
                                source_device_index
                            )
                        else:
                            self.top_to_bottom_device_map[destination_device_index].add(
                                source_device_index
                            )

                    elif (
                        destination_device_index
                        in self.tier_device_instances[source_key]
                    ):
                        if (
                            source_device_index
                            not in self.tier_device_instances[destination_key]
                            and source_device_index not in parsed_devices
                        ):
                            self.tier_device_instances[destination_key].add(
                                source_device_index
                            )
                        # if source_device_index not in self.top_to_bottom_device_map:
                        #     self.top_to_bottom_device_map[source_device_index] = set()
                        #     self.top_to_bottom_device_map[source_device_index].add(destination_device_index)
                        # else:
                        #     self.top_to_bottom_device_map[source_device_index].add(destination_device_index)

    def _get_tier_information(self, up_tier: str, low_tier: str, mid_tier: str):
        # the expectation is that we get to see the devices placed in tiers and we will see if mid_tier single device is able to access either of them, we can count the data
        if (
            len(self.tier_device_instances[mid_tier]) < 0
        ):  # get the first device and check
            return None
        tier = Tier()
        tier.radix_up = 0
        tier.radix_down = 0
        tier.oversubscribed = 0

        up_tier_devices = set()
        if up_tier in self.tier_device_instances:
            up_tier_devices = self.tier_device_instances[up_tier]

        low_tier_devices = set()
        if low_tier in self.tier_device_instances:
            low_tier_devices = self.tier_device_instances[low_tier]

        current_tier_device_instance = list(self.tier_device_instances[mid_tier])[
            0
        ]  # get the first device instance and check
        # get the device too
        current_tier_device = self.annotation.instance_to_device_name[
            current_tier_device_instance
        ]
        # get the specification

        current_tier_device_spec = self.annotation.get_device_specification(
            current_tier_device
        )
        if len(current_tier_device_spec) == 0:
            raise InfragraphError(
                f"Device specification for {current_tier_device} not set",
                grpc.StatusCode.NOT_FOUND,
                404,
            )

        tier.queue_up = current_tier_device_spec["queue_up"]
        tier.queue_down = current_tier_device_spec["queue_down"]
        tier.switch_latency_ns = current_tier_device_spec["device_latency_ms"]

        downlink_device = ""
        for source, destination, attr in self.graph.edges(data=True):
            source_split = source.split(".")
            destination_split = destination.split(".")
            source_device_index = source_split[0] + "." + source_split[1]
            destination_device_index = destination_split[0] + "." + destination_split[1]

            if source_device_index == current_tier_device_instance:
                if destination_device_index in up_tier_devices:
                    tier.radix_up = tier.radix_up + 1
                elif destination_device_index in low_tier_devices:
                    tier.radix_down = tier.radix_down + 1
                    link = self.annotation.get_link_specification(attr["link"])
                    tier.downlink_speed_gbps = link["bandwidth"].to_str()
                    tier.downlink_latency_ns = link["latency"].to_str(
                        TimeUnit.NANOSECOND
                    )
                    if downlink_device == "":
                        downlink_device = destination_device_index

            elif destination_device_index == current_tier_device_instance:
                if source_device_index in up_tier_devices:
                    tier.radix_up = tier.radix_up + 1
                elif source_device_index in low_tier_devices:
                    tier.radix_down = tier.radix_down + 1
                    link = self.annotation.get_link_specification(attr["link"])
                    tier.downlink_speed_gbps = link["bandwidth"].to_str()
                    tier.downlink_latency_ns = link["latency"].to_str(
                        TimeUnit.NANOSECOND
                    )
                    if downlink_device == "":
                        downlink_device = source_device_index

            if (
                downlink_device == destination_device_index
                or downlink_device == source_device_index
            ):
                tier.bundle = tier.bundle + 1

        if tier.radix_up != 0:
            tier.oversubscribed = tier.radix_down // tier.radix_up
        return tier

    def _get_pod_size(self):

        # get a tier2 device:
        if "tier1" not in self.tier_device_instances:
            raise InfragraphError("tier1 is missing", grpc.StatusCode.NOT_FOUND, 404)

        tier2_device = list(self.tier_device_instances["tier1"])[0]

        # use the top_to_bottom_map to parse and get the devices
        stack = [tier2_device]
        pod_size = 0
        while stack:
            device = stack.pop()
            if device in self.top_to_bottom_device_map:
                stack.extend(list(self.top_to_bottom_device_map[device]))
            else:
                pod_size = pod_size + 1
        return pod_size

    def parse_graph(self, configuration: astra_sim.Config):
        """
        Function that parses the networkx graph and generates relation between various tiers of the topology
        """
        if len(self.annotation.hosts) > 1:
            raise InfragraphError(
                "htsim fat tree topology can have a single type of host",
                grpc.StatusCode.INVALID_ARGUMENT,
                400,
            )

        # get all the hosts
        self._edge_parser("host", "tier0")
        self._edge_parser("tier0", "tier1")
        self._edge_parser("tier1", "tier2")

        # check if gpus matter here?
        configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.nodes = len(
            self.tier_device_instances["host"]
        )
        # create for tier0
        tier0 = self._get_tier_information(
            low_tier="host", mid_tier="tier0", up_tier="tier1"
        )
        if tier0 is not None:
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.downlink_speed_gbps = (
                tier0.downlink_speed_gbps
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.radix_up = (
                tier0.radix_up
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.radix_down = (
                tier0.radix_down
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.queue_up = (
                tier0.queue_up
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.queue_down = (
                tier0.queue_down
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.oversubscribed = (
                tier0.oversubscribed
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.bundle = (
                tier0.bundle
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.switch_latency_ns = (
                tier0.switch_latency_ns
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.downlink_latency_ns = (
                tier0.downlink_latency_ns
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tiers = (
                1
            )
        tier1 = self._get_tier_information(
            low_tier="tier0", mid_tier="tier1", up_tier="tier2"
        )
        if tier1 is not None:
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_1.downlink_speed_gbps = (
                tier1.downlink_speed_gbps
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_1.radix_up = (
                tier1.radix_up
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_1.radix_down = (
                tier1.radix_down
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_1.queue_up = (
                tier1.queue_up
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_1.queue_down = (
                tier1.queue_down
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_1.oversubscribed = (
                tier1.oversubscribed
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_1.bundle = (
                tier1.bundle
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_1.switch_latency_ns = (
                tier1.switch_latency_ns
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_1.downlink_latency_ns = (
                tier1.downlink_latency_ns
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tiers = (
                2
            )
        tier2 = self._get_tier_information(
            low_tier="tier1", mid_tier="tier2", up_tier="tier3"
        )
        if tier2 is not None:
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_2.downlink_speed_gbps = (
                tier2.downlink_speed_gbps
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_2.radix_down = (
                tier2.radix_down
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_2.queue_down = (
                tier2.queue_down
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_2.oversubscribed = (
                tier2.oversubscribed
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_2.bundle = (
                tier2.bundle
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_2.switch_latency_ns = (
                tier2.switch_latency_ns
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_2.downlink_latency_ns = (
                tier2.downlink_latency_ns
            )
            configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tiers = (
                3
            )

        configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.podsize = (
            self._get_pod_size()
        )


class HTSimTopology:
    """
    Class that acts as a switch to generate htsim topology from infragraph
    """

    @staticmethod
    def generate_topology(configuration: astra_sim.Config):
        """
        Generates htsim topology from infragraph and annotations
        """
        # need a switch for fat tree, dragonfly and so on here the configuration will have the topology choice

        # TODO: a switch is required between various topologies
        HTSimFatTree(configuration)

        # analytical topology generation here
        infrastructure = configuration.infragraph.infrastructure
        annotations = configuration.infragraph.annotations
        topology = AnalyticalTopology(infrastructure, annotations)
        if topology.analytical_1d is not None:
            configuration.network_backend.htsim.topology.network_topology_configuration.network.add(
                topology=topology.analytical_1d.topology,  # type: ignore
                npus_count=topology.analytical_1d.node_count,
                bandwidth=topology.analytical_1d.bandwidth,
                latency=topology.analytical_1d.latency,
            )
        if topology.analytical_2d is not None:
            configuration.network_backend.htsim.topology.network_topology_configuration.network.add(
                topology=topology.analytical_2d.topology,  # type: ignore
                npus_count=topology.analytical_2d.node_count,
                bandwidth=topology.analytical_2d.bandwidth,
                latency=topology.analytical_2d.latency,
            )
        if topology.analytical_3d is not None:
            configuration.network_backend.htsim.topology.network_topology_configuration.network.add(
                topology=topology.analytical_3d.topology,  # type: ignore
                npus_count=topology.analytical_3d.node_count,
                bandwidth=topology.analytical_3d.bandwidth,
                latency=topology.analytical_3d.latency,
            )
