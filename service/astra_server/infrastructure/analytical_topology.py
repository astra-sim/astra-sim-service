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

from dataclasses import dataclass
import networkx as nx
import grpc

import astra_sim_sdk.astra_sim_sdk as astra_sim
from infragraph.infragraph_service import InfraGraphService


if __package__ is None or __package__ == "":
    from errors import InfragraphError
    from infrastructure.infra_utils import (
        Annotation,
        NetworkxUtils,
        TransferUnit,
        TimeUnit,
    )
else:
    from astra_server.errors import InfragraphError
    from astra_server.infrastructure.infra_utils import (
        Annotation,
        NetworkxUtils,
        TransferUnit,
        TimeUnit,
    )


@dataclass
class AnalyticalNetworkConfig:
    """
    Class that holds the analytical network configuration parameters
    """

    FULLY_CONNECTED = "fullyconnected"
    SWITCH = "switch"
    RING = "ring"
    UNDEFINED = "undefined"

    def __init__(
        self, topology="undefined", node_count=-1, bandwidth=-1.0, latency=-1.0
    ):
        self.topology = topology
        self.node_count = node_count
        self.bandwidth = bandwidth
        self.latency = latency


class AnalyticalTopology:
    """
    Class that helps in converting infragraph to analytical topology by using infragraph, the generated networkx graph and annotations
    """

    def __init__(
        self,
        infrastructure: astra_sim.Infrastructure,
        annotations: astra_sim.Annotations,
    ):
        self.analytical_1d = None
        self.analytical_2d = None
        self.analytical_3d = None
        self.total_npu_nodes = 0
        self.annotation = Annotation(annotations)
        self.infragraph_service = InfraGraphService()
        self.infragraph_service.set_graph(infrastructure.__str__())
        # store the network graph
        self.graph = self.infragraph_service.get_networkx_graph()
        # self._print_graph()
        self._process_infra(infrastructure)

    def _print_graph(self):
        for node, attrs in self.graph.nodes(data=True):
            print(f"Node: {node}, Attributes: {attrs}")

        for u, v, attrs in self.graph.edges(data=True):
            print(f"Edge: ({u}, {v}), Attributes: {attrs}")

    @staticmethod
    def get_edge_link(graph, edge1="", edge2=""):
        """
        Static method to get the link between two edges
        """
        edges = list(graph.edges)
        if edge1 != "":
            ep1 = edge1
        else:
            ep1 = edges[0]
        if edge2 != "":
            ep2 = edge2
        else:
            ep2 = edges[1]
        return graph.edges[ep1, ep2].get("link", "")

    def _process_host(self, host_instance: str):
        # set the first dimension:
        self.analytical_1d = AnalyticalNetworkConfig()
        # here we parse the npu
        instance_name = host_instance.split(".")[0]
        instance_index = host_instance.split(".")[1]
        npu_nodes = NetworkxUtils.get_component_node_from_type_and_instance(
            self.infragraph_service, "xpu", instance_name, int(instance_index)
        )

        # homogenous topology with a single host type
        if len(npu_nodes) > 1:
            self.analytical_1d.node_count = len(npu_nodes)

            # check for full connection?
            subgraph = self.graph.subgraph(npu_nodes)
            n = len(npu_nodes)
            expected_edges = n * (n - 1) // 2
            if subgraph.number_of_edges() == expected_edges:
                self.analytical_1d.topology = AnalyticalNetworkConfig.FULLY_CONNECTED
                link_name = AnalyticalTopology.get_edge_link(graph=subgraph)
                if link_name == "":
                    raise InfragraphError(
                        "link not specified between npus",
                        grpc.StatusCode.NOT_FOUND,
                        404,
                    )
                # from annotations get the attributes
                link_specification = self.annotation.get_link_specification(link_name)
                self.analytical_1d.bandwidth = link_specification[
                    "bandwidth"
                ].to_transfer_unit(TransferUnit.GIGABYTES_PER_SECOND)
                self.analytical_1d.latency = link_specification["latency"].to_time_unit(
                    TimeUnit.NANOSECOND
                )

            else:
                # check for ring?
                subgraph = self.graph.subgraph(npu_nodes)
                cycles = nx.cycle_basis(subgraph)  # For undirected graphs
                # Check if any cycle covers all nodes
                is_ring = any(
                    set(cycle) == set(npu_nodes) and len(cycle) == len(npu_nodes)
                    for cycle in cycles
                )
                if is_ring:
                    self.analytical_1d.topology = AnalyticalNetworkConfig.RING
                    link_name = AnalyticalTopology.get_edge_link(graph=subgraph)
                    if link_name == "":
                        raise InfragraphError(
                            "link not specified between npus",
                            grpc.StatusCode.NOT_FOUND,
                            404,
                        )
                    # from annotations get the attributes
                    link_specification = self.annotation.get_link_specification(
                        link_name
                    )
                    self.analytical_1d.bandwidth = link_specification[
                        "bandwidth"
                    ].to_transfer_unit(TransferUnit.GIGABYTES_PER_SECOND)
                    self.analytical_1d.latency = link_specification[
                        "latency"
                    ].to_time_unit(TimeUnit.NANOSECOND)
                else:
                    switch_nodes = (
                        NetworkxUtils.get_component_node_from_type_and_instance(
                            self.infragraph_service,
                            "switch",
                            instance_name,
                            int(instance_index),
                        )
                    )
                    for switch in switch_nodes:
                        if (
                            len(
                                NetworkxUtils.get_neighbour_nodes_for_component_type(
                                    self.graph, switch, "xpu"
                                )
                            )
                            > 1
                        ):
                            # if more than 1 npu is connected the topology is a switch
                            self.analytical_1d.topology = AnalyticalNetworkConfig.SWITCH
                            link_name = AnalyticalTopology.get_edge_link(
                                graph=self.graph, edge1=switch, edge2=npu_nodes[0]
                            )
                            if link_name == "":
                                raise InfragraphError(
                                    "link not specified between npus",
                                    grpc.StatusCode.NOT_FOUND,
                                    404,
                                )
                            # from annotations get the attributes
                            link_specification = self.annotation.get_link_specification(
                                link_name
                            )
                            self.analytical_1d.bandwidth = link_specification[
                                "bandwidth"
                            ].to_transfer_unit(TransferUnit.GIGABYTES_PER_SECOND)
                            self.analytical_1d.latency = link_specification[
                                "latency"
                            ].to_time_unit(TimeUnit.NANOSECOND)
                            break
        else:
            self.analytical_1d = None

    def _process_rack(self, host_instance: str):
        tor_instance = ""
        rack_downlink_name = ""
        host_split = host_instance.split(".")
        for source, destination, attrs in self.graph.edges(data=True):
            source_split = source.split(".")
            destination_split = destination.split(".")
            source_instance = source_split[0] + "." + source_split[1]
            destination_instance = destination_split[0] + "." + destination_split[1]

            if (
                source_instance == host_instance
                and destination_instance != host_instance
                and destination_split[0] != host_split[0]
            ):
                tor_instance = destination_instance
                rack_downlink_name = attrs["link"]
                break
            elif (
                destination_instance == host_instance
                and source_instance != host_instance
                and source_split[0] != host_split[0]
            ):
                tor_instance = source_instance
                rack_downlink_name = attrs["link"]
                break
        # reverse parse and get the rack uplink data?
        if tor_instance == "":
            # return as tor instance is not present
            self.analytical_2d = None
            self.analytical_3d = None
            return

        # now get all the connections of tor_instance to host

        rack_uplink_name = ""
        rack_downlink_nodes = 0
        for source, destination, attrs in self.graph.edges(data=True):
            source_split = source.split(".")
            destination_split = destination.split(".")
            source_instance = source_split[0] + "." + source_split[1]
            destination_instance = destination_split[0] + "." + destination_split[1]

            if (
                rack_uplink_name == ""
                and source_instance == tor_instance
                and destination_instance
                != tor_instance  # we do not want the destination to be the same switch
                and destination_instance != host_instance
                and destination_split[0]
                != host_split  # we do not want the destination to be a host
            ):
                rack_uplink_name = attrs["link"]

            elif (
                rack_uplink_name == ""
                and destination_instance == tor_instance
                and source_instance != tor_instance
                and source_instance != host_instance
                and destination_split[0] != host_split
            ):
                rack_uplink_name = attrs["link"]  # we just want the link

            # here check that for the tor_instance how many hosts are connected
            if (
                source_instance == tor_instance
                and destination_instance != tor_instance
                and destination_split[0] != host_split
            ):
                rack_downlink_nodes = rack_downlink_nodes + 1
            elif (
                destination_instance == tor_instance
                and source_instance != tor_instance
                and source_split[0] != host_split
            ):
                rack_downlink_nodes = rack_downlink_nodes + 1

        if rack_downlink_name == "":
            raise InfragraphError(
                "rack to host link is not defined", grpc.StatusCode.NOT_FOUND, 404
            )

        # we get the downlink nodes
        if self.analytical_1d is None:
            # if none then set to 1d
            self.analytical_1d = AnalyticalNetworkConfig()
            self.analytical_1d.topology = AnalyticalNetworkConfig.SWITCH
            self.analytical_1d.node_count = rack_downlink_nodes
            # from annotations get the attributes
            link_specification = self.annotation.get_link_specification(
                rack_downlink_name
            )
            self.analytical_1d.bandwidth = link_specification[
                "bandwidth"
            ].to_transfer_unit(TransferUnit.GIGABYTES_PER_SECOND)
            self.analytical_1d.latency = link_specification["latency"].to_time_unit(
                TimeUnit.NANOSECOND
            )

            if rack_uplink_name != "":
                # set the upper level
                if self.total_npu_nodes // self.analytical_1d.node_count > 1:
                    self.analytical_2d = AnalyticalNetworkConfig()
                    self.analytical_2d.topology = (
                        AnalyticalNetworkConfig.SWITCH
                    )  # assuming its a CLOS Tier and Dragonfly
                    self.analytical_2d.node_count = (
                        self.total_npu_nodes // self.analytical_1d.node_count
                    )
                    link_specification = self.annotation.get_link_specification(
                        rack_uplink_name
                    )
                    self.analytical_2d.bandwidth = link_specification[
                        "bandwidth"
                    ].to_transfer_unit(TransferUnit.GIGABYTES_PER_SECOND)
                    self.analytical_2d.latency = link_specification[
                        "latency"
                    ].to_time_unit(TimeUnit.NANOSECOND)
        else:
            # the 1d topo is present
            if self.total_npu_nodes > rack_downlink_nodes:  # multiple racks are present
                # rack can be connected to a host with same number of nics?
                if rack_downlink_nodes // self.analytical_1d.node_count > 1:
                    self.analytical_2d = AnalyticalNetworkConfig()
                    self.analytical_2d.topology = (
                        AnalyticalNetworkConfig.SWITCH
                    )  # assuming its a CLOS Tier and Dragonfly
                    self.analytical_2d.node_count = (
                        rack_downlink_nodes // self.analytical_1d.node_count
                    )
                    link_specification = self.annotation.get_link_specification(
                        rack_downlink_name
                    )
                    self.analytical_2d.bandwidth = link_specification[
                        "bandwidth"
                    ].to_transfer_unit(TransferUnit.GIGABYTES_PER_SECOND)
                    self.analytical_2d.latency = link_specification[
                        "latency"
                    ].to_time_unit(TimeUnit.NANOSECOND)
                    if rack_uplink_name != "":  # a third layer exists
                        # set the upper level
                        if self.total_npu_nodes // self.analytical_2d.node_count > 1:
                            self.analytical_3d = AnalyticalNetworkConfig()
                            self.analytical_3d.topology = (
                                AnalyticalNetworkConfig.SWITCH
                            )  # assuming its a CLOS Tier and Dragonfly
                            self.analytical_3d.node_count = (
                                self.total_npu_nodes
                                // self.analytical_2d.node_count
                                // self.analytical_3d.node_count
                            )
                            link_specification = self.annotation.get_link_specification(
                                rack_uplink_name
                            )
                            self.analytical_3d.bandwidth = link_specification[
                                "bandwidth"
                            ].to_transfer_unit(TransferUnit.GIGABYTES_PER_SECOND)
                            self.analytical_3d.latency = link_specification[
                                "latency"
                            ].to_time_unit(TimeUnit.NANOSECOND)

    def _process_infra(self, infrastructure: astra_sim.Infrastructure):
        for device in infrastructure.devices:
            self.annotation.add_device(device.name)
            for link in device.links:
                self.annotation.add_link(link)

        # add links
        for link in infrastructure.links:
            self.annotation.add_link(link)

        host_instance = ""
        for instance in infrastructure.instances:
            self.annotation.add_device_instance(
                device_instance=instance.name, device_name=instance.device
            )
            for i in range(0, instance.count):
                self.annotation.add_device_instance(
                    device_instance=instance.name + "." + str(i),
                    device_name=instance.device,
                )
                if instance.device in self.annotation.hosts:
                    npu_nodes = NetworkxUtils.get_component_node_from_type_and_instance(
                        self.infragraph_service, "xpu", instance.name, i
                    )
                    self.total_npu_nodes = self.total_npu_nodes + len(npu_nodes)
            if host_instance == "":
                device_name = self.annotation.instance_to_device_name[instance.name]
                if device_name in self.annotation.hosts:
                    host_instance = instance.name + ".0"  # the first instance of host

        if host_instance == "":
            raise InfragraphError(
                "host instance is not set. This is required to form the first dimension",
                grpc.StatusCode.NOT_FOUND,
                404,
            )

        self._process_host(host_instance=host_instance)
        self._process_rack(host_instance=host_instance)

    @staticmethod
    def generate_topology(configuration: astra_sim.Config):
        """
        Generates anaytical topology from infragraph and annotations
        """
        infrastructure = configuration.infragraph.infrastructure
        annotations = configuration.infragraph.annotations
        topology = AnalyticalTopology(infrastructure, annotations)
        if configuration.network_backend.choice == "analytical_congestion_aware":
            if topology.analytical_1d is not None:
                configuration.network_backend.analytical_congestion_aware.topology.network.add(
                    topology=topology.analytical_1d.topology,  # type: ignore
                    npus_count=topology.analytical_1d.node_count,
                    bandwidth=topology.analytical_1d.bandwidth,
                    latency=topology.analytical_1d.latency,
                )
            if topology.analytical_2d is not None:
                configuration.network_backend.analytical_congestion_aware.topology.network.add(
                    topology=topology.analytical_2d.topology,  # type: ignore
                    npus_count=topology.analytical_2d.node_count,
                    bandwidth=topology.analytical_2d.bandwidth,
                    latency=topology.analytical_2d.latency,
                )
            if topology.analytical_3d is not None:
                configuration.network_backend.analytical_congestion_aware.topology.network.add(
                    topology=topology.analytical_3d.topology,  # type: ignore
                    npus_count=topology.analytical_3d.node_count,
                    bandwidth=topology.analytical_3d.bandwidth,
                    latency=topology.analytical_3d.latency,
                )
        if configuration.network_backend.choice == "analytical_congestion_unaware":
            if topology.analytical_1d is not None:
                configuration.network_backend.analytical_congestion_unaware.topology.network.add(
                    topology=topology.analytical_1d.topology,  # type: ignore
                    npus_count=topology.analytical_1d.node_count,
                    bandwidth=topology.analytical_1d.bandwidth,
                    latency=topology.analytical_1d.latency,
                )
            if topology.analytical_2d is not None:
                configuration.network_backend.analytical_congestion_unaware.topology.network.add(
                    topology=topology.analytical_2d.topology,  # type: ignore
                    npus_count=topology.analytical_2d.node_count,
                    bandwidth=topology.analytical_2d.bandwidth,
                    latency=topology.analytical_2d.latency,
                )
            if topology.analytical_3d is not None:
                configuration.network_backend.analytical_congestion_unaware.topology.network.add(
                    topology=topology.analytical_3d.topology,  # type: ignore
                    npus_count=topology.analytical_3d.node_count,
                    bandwidth=topology.analytical_3d.bandwidth,
                    latency=topology.analytical_3d.latency,
                )
