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
from typing import List, Tuple, Set
from itertools import product
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


class DeviceTopologyDetector:
    """
    Detects network topologies from NetworkX subgraph.
    Supports RING, FULL_MESH, and SWITCH topologies with dimensional multiplication.
    """

    def __init__(
        self,
        graph: nx.Graph,
        npu_nodes: List[str],
        switch_nodes: List[str],
        npu_bandwidth: float,
        npu_latency: float,
        switch_bandwidth: float,
        switch_latency: float,
        detection_level: int = 3,
    ):
        self.graph = graph
        self.nodes = sorted(npu_nodes, key=lambda x: int(x.split(".")[1]))
        self.switches = sorted(switch_nodes, key=lambda x: int(x.split(".")[1]))
        self.node_prefix = ""
        if len(self.nodes) > 0:
            self.node_prefix = self.nodes[0].rsplit(".", 1)[0]
        self.switch_prefix = ""
        if len(self.switches) > 0:
            self.switch_prefix = self.switches[0].rsplit(".", 1)[0]
        self.npu_bandwidth = npu_bandwidth
        self.npu_latency = npu_latency
        self.switch_bandwidth = switch_bandwidth
        self.switch_latency = switch_latency
        self.detection_level = detection_level

    def _get_node_neighbors(
        self, node: str, exclude_switches: bool = False
    ) -> Set[str]:
        """Get neighbors of a node, optionally excluding switches."""
        neighbors = set(self.graph.neighbors(node))
        if exclude_switches:
            neighbors = {
                n
                for n in neighbors
                if n.startswith(self.node_prefix) and self.node_prefix != ""
            }
        return neighbors

    def _get_direct_node_edges(self, nodes: List[str]) -> Set[Tuple[str, str]]:
        """Get all direct node-to-node edges (excluding edges through switches)."""
        edges = set()
        for u, v in self.graph.edges():
            if u in nodes and v in nodes:
                if (
                    u.startswith(self.node_prefix)
                    and v.startswith(self.node_prefix)
                    and self.node_prefix != ""
                ):
                    edges.add((min(u, v), max(u, v)))
        return edges

    def _is_ring(self, node_subset: List[str]) -> bool:
        """Check if a subset of nodes forms a ring topology."""
        if len(node_subset) < 2:
            return False

        # 2-node case: a degenerate ring (two nodes connected by a single edge)
        if len(node_subset) == 2:
            edges = self._get_direct_node_edges(node_subset)
            return len(edges) == 1

        # Get only direct node-to-node connections
        edges = self._get_direct_node_edges(node_subset)

        # Create subgraph with only these edges
        G = nx.Graph()
        G.add_nodes_from(node_subset)
        G.add_edges_from(edges)

        # Each node should have exactly 2 neighbors
        for node in node_subset:
            if G.degree(node) != 2:
                return False

        # Should form a single cycle
        try:
            cycle = nx.find_cycle(G)
            cycle_nodes = set()
            for u, v in cycle:
                cycle_nodes.add(u)
                cycle_nodes.add(v)
            return len(cycle_nodes) == len(node_subset)
        except nx.NetworkXNoCycle:
            return False

    def _get_topology_priority_order(self):
        """Return topology types in priority order for dimensional decomposition."""
        # RING first: for small groups (K2, K3), RING and FULL_MESH are equivalent;
        # preferring RING avoids misclassifying ring dimensions as FULL_MESH.
        # For n>=4, RING and FULL_MESH are mutually exclusive so order doesn't matter.
        return [
            AnalyticalNetworkConfig.RING,
            AnalyticalNetworkConfig.FULLY_CONNECTED,
            AnalyticalNetworkConfig.SWITCH,
        ]

    def _is_full_mesh(self, node_subset: List[str]) -> bool:
        """Check if a subset of nodes forms a full mesh topology."""
        if len(node_subset) < 2:
            return False

        # Get only direct node-to-node connections
        edges = self._get_direct_node_edges(node_subset)

        # In a full mesh, we need n*(n-1)/2 edges
        n = len(node_subset)
        expected_edges = n * (n - 1) // 2

        if len(edges) != expected_edges:
            return False

        # Each node should be connected to all others
        G = nx.Graph()
        G.add_nodes_from(node_subset)
        G.add_edges_from(edges)

        for node in node_subset:
            if G.degree(node) != n - 1:
                return False

        return True

    def _is_switch_connected(self, node_subset: List[str]) -> bool:
        """Check if nodes in subset are all connected through the same switch(es)."""
        if len(node_subset) < 2:
            return False

        # Nodes should NOT have direct connections to each other
        direct_edges = self._get_direct_node_edges(node_subset)
        if len(direct_edges) > 0:
            return False

        for node in node_subset:
            neighbors = set(self.graph.neighbors(node))
            node_switches = {
                n
                for n in neighbors
                if n.startswith(self.switch_prefix) and self.switch_prefix != ""
            }

            if not node_switches:
                return False

            # Check connectivity through switch-only infrastructure:
            # Build a subgraph containing only the node_subset and all switches,
            # then check if all nodes in the subset are connected.
            node_set = set(node_subset)
            switch_set = set(self.switches)
            relevant_nodes = node_set | switch_set
            subgraph = self.graph.subgraph(relevant_nodes)

            # All nodes in the subset must be in the same connected component
            try:
                for i in range(1, len(node_subset)):
                    if not nx.has_path(subgraph, node_subset[0], node_subset[i]):
                        return False
            except nx.NodeNotFound:
                return False

        return True

    def _find_divisors(self, n: int) -> List[int]:
        """Find all divisors of n greater than 1."""
        divisors = []
        for i in range(2, n + 1):
            if n % i == 0:
                divisors.append(i)
        return divisors

    def _partition_by_dimension(self, nodes, dim1, dim2):
        total = len(nodes)
        if dim1 * dim2 != total:
            return [], []

        # Map node index to 2D coordinate
        coord_map = {}
        for idx, node in enumerate(nodes):
            x = idx % dim1
            y = idx // dim1
            coord_map[node] = (x, y)

        dim1_groups = []
        for y in range(dim2):
            group = [n for n, (x, yy) in coord_map.items() if yy == y]
            dim1_groups.append(group)

        dim2_groups = []
        for x in range(dim1):
            group = [n for n, (xx, y) in coord_map.items() if xx == x]
            dim2_groups.append(group)

        return dim1_groups, dim2_groups

    def _partition_by_3d(self, nodes, dim1, dim2, dim3):
        total = len(nodes)
        if dim1 * dim2 * dim3 != total:
            return [], [], []

        coord_map = {}
        for idx, node in enumerate(nodes):
            x = idx % dim1
            y = (idx // dim1) % dim2
            z = idx // (dim1 * dim2)
            coord_map[node] = (x, y, z)

        dim1_groups = []
        for y in range(dim2):
            for z in range(dim3):
                group = [
                    n for n, (x, yy, zz) in coord_map.items() if yy == y and zz == z
                ]
                dim1_groups.append(group)

        dim2_groups = []
        for x in range(dim1):
            for z in range(dim3):
                group = [
                    n for n, (xx, y, zz) in coord_map.items() if xx == x and zz == z
                ]
                dim2_groups.append(group)

        dim3_groups = []
        for x in range(dim1):
            for y in range(dim2):
                group = [
                    n for n, (xx, yy, z) in coord_map.items() if xx == x and yy == y
                ]
                dim3_groups.append(group)

        return dim1_groups, dim2_groups, dim3_groups

    def _check_topology_type(self, node_group: List[str], topo_type: str) -> bool:
        """Check if a node group matches the specified topology type."""
        if len(node_group) < 2:
            return False

        if topo_type == AnalyticalNetworkConfig.RING:
            return self._is_ring(node_group)
        elif topo_type == AnalyticalNetworkConfig.FULLY_CONNECTED:
            return self._is_full_mesh(node_group)
        elif topo_type == AnalyticalNetworkConfig.SWITCH:
            return self._is_switch_connected(node_group)
        return False

    def _check_2d_structure(
        self, nodes: List[str], dim1: int, dim2: int, topo1: str, topo2: str
    ) -> bool:
        """
        Check if nodes form a 2D dimensional structure.
        dim1 x dim2 = total nodes
        """
        dim1_groups, dim2_groups = self._partition_by_dimension(nodes, dim1, dim2)

        if not dim1_groups or not dim2_groups:
            return False

        # Check all dimension 1 groups match topology 1
        for group in dim1_groups:
            if not self._check_topology_type(group, topo1):
                return False

        # Check all dimension 2 groups match topology 2
        for group in dim2_groups:
            if not self._check_topology_type(group, topo2):
                return False

        return True

    def _check_3d_structure(
        self,
        nodes: List[str],
        dim1: int,
        dim2: int,
        dim3: int,
        topo1: str,
        topo2: str,
        topo3: str,
    ) -> bool:
        """
        Check if nodes form a 3D dimensional structure.
        dim1 x dim2 x dim3 = total nodes
        """
        dim1_groups, dim2_groups, dim3_groups = self._partition_by_3d(
            nodes, dim1, dim2, dim3
        )

        if not dim1_groups or not dim2_groups or not dim3_groups:
            return False

        # Check all dimension 1 groups match topology 1
        for group in dim1_groups:
            if not self._check_topology_type(group, topo1):
                return False

        # Check all dimension 2 groups match topology 2
        for group in dim2_groups:
            if not self._check_topology_type(group, topo2):
                return False

        # Check all dimension 3 groups match topology 3
        for group in dim3_groups:
            if not self._check_topology_type(group, topo3):
                return False

        return True

    def _has_switch_substructure(self) -> bool:
        """Check if any switch connects a proper subset of nodes,
        indicating a multi-dimensional switch structure."""
        node_set = set(self.nodes)
        for switch in self.switches:
            switch_neighbors = {
                n
                for n in self.graph.neighbors(switch)
                if n.startswith(self.node_prefix) and self.node_prefix != ""
            }
            if switch_neighbors and switch_neighbors < node_set:
                return True
        return False

    def _detect_single_topology(self) -> List[AnalyticalNetworkConfig]:
        """Detect single topology (1D)."""
        if self._is_ring(self.nodes):
            return [
                AnalyticalNetworkConfig(
                    AnalyticalNetworkConfig.RING,
                    len(self.nodes),
                    self.npu_bandwidth,
                    self.npu_latency,
                )
            ]
        elif self._is_full_mesh(self.nodes):
            return [
                AnalyticalNetworkConfig(
                    AnalyticalNetworkConfig.FULLY_CONNECTED,
                    len(self.nodes),
                    self.npu_bandwidth,
                    self.npu_latency,
                )
            ]
        elif self._is_switch_connected(self.nodes):
            # If switches create proper subgroups, skip 1D — likely multi-dimensional
            if not self._has_switch_substructure():
                return [
                    AnalyticalNetworkConfig(
                        AnalyticalNetworkConfig.SWITCH,
                        len(self.nodes),
                        self.switch_bandwidth,
                        self.switch_latency,
                    )
                ]

        return []

    def _detect_2d_topology(self) -> List[AnalyticalNetworkConfig]:
        """Detect 2D dimensional topology."""
        total = len(self.nodes)
        divisors = self._find_divisors(total)

        # Get topology priority order
        topologies = self._get_topology_priority_order()

        # Try all dimension combinations, prioritizing larger first dimension
        tested_combinations = set()

        for dim1 in reversed(divisors):  # Try larger dimensions first
            dim2 = total // dim1
            if dim2 < 2 or dim1 < 2:  # Need at least 2 nodes per dimension
                continue

            # Skip if we've already tested this combination (avoid duplicates)
            combo_key = tuple(sorted([dim1, dim2]))
            if combo_key in tested_combinations:
                continue
            tested_combinations.add(combo_key)

            for topo1, topo2 in product(topologies, topologies):
                # Check if the structure matches
                if self._check_2d_structure(self.nodes, dim1, dim2, topo1, topo2):
                    analytical_dimensions = []
                    for topo, dim in zip([topo1, topo2], [dim1, dim2]):
                        bandwidth = self.npu_bandwidth
                        latency = self.npu_latency
                        if topo == AnalyticalNetworkConfig.SWITCH:
                            bandwidth = self.switch_bandwidth
                            latency = self.switch_latency
                        analytical_dimensions.append(
                            AnalyticalNetworkConfig(topo, dim, bandwidth, latency)
                        )
                    return analytical_dimensions
        return []

    def _detect_3d_topology(self) -> List[AnalyticalNetworkConfig]:
        """Detect 3D dimensional topology."""
        total = len(self.nodes)
        divisors = self._find_divisors(total)

        topologies = self._get_topology_priority_order()

        tested_combinations = set()

        for dim1 in reversed(divisors):
            remaining = total // dim1
            for dim2 in reversed(self._find_divisors(remaining)):
                dim3 = remaining // dim2
                if dim3 < 2 or dim2 < 2 or dim1 < 2:
                    continue

                # Skip duplicates
                combo_key = tuple(sorted([dim1, dim2, dim3]))
                if combo_key in tested_combinations:
                    continue
                tested_combinations.add(combo_key)

                for topo1, topo2, topo3 in product(topologies, topologies, topologies):
                    if self._check_3d_structure(
                        self.nodes, dim1, dim2, dim3, topo1, topo2, topo3
                    ):
                        analytical_dimensions = []
                        for topo, dim in zip([topo1, topo2, topo3], [dim1, dim2, dim3]):
                            bandwidth = self.npu_bandwidth
                            latency = self.npu_latency
                            if topo == AnalyticalNetworkConfig.SWITCH:
                                bandwidth = self.switch_bandwidth
                                latency = self.switch_latency
                            analytical_dimensions.append(
                                AnalyticalNetworkConfig(topo, dim, bandwidth, latency)
                            )
                        return analytical_dimensions

        return []

    def detect_topology(self) -> List[AnalyticalNetworkConfig]:
        """
        Detect the dimensional topology of the network.
        Returns:
            - List of topology types (1D, 2D, or 3D)
            - List of dimension sizes that multiply to total nodes
        """
        if len(self.nodes) == 0:
            return []

        # Try 1D first (simplest explanation)
        result = self._detect_single_topology()
        if result:
            return result

        if self.detection_level >= 2:
            # Try 2D
            result = self._detect_2d_topology()
            if result:
                return result

        if self.detection_level == 3:
            # Try 3D (most complex)
            result = self._detect_3d_topology()
            if result:
                return result

        # No topology detected
        return []


class AnalyticalTopology:
    """
    Class that helps in converting infragraph to analytical topology by using infragraph, the generated networkx graph and annotations
    """

    def __init__(
        self,
        infrastructure: astra_sim.Infrastructure,
        annotations: astra_sim.Annotations,
    ):
        self.analytical_topology = []
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
        if len(edges) > 1:
            if edge1 != "":
                ep1 = edge1
            else:
                ep1 = edges[0][0]
            if edge2 != "":
                ep2 = edge2
            else:
                ep2 = edges[0][1]
            return graph.edges[ep1, ep2].get("link", "")
        else:
            return ""

    def _process_host(self, host_instance: str, multi_tier=False):
        # here we parse the npu
        instance_name = host_instance.split(".")[0]
        instance_index = host_instance.split(".")[1]

        # get data for npu
        npu_nodes = NetworkxUtils.get_component_node_from_type_and_instance(
            self.infragraph_service, "xpu", instance_name, int(instance_index)
        )
        # get the subgraph and get the link name
        subgraph = self.graph.subgraph(npu_nodes)
        link_name = AnalyticalTopology.get_edge_link(graph=subgraph)
        npu_bandwidth = 0
        npu_latency = 0
        if link_name != "":
            # it may so happen that npus are not connected with each other
            link_specification = self.annotation.get_link_specification(link_name)
            npu_bandwidth = link_specification["bandwidth"]
            npu_latency = link_specification["latency"]

        # get the switch nodes
        all_switch_nodes = NetworkxUtils.get_component_node_from_type_and_instance(
            self.infragraph_service,
            "switch",
            instance_name,
            int(instance_index),
        )

        nvswitch_nodes = []
        for switch in all_switch_nodes:
            xpu_connected = NetworkxUtils.get_neighbour_nodes_for_component_type(
                self.graph, switch, "xpu"
            )
            if len(xpu_connected) == len(npu_nodes) and len(xpu_connected) > 1:
                # if more than 1 npu is connected
                nvswitch_nodes.append(switch)

        switch_bandwidth = 0
        switch_latency = 0
        if len(nvswitch_nodes) > 0:
            link_name = AnalyticalTopology.get_edge_link(
                graph=self.graph, edge1=nvswitch_nodes[0], edge2=npu_nodes[0]
            )
            if link_name == "":
                raise InfragraphError(
                    "link not specified between npus",
                    grpc.StatusCode.NOT_FOUND,
                    404,
                )
            # from annotations get the attributes
            link_specification = self.annotation.get_link_specification(link_name)
            switch_bandwidth = link_specification["bandwidth"]
            switch_latency = link_specification["latency"]

        if not multi_tier:
            topology_detector = DeviceTopologyDetector(
                self.graph,
                npu_nodes,
                nvswitch_nodes,
                npu_bandwidth,
                npu_latency,
                switch_bandwidth,
                switch_latency,
                3,
            )
            self.analytical_topology = topology_detector.detect_topology()
        else:
            # homognous topology with a single host type - detect till two dimensions?
            topology_detector = DeviceTopologyDetector(
                self.graph,
                npu_nodes,
                nvswitch_nodes,
                npu_bandwidth,
                npu_latency,
                switch_bandwidth,
                switch_latency,
                2,
            )
            self.analytical_topology = topology_detector.detect_topology()

    def _get_rack_name_and_downlink(self, host_instance: str):
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
        return tor_instance, rack_downlink_name

    def _process_rack(self, host_instance: str):
        host_split = host_instance.split(".")
        tor_instance, rack_downlink_name = self._get_rack_name_and_downlink(
            host_instance
        )
        # reverse parse and get the rack uplink data?
        if tor_instance == "":
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
        if len(self.analytical_topology) == 0:
            # if none then set to 1d
            # from annotations get the attributes
            link_specification = self.annotation.get_link_specification(
                rack_downlink_name
            )
            bandwidth = link_specification["bandwidth"]
            latency = link_specification["latency"]

            # add to array
            self.analytical_topology.append(
                AnalyticalNetworkConfig(
                    AnalyticalNetworkConfig.SWITCH,
                    rack_downlink_nodes,
                    bandwidth,
                    latency,
                )
            )

            if rack_uplink_name != "":
                # set the upper level
                if self.total_npu_nodes // self.analytical_topology[0].node_count > 1:
                    node_count = (
                        self.total_npu_nodes // self.analytical_topology[0].node_count
                    )

                    link_specification = self.annotation.get_link_specification(
                        rack_uplink_name
                    )
                    bandwidth = link_specification["bandwidth"]
                    latency = link_specification["latency"]
                    self.analytical_topology.append(
                        AnalyticalNetworkConfig(
                            AnalyticalNetworkConfig.SWITCH,
                            node_count,
                            bandwidth,
                            latency,
                        )
                    )
        else:
            # the 1d topo is present
            if self.total_npu_nodes > rack_downlink_nodes:  # multiple racks are present
                # rack can be connected to a host with same number of nics?
                if rack_downlink_nodes // self.analytical_topology[0].node_count > 1:
                    node_count = (
                        rack_downlink_nodes // self.analytical_topology[0].node_count
                    )
                    link_specification = self.annotation.get_link_specification(
                        rack_downlink_name
                    )
                    bandwidth = link_specification["bandwidth"]
                    latency = link_specification["latency"]
                    self.analytical_topology.append(
                        AnalyticalNetworkConfig(
                            AnalyticalNetworkConfig.SWITCH,
                            node_count,
                            bandwidth,
                            latency,
                        )
                    )

                    if rack_uplink_name != "":  # a third layer exists
                        # set the upper level
                        if (
                            self.total_npu_nodes
                            // self.analytical_topology[1].node_count
                            > 1
                        ):
                            node_count = (
                                self.total_npu_nodes
                                // self.analytical_topology[0].node_count
                                // self.analytical_topology[1].node_count
                            )
                            link_specification = self.annotation.get_link_specification(
                                rack_uplink_name
                            )
                            bandwidth = link_specification["bandwidth"]
                            latency = link_specification["latency"]
                            self.analytical_topology.append(
                                AnalyticalNetworkConfig(
                                    AnalyticalNetworkConfig.SWITCH,
                                    node_count,
                                    bandwidth,
                                    latency,
                                )
                            )

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

        multi_tier = True
        if len(infrastructure.instances) == 1:
            # get the instance and check for count, should be 1
            multi_tier = False

        self._process_host(host_instance=host_instance, multi_tier=multi_tier)
        if multi_tier:
            if len(self.analytical_topology) == 1 or len(self.analytical_topology) == 0:
                # process rack and add the two dimensions
                self._process_rack(host_instance=host_instance)
            else:
                # directly add a switch on top of the device
                remaining_npu_nodes = (
                    self.total_npu_nodes // self.analytical_topology[0].node_count
                )
                # add it as the third or second dimension
                if remaining_npu_nodes > 1:
                    _, rack_downlink_name = self._get_rack_name_and_downlink(
                        host_instance
                    )
                    if rack_downlink_name != "":
                        # it may so happen that npus are not connected with each other
                        link_specification = self.annotation.get_link_specification(
                            rack_downlink_name
                        )
                        bandwidth = link_specification["bandwidth"]
                        latency = link_specification["latency"]
                        self.analytical_topology.append(
                            AnalyticalNetworkConfig(
                                AnalyticalNetworkConfig.SWITCH,
                                remaining_npu_nodes,
                                bandwidth,
                                latency,
                            )
                        )

    @staticmethod
    def generate_topology(configuration: astra_sim.Config):
        """
        Generates anaytical topology from infragraph and annotations
        """
        infrastructure = configuration.infragraph.infrastructure
        annotations = configuration.infragraph.annotations
        topology = AnalyticalTopology(infrastructure, annotations)
        if configuration.network_backend.choice == "analytical_congestion_aware":
            if len(topology.analytical_topology) >= 1:
                configuration.network_backend.analytical_congestion_aware.topology.network.add(
                    topology=topology.analytical_topology[0].topology,  # type: ignore
                    npus_count=topology.analytical_topology[0].node_count,
                    bandwidth=topology.analytical_topology[0].bandwidth,
                    latency=topology.analytical_topology[0].latency,
                )
            if len(topology.analytical_topology) >= 2:
                configuration.network_backend.analytical_congestion_aware.topology.network.add(
                    topology=topology.analytical_topology[1].topology,  # type: ignore
                    npus_count=topology.analytical_topology[1].node_count,
                    bandwidth=topology.analytical_topology[1].bandwidth,
                    latency=topology.analytical_topology[1].latency,
                )
            if len(topology.analytical_topology) == 3:
                configuration.network_backend.analytical_congestion_aware.topology.network.add(
                    topology=topology.analytical_topology[2].topology,  # type: ignore
                    npus_count=topology.analytical_topology[2].node_count,
                    bandwidth=topology.analytical_topology[2].bandwidth,
                    latency=topology.analytical_topology[2].latency,
                )
        if configuration.network_backend.choice == "analytical_congestion_unaware":
            if len(topology.analytical_topology) >= 1:
                configuration.network_backend.analytical_congestion_unaware.topology.network.add(
                    topology=topology.analytical_topology[0].topology,  # type: ignore
                    npus_count=topology.analytical_topology[0].node_count,
                    bandwidth=topology.analytical_topology[0].bandwidth,
                    latency=topology.analytical_topology[0].latency,
                )
            if len(topology.analytical_topology) >= 2:
                configuration.network_backend.analytical_congestion_unaware.topology.network.add(
                    topology=topology.analytical_topology[1].topology,  # type: ignore
                    npus_count=topology.analytical_topology[1].node_count,
                    bandwidth=topology.analytical_topology[1].bandwidth,
                    latency=topology.analytical_topology[1].latency,
                )
            if len(topology.analytical_topology) == 3:
                configuration.network_backend.analytical_congestion_unaware.topology.network.add(
                    topology=topology.analytical_topology[2].topology,  # type: ignore
                    npus_count=topology.analytical_topology[2].node_count,
                    bandwidth=topology.analytical_topology[2].bandwidth,
                    latency=topology.analytical_topology[2].latency,
                )
