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
    from infrastructure.infra_utils import Annotation, NetworkxUtils
else:
    from astra_server.errors import InfragraphError
    from astra_server.infrastructure.infra_utils import Annotation, NetworkxUtils


class NS3Topology:
    """
    Class that is used to generate NS3 Topology by parsing the infragraph, networkx graph and annotations
    """

    def __init__(
        self,
        infrastructure: astra_sim.Infrastructure,
        annotations: astra_sim.Annotations,
    ):
        self.switches = []
        # read the annotation and store the link and device data
        self.annotation = Annotation(annotations)
        self.infragraph_service = InfraGraphService()
        self.infragraph_service.set_graph(infrastructure.__str__())
        # store the network graph
        self.graph = self.infragraph_service.get_networkx_graph()
        self._print_graph()
        self._process_infra(infrastructure)

    def _print_graph(self):
        for node, attrs in self.graph.nodes(data=True):
            print(f"Node: {node}, Attributes: {attrs}")

        for u, v, attrs in self.graph.edges(data=True):
            print(f"Edge: ({u}, {v}), Attributes: {attrs}")

    def _host_rank_assignment(self, infrastructure: astra_sim.Infrastructure):
        if self.annotation.last_rank_identifier <= 0:
            # no rank has been assigned
            # we get the hosts and assign the ranks to npu
            # can be assigned linearly
            self.annotation.last_rank_identifier = 0
            for device_instance in infrastructure.instances:
                # get the type of device_instance
                device_name = self.annotation.instance_to_device_name[
                    device_instance.name
                ]
                if device_name in self.annotation.hosts:
                    # so we got a host
                    for i in range(0, device_instance.count):
                        # get the npus from networkx graph
                        nodes = NetworkxUtils.get_component_node_from_type_and_instance(
                            self.infragraph_service, "xpu", device_instance.name, int(i)
                        )

                        for node in nodes:
                            self.annotation.device_to_id[
                                node
                            ] = self.annotation.last_rank_identifier
                            self.annotation.last_rank_identifier = (
                                self.annotation.last_rank_identifier + 1
                            )

                        self.annotation.host_sequence.append(
                            device_instance.name + "." + str(i)
                        )

        for host_instance in self.annotation.host_sequence:
            # get the device instance
            instance_name = host_instance.split(".")[0]
            instance_index = host_instance.split(".")[1]
            # from graph, get all npus and then for each npu, get the nic neighbour
            npu_nodes = NetworkxUtils.get_component_node_from_type_and_instance(
                self.infragraph_service, "xpu", instance_name, int(instance_index)
            )

            # get the neighbour nics
            for npu in npu_nodes:
                nics = NetworkxUtils.get_neighbour_nodes_for_component_type(
                    self.graph, npu, "nic"
                )
                if len(nics) <= 0:
                    # here we get equivalent nic
                    nic_nodes = NetworkxUtils.get_component_node_from_type_and_instance(
                        self.infragraph_service,
                        "nic",
                        instance_name,
                        int(instance_index),
                    )
                    if len(nic_nodes) <= 0:
                        raise InfragraphError(
                            f"nic nodes missing for npu: {npu}",
                            grpc.StatusCode.NOT_FOUND,
                            404,
                        )

                    if len(nic_nodes) < len(npu_nodes):
                        raise InfragraphError(
                            "the nics are less than the npu count in the device",
                            grpc.StatusCode.INVALID_ARGUMENT,
                            400,
                        )

                    nic_instance_index = nic_nodes[0]
                    nic_component_name = (
                        nic_instance_index.split(".")[0]
                        + "."
                        + nic_instance_index.split(".")[1]
                        + "."
                        + nic_instance_index.split(".")[2]
                    )
                    npu_index = npu.split(".")[3]
                    connected_nic = nic_component_name + "." + str(npu_index)
                    nics = [connected_nic]

                rank_id = self.annotation.device_to_id[npu]
                for nic in nics:
                    self.annotation.device_to_id[nic] = rank_id

            switch_nodes = NetworkxUtils.get_component_node_from_type_and_instance(
                self.infragraph_service, "switch", instance_name, int(instance_index)
            )

            # chances are switch nodes can be empty
            for switch in switch_nodes:
                if (
                    len(
                        NetworkxUtils.get_neighbour_nodes_for_component_type(
                            self.graph, switch, "xpu"
                        )
                    )
                    > 1
                ):
                    # if more than 1 npu is connected
                    self.switches.append(switch)
                    self.annotation.device_to_id[
                        switch
                    ] = self.annotation.last_rank_identifier
                    self.annotation.last_rank_identifier = (
                        self.annotation.last_rank_identifier + 1
                    )

    def _process_infra(self, infrastructure: astra_sim.Infrastructure):

        # parse device
        # parse device instances
        # parse connections
        for device in infrastructure.devices:
            self.annotation.add_device(device.name)
            for link in device.links:
                self.annotation.add_link(link)

        # add links
        for link in infrastructure.links:
            self.annotation.add_link(link)

        instance_map = {}
        for instance in infrastructure.instances:
            self.annotation.add_device_instance(
                device_instance=instance.name, device_name=instance.device
            )
            instance_map[instance.name] = []
            for i in range(0, instance.count):
                self.annotation.add_device_instance(
                    device_instance=instance.name + "." + str(i),
                    device_name=instance.device,
                )
                instance_map[instance.name].append(instance.name + "." + str(i))

        # assign ranks or identifiers to host components like nic, npu, switch
        self._host_rank_assignment(infrastructure)

        # generate the device identifier
        self._generate_external_switch_identifier(instance_map)

    def _generate_external_switch_identifier(self, instance_map: dict):
        # component graph where - instance is key and - [instance.component] is value
        device_component_map = {}
        # add all hosts in self.graph
        device_connection_graph = {}
        for host in self.annotation.host_sequence:
            host_name = host.split(".")[0]
            if host_name not in device_connection_graph:
                device_connection_graph[host_name] = []

        # we need to know the connection of devices - mainly how switches are connected to each other
        for source, destination, _ in self.graph.edges(data=True):

            source_split = source.split(".")
            destination_split = destination.split(".")
            source_device_index = source_split[0] + "." + source_split[1]
            destination_device_index = destination_split[0] + "." + destination_split[1]
            source_device = source_split[0]
            destination_device = destination_split[0]

            if source_device_index in device_component_map:
                device_component_map[source_device_index].add(source)
            else:
                device_component_map[source_device_index] = set([source])

            if destination_device_index in device_component_map:
                device_component_map[destination_device_index].add(destination)
            else:
                device_component_map[destination_device_index] = set([destination])

            if source_device_index != destination_device_index:
                # connection in the same device is not allowed here
                if source_device in device_connection_graph:
                    if destination_device not in device_connection_graph[source_device]:
                        device_connection_graph[source_device] = [destination_device]
                    else:
                        if destination_device not in set(
                            device_connection_graph[source_device]
                        ):
                            device_connection_graph[source_device].append(
                                destination_device
                            )

                elif destination_device in device_connection_graph:
                    if source_device not in device_connection_graph[destination_device]:
                        device_connection_graph[destination_device] = [source_device]
                    else:
                        if source_device not in set(
                            device_connection_graph[source_device]
                        ):
                            device_connection_graph[destination_device].append(
                                source_device
                            )
        stack = []
        for host in self.annotation.host_sequence:
            host_name = host.split(".")[0]
            if host_name not in set(stack):
                stack.append(host_name)
        while stack:
            device = stack.pop()
            next_devices = device_connection_graph.get(device)
            if next_devices:
                stack.extend(next_devices)
            if self.annotation.get_instance_type(device) == "switch":
                # get all instances
                device_instances = instance_map[device]
                for instance in device_instances:
                    self.switches.append(instance)
                    self.annotation.device_to_id[
                        instance
                    ] = self.annotation.last_rank_identifier
                    # add the device_components with same identifier
                    for component in device_component_map[instance]:
                        self.annotation.device_to_id[
                            component
                        ] = self.annotation.last_rank_identifier
                    self.annotation.last_rank_identifier = (
                        self.annotation.last_rank_identifier + 1
                    )

    @staticmethod
    def generate_topology(configuration: astra_sim.Config):
        """
        Generates ns3 topology from infragraph and annotations
        """

        infrastructure = configuration.infragraph.infrastructure
        annotations = configuration.infragraph.annotations
        topology = NS3Topology(infrastructure, annotations)

        configuration.network_backend.ns3.topology.nc_topology.total_links = 0
        configuration.network_backend.ns3.topology.nc_topology.total_switches = len(
            topology.switches
        )
        configuration.network_backend.ns3.topology.nc_topology.switch_ids = []

        for switch in topology.switches:
            switch_id = topology.annotation.device_to_id[switch]
            configuration.network_backend.ns3.topology.nc_topology.switch_ids.append(
                switch_id
            )

        configuration.network_backend.ns3.topology.nc_topology.total_nodes = (
            topology.annotation.last_rank_identifier
        )
        for source, destination, attr in topology.graph.edges(data=True):
            source_dev = -1
            dest_dev = -1

            source_split = source.split(".")
            destination_split = destination.split(".")

            source_device_index = source_split[0] + "." + source_split[1]
            destination_device_index = destination_split[0] + "." + destination_split[1]

            # case 1: both source and destination are hosts
            if (
                topology.graph.nodes[source]["device"] in topology.annotation.hosts
                and topology.graph.nodes[destination]["device"]
                in topology.annotation.hosts
            ):
                # if either one is a switch and the other one is an npu:
                if (
                    topology.graph.nodes[source]["type"] == "switch"
                    and topology.graph.nodes[destination]["type"] == "xpu"
                ) or (
                    topology.graph.nodes[source]["type"] == "xpu"
                    and topology.graph.nodes[destination]["type"] == "switch"
                ):
                    if source in topology.annotation.device_to_id:
                        source_dev = topology.annotation.device_to_id[source]
                    if destination in topology.annotation.device_to_id:
                        dest_dev = topology.annotation.device_to_id[destination]
            # case 2: either one can be a host?
            elif (
                topology.graph.nodes[source]["device"] in topology.annotation.hosts
                and topology.graph.nodes[destination]["device"]
                not in topology.annotation.hosts
            ) or (
                topology.graph.nodes[source]["device"] not in topology.annotation.hosts
                and topology.graph.nodes[destination]["device"]
                in topology.annotation.hosts
            ):
                if source in topology.annotation.device_to_id:
                    source_dev = topology.annotation.device_to_id[source]
                if destination in topology.annotation.device_to_id:
                    dest_dev = topology.annotation.device_to_id[destination]
            # case 2: both are not hosts and not same device
            elif (
                topology.graph.nodes[source]["device"] not in topology.annotation.hosts
                and topology.graph.nodes[destination]["device"]
                not in topology.annotation.hosts
            ) and (source_device_index != destination_device_index):
                if source in topology.annotation.device_to_id:
                    source_dev = topology.annotation.device_to_id[source]
                if destination in topology.annotation.device_to_id:
                    dest_dev = topology.annotation.device_to_id[destination]

            if source_dev > -1 and dest_dev > -1:
                print(f"Edge from {source} to {destination} with attributes {attr}")
                print(f"ns3: {source_dev} {dest_dev}")

                link = topology.annotation.get_link_specification(
                    attr["link"]
                )  # this is a dict
                if len(link) == 0:
                    raise InfragraphError(
                        "Link missing", grpc.StatusCode.NOT_FOUND, 404
                    )

                bandwidth = link["bandwidth"].to_str()
                latency = link["latency"].to_str()
                error_rate = str(link["link_error_rate"])

                configuration.network_backend.ns3.topology.nc_topology.connections.add(
                    source_index=source_dev,
                    destination_index=dest_dev,
                    bandwidth=bandwidth,
                    latency=latency,
                    error_rate=error_rate,
                )

                configuration.network_backend.ns3.topology.nc_topology.total_links = (
                    configuration.network_backend.ns3.topology.nc_topology.total_links
                    + 1
                )
        # NS3Topology.dump_ns3(configuration.network_backend.ns3.topology.nc_topology)

    @staticmethod
    def dump_ns3(nc_topology):
        """
        Dump nc topology file from configuration. Used for debugging purpose.
        """
        config = (
            str(nc_topology.total_nodes)
            + " "
            + str(nc_topology.total_switches)
            + " "
            + str(nc_topology.total_links)
        )
        config = config + "\n" + " ".join(str(num) for num in nc_topology.switch_ids)
        for connection in nc_topology.connections:
            config = (
                config
                + "\n"
                + str(connection.source_index)
                + " "
                + str(connection.destination_index)
                + " "
                + str(connection.bandwidth)
                + " "
                + str(connection.latency)
                + " "
                + str(connection.error_rate)
            )
        with open("nc_topology.txt", "w", encoding="utf-8") as file:
            file.write(config)
