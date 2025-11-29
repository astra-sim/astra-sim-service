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

from enum import Enum
import grpc
from astra_sim_sdk.astra_sim_sdk import Annotations
import astra_sim_sdk.astra_sim_sdk as astra_sim
from infragraph import QueryRequest, QueryNodeFilter, QueryNodeId

if __package__ is None or __package__ == "":
    from errors import InfragraphError
else:
    from astra_server.errors import InfragraphError


class InfraUtils:
    """
    A dataclass that holds various constants and strings
    """

    DEVICE_SPECIFICATION = "DeviceSpecification"
    LINK_SPECIFICATION = "LinkSpecification"
    RANK_ASSIGNMENT = "RankAssignment"
    ANNOTATIONS = "annotations"

    TRANSFER_UNIT_TO_SHORT_NOTATION = {
        "BITS_PER_SECOND": "bps",
        "BYTES_PER_SECOND": "Bps",
        "KILOBIT_PER_SECOND": "Kbps",
        "KILOBYTE_PER_SECOND": "kBps",
        "KIBIBIT_PER_SECOND": "",
        "MEGABIT_PER_SECOND": "Mbps",
        "MEGABYTE_PER_SECOND": "MBps",
        "MEBIBIT_PER_SECOND": "",
        "GIGABIT_PER_SECOND": "Gbps",
        "GIGABYTES_PER_SECOND": "GBps",
        "GIBIBIT_PER_SECOND": "",
        "TERABIT_PER_SECOND": "Tbps",
        "TERABYTES_PER_SECOND": "TBps",
        "TEBIBIT_PER_SECOND": "",
        "GIGA_TRANSFERS_PER_SECOND": "gts",
    }

    TIME_UNIT_TO_SHORT_NOTATION = {
        "SECOND": "s",
        "MILLISECOND": "ms",
        "MICROSECOND": "us",
        "NANOSECOND": "ns",
    }


class TimeUnit(Enum):
    """
    Enum class that holds the timeunit and its conversion factor from ms
    """

    SECOND = 0.001
    MILLISECOND = 1
    MICROSECOND = 1000
    NANOSECOND = 1000000


class TransferUnit(Enum):
    """
    Enum class that holds the transfer unit and its conversion factor from gigabit per second
    """

    BITS_PER_SECOND = 1000000000
    BYTES_PER_SECOND = 125000000
    KILOBIT_PER_SECOND = 1000000
    KILOBYTE_PER_SECOND = 125000
    KIBIBIT_PER_SECOND = 976563
    MEGABIT_PER_SECOND = 1000
    MEGABYTE_PER_SECOND = 125
    MEBIBIT_PER_SECOND = 953.674
    GIGABIT_PER_SECOND = 1
    GIGABYTES_PER_SECOND = 0.125
    GIBIBIT_PER_SECOND = 0.931323
    TERABIT_PER_SECOND = 0.001
    TERABYTES_PER_SECOND = 0.000125
    TEBIBIT_PER_SECOND = 0.000909495
    GIGA_TRANSFERS_PER_SECOND = 1


class DeviceRateMetrics:
    """
    Class that deals with data rate metrics which accepts bandwidth value in gbps and handles translations to other transfer units
    """

    def __init__(self, value_in_gbps=0.0):
        self._bandwidth_in_gbps = value_in_gbps

    @property
    def bandwidth_in_gbps(self):
        """
        Returns the bandwidth in gbos
        """
        return self._bandwidth_in_gbps

    @bandwidth_in_gbps.setter
    def bandwidth_in_gbps(self, value):
        self._bandwidth_in_gbps = value

    def to_transfer_unit(self, target_unit=TransferUnit.GIGABIT_PER_SECOND):
        """
        Converts the bandwith to the specified transfer unit
        """
        return self._bandwidth_in_gbps / TransferUnit.GIGABIT_PER_SECOND.value * target_unit.value

    def to_str(self, target_unit=TransferUnit.GIGABIT_PER_SECOND):
        """
        Converts the bandwith to the specified transfer unit and returns as string with the unit name appended
        """
        return (
            str(int(self._bandwidth_in_gbps / TransferUnit.GIGABIT_PER_SECOND.value * target_unit.value))
            + InfraUtils.TRANSFER_UNIT_TO_SHORT_NOTATION[target_unit.name]
        )

    def to_float(self, target_unit=TransferUnit.GIGABIT_PER_SECOND, decimal_places=2):
        """
        Converts the bandwidth to the specified transfer unit and returns as an integer
        """
        return round(
            self._bandwidth_in_gbps / TransferUnit.GIGABIT_PER_SECOND.value * target_unit.value,
            decimal_places,
        )

    def to_int(self, target_unit=TransferUnit.GIGABIT_PER_SECOND):
        """
        Converts the bandwidth to the specified transfer unit and returns as an integer
        """
        return int(self._bandwidth_in_gbps / TransferUnit.GIGABIT_PER_SECOND.value * target_unit.value)

    def to_int_str(self, target_unit=TransferUnit.GIGABIT_PER_SECOND):
        """
        Converts the bandwidth to the specified transfer unit and returns a string with transfer unit value in integer
        """
        return (
            str(int(self._bandwidth_in_gbps / TransferUnit.GIGABIT_PER_SECOND.value * target_unit.value))
            + InfraUtils.TRANSFER_UNIT_TO_SHORT_NOTATION[target_unit.name]
        )


class Latency:
    """
    Class that deals with latency which accepts latency value in ms and handles translations
    """

    def __init__(self, value_in_ms=0.0):
        self._latency_in_ms = value_in_ms

    @property
    def latency_in_ms(self):
        """
        Returns the latency in ms
        """
        return self._latency_in_ms

    @latency_in_ms.setter
    def latency_in_ms(self, value):
        self._latency_in_ms = value

    def to_time_unit(self, target_unit=TimeUnit.MILLISECOND):
        """
        Converts the latency to the specified time unit
        """
        return self._latency_in_ms * target_unit.value

    def to_time_unit_int(self, target_unit=TimeUnit.MILLISECOND):
        """
        Converts the latency to the specified time unit and returns as int type
        """
        return self._latency_in_ms * target_unit.value

    def to_time_unit_float(self, target_unit=TimeUnit.MILLISECOND, decimal_places=2):
        """
        Converts the latency to the specified time unit and returns as int type
        """
        return round(self._latency_in_ms * target_unit.value, decimal_places)

    def to_str(self, target_unit=TimeUnit.MILLISECOND):
        """
        Converts the latency to the specified time unit and returns as string with the unit name appended
        """
        return (
            str(self._latency_in_ms / TimeUnit.MILLISECOND.value * target_unit.value)
            + InfraUtils.TIME_UNIT_TO_SHORT_NOTATION[target_unit.name]
        )


class AnalyticalNetworkType(Enum):
    """
    Enum class that holds the network type used by analytical network backend
    """

    UNDEFINED = 0
    RING = 1
    FULLY_CONNECTED = 2
    SWITCH = 3


class Annotation:
    """
    Class that deals with annotations and holds the dictionaries which gives relation between:
        - device instance and device name
        - device name and device specification
        - link name and link specification
        - device instance & component to identifier
    """

    def __init__(self, annotations: Annotations):
        self.device_specification = {}
        self.link_specification = {}
        self.device_to_id = {}
        self.instance_to_device_name = {}
        """
        This will hold all the host instances in sequence of rank assignements
        """
        self.host_sequence = []

        """
        This will hold all the hosts present
        """
        self.hosts = set()
        self.last_rank_identifier = -1

        self._parse_device_specification(annotations)
        self._parse_link_specification(annotations)
        self._parse_rank_annotation(annotations)

    def _parse_device_specification(self, annotations: Annotations):
        for device_spec in annotations.device_specifications:
            self.device_specification[device_spec.device_name] = {
                "device_name": device_spec.device_name,
                "device_type": device_spec.device_type,
                "device_latency_ms": device_spec.device_latency_ms,
                "device_bandwidth_gbps": device_spec.device_bandwidth_gbps,
                "radix_up": device_spec.radix_up,
                "radix_down": device_spec.radix_down,
                "queue_up": device_spec.queue_up,
                "queue_down": device_spec.queue_down,
            }
        self._infer_host_devices()

    def _parse_link_specification(self, annotations: Annotations):
        for link_spec in annotations.link_specifications:
            self.link_specification[link_spec.link_name] = {
                "link_name": link_spec.link_name,
                "packet_loss_rate": link_spec.packet_loss_rate,
                "link_error_rate": link_spec.link_error_rate,
            }

    def _parse_rank_annotation(self, annotations: Annotations):
        rank_to_npu = {}
        for rank_assignment in annotations.rank_assignment:
            # assign to rank -> npu and npu -> rank #two way map
            rank_to_npu[rank_assignment.rank_identifier] = rank_assignment.npu_identifier
            self.device_to_id[rank_assignment.npu_identifier] = rank_assignment.rank_identifier

        # if ranks are not assigned?
        self.last_rank_identifier = len(rank_to_npu)

        host_instance = ""
        for i in range(0, self.last_rank_identifier):
            npu_instance = rank_to_npu[i]
            npu_location_split = npu_instance.split(".")
            device_instance = npu_location_split[0] + "." + npu_location_split[1]
            if device_instance != host_instance:
                self.host_sequence.append(device_instance)
                host_instance = device_instance

    def get_device_specification(self, device):
        """
        Returns the device specification map where the key is device name and the value is a dict containing the specification
        """
        return self.device_specification.get(device, {})

    def get_link_specification(self, link: str):
        """
        Returns the link specification map where the key is link name and the value is a dict containing the specification
        """
        return self.link_specification.get(link, {})

    def get_instance_type(self, device_instance: str):
        """
        Returns the device type of the device instance. It can be a switch or a host
        """
        device_name = self.instance_to_device_name[device_instance]
        if device_name not in self.device_specification:
            return ""
        return self.device_specification[device_name]["device_type"]

    def _infer_host_devices(self):
        # get the device type map:
        for device_name, device_data in self.device_specification.items():
            dev_type = device_data.get("device_type")
            if dev_type is None:
                raise InfragraphError("Device Type is missing", grpc.StatusCode.INVALID_ARGUMENT, 400)
            if "host" == dev_type:
                self.hosts.add(device_name)
        if len(self.hosts) == 0:
            raise InfragraphError("host devices not specified", grpc.StatusCode.NOT_FOUND, 404)

    def add_device(self, device_name: str):
        """
        Adds a device to the device specification map and creates a relation between the device name and the spec
        """
        if device_name not in self.device_specification:
            self.device_specification[device_name] = {
                "device_name": device_name,
                "device_type": "",
                "device_latency_ms": "",
                "device_bandwidth_gbps": "",
                "radix_up": "",
                "radix_down": "",
                "queue_up": "",
                "queue_down": "",
            }

    def _add_default_link(self, link_name: str):
        self.link_specification[link_name] = {
            "link_name": link_name,
            "packet_loss_rate": 0,
            "link_error_rate": 0,
            "bandwidth": DeviceRateMetrics(100),
            "latency": Latency(0.005),
        }

    def add_link(self, link: astra_sim.Link):
        """
        Adds a link to the link specification map and creates a relation between the link name and the spec
        """
        if link.name not in self.link_specification:
            # add default parameters
            self._add_default_link(link.name)
        # add the bandwidth and latency?
        if link.get("physical") is not None:
            if link.physical.get("bandwidth") is not None:
                if link.physical.bandwidth.choice == "gigabits_per_second":
                    self.link_specification[link.name]["bandwidth"] = DeviceRateMetrics(
                        link.physical.bandwidth.gigabits_per_second
                    )
                elif link.physical.bandwidth.choice == "gigabytes_per_second":
                    self.link_specification[link.name]["bandwidth"] = DeviceRateMetrics(
                        link.physical.bandwidth.gigabytes_per_second * 8
                    )
                elif link.physical.bandwidth.choice == "gigatransfers_per_second":
                    self.link_specification[link.name]["bandwidth"] = DeviceRateMetrics(
                        link.physical.bandwidth.gigatransfers_per_second * 8
                    )

            if link.physical.get("latency") is not None:
                if link.physical.latency.choice == "ms":
                    self.link_specification[link.name]["latency"] = Latency(link.physical.latency.ms)
                elif link.physical.latency.choice == "ns":
                    self.link_specification[link.name]["latency"] = Latency(
                        link.physical.latency.ns * 0.000001
                    )
                elif link.physical.latency.choice == "us":
                    self.link_specification[link.name]["latency"] = Latency(link.physical.latency.us * 0.001)

    def add_device_instance(self, device_instance: str, device_name: str):
        """
        Adds device instance as a key and value being the device name to an instance_to_device_map - holds the relation between instance and device
        """
        self.instance_to_device_name[device_instance] = device_name


class NetworkxUtils:
    """
    Static class that holds static functions which are used as networkx utils required by translators
    """

    @staticmethod
    def get_neighbour_nodes_for_component_type(graph, node, component_type):
        """
        This returns the neighbour nodes for a given component and its type
        """
        neighbors = []
        for neighbor in graph.neighbors(node):
            if graph.nodes[neighbor].get("type") == component_type:
                neighbors.append(neighbor)

        return list(set(neighbors))

    @staticmethod
    def get_nodes_from_device_component_type(graph, device_instance_name: str, component_type: str):
        """
        This returns all the nodes from the graph for a given component type
        """
        nodes = []
        for node, attrs in graph.nodes(data=True):
            if attrs.get("type") == component_type and attrs.get("instance") == device_instance_name:
                nodes.append(node)
        return nodes

    @staticmethod
    def get_component_node_from_type_and_instance(
        service, component_type: str, instance_name: str, instance_index: int
    ):
        """
        This uses the infragraph request query mechanism and returns the component node for a given type and instance as well as instance index
        """
        request = QueryRequest()
        query_filter = request.node_filters.add(name="component filter")
        query_filter.choice = QueryNodeFilter.ATTRIBUTE_FILTER
        query_filter.attribute_filter.name = "type"
        query_filter.attribute_filter.operator = QueryNodeId.EQ
        query_filter.attribute_filter.value = component_type
        query_filter = request.node_filters.add(name="instance filter")
        query_filter.choice = QueryNodeFilter.ATTRIBUTE_FILTER
        query_filter.attribute_filter.name = "instance"
        query_filter.attribute_filter.operator = QueryNodeId.EQ
        query_filter.attribute_filter.value = instance_name
        query_filter = request.node_filters.add(name="instance idx filter")
        query_filter.choice = QueryNodeFilter.ATTRIBUTE_FILTER
        query_filter.attribute_filter.name = "instance_idx"
        query_filter.attribute_filter.operator = QueryNodeId.EQ
        query_filter.attribute_filter.value = instance_index
        response = service.query_graph(request)
        nodes = []
        for node in response.node_matches:
            nodes.append(node.id)
        return nodes
