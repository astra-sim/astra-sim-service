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

import os
import time
import subprocess
import pytest
from astra_sim_sdk import astra_sim_sdk as astra_sim
from astra_sim_sdk import Device, Component, DeviceEdge
from astra_server.configuration_handler import ConfigurationHandler
from infragraph.blueprints.devices.dgx import Dgx
from infragraph.blueprints.devices.server import Server
from infragraph.blueprints.devices.generic_switch import Switch

CURRENT_FOLDER = os.path.dirname(os.path.abspath(__file__))
# Path to the folder you want to clear every test
TEMP_FOLDER = os.path.join(CURRENT_FOLDER, "temp")


@pytest.fixture
def temp_dir():
    """
    The temporary directory used to dump files/folders
    """
    return TEMP_FOLDER


@pytest.fixture(autouse=True, scope="session")
def load_schemas():
    """
    Fixture that loads astra-sim schemas
    """
    schema_handler = ConfigurationHandler()
    schema_handler.load_schemas()


@pytest.fixture(scope="session")
def port_number():
    """
    Fixture that holds the astra-sim-server port number
    """
    return "55643"


@pytest.fixture(
    scope="session",
    autouse=True,
)
def start_server(port_number):
    """
    Fixture that starts the astra-sim server for every pytest session
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    server_path = os.path.join(script_dir, "..", "astra_server", "__main__.py")
    server_process = subprocess.Popen(
        ["python3", server_path, "--port_number", port_number]
    )

    print(f"ASTRA-sim Server started on port {port_number}")
    time.sleep(5)
    yield
    server_process.terminate()
    server_process.wait()
    print("ASTRA-sim Server stopped.")


@pytest.fixture
def ns3_schema_config():
    """
    Fixture that generates a ns3 configuration using astra-sim-sdk
    """
    config = astra_sim.Config()
    # workload
    config.common_config.workload = "allreduce/allreduce"
    # Communicator Group File
    config.common_config.communicator_group.add("0", [0, 1, 2, 3])
    # System Config file

    config.common_config.system.scheduling_policy = astra_sim.SystemConfiguration.LIFO
    config.common_config.system.endpoint_delay = 10
    config.common_config.system.active_chunks_per_dimension = 1
    config.common_config.system.all_gather_implementation = [
        astra_sim.SystemConfiguration.RING
    ]
    config.common_config.system.collective_optimization = (
        astra_sim.SystemConfiguration.LOCALBWAWARE
    )
    config.common_config.system.local_mem_bw = 1600
    # Remote Memory File
    config.common_config.remote_memory.memory_type = (
        astra_sim.RemoteMemory.NO_MEMORY_EXPANSION
    )
    # network backend
    config.network_backend.choice = config.network_backend.NS3
    # Logical topology
    config.network_backend.ns3.logical_topology.logical_dimensions = [4]
    # NC Topology - send as file for now
    config.network_backend.ns3.topology.nc_topology.total_nodes = 5
    config.network_backend.ns3.topology.nc_topology.total_switches = 1
    config.network_backend.ns3.topology.nc_topology.total_links = 1
    config.network_backend.ns3.topology.nc_topology.switch_ids = [4]
    config.network_backend.ns3.topology.nc_topology.connections.add(
        0, 4, "100Gbps", "0.005ms", "0"
    )
    config.network_backend.ns3.topology.nc_topology.connections.add(
        1, 4, "100Gbps", "0.005ms", "0"
    )
    config.network_backend.ns3.topology.nc_topology.connections.add(
        2, 4, "100Gbps", "0.005ms", "0"
    )
    config.network_backend.ns3.topology.nc_topology.connections.add(
        3, 4, "100Gbps", "0.005ms", "0"
    )
    # generate ns3 network config
    config.network_backend.ns3.network.packet_payload_size = int(8192)
    # generate trace
    config.network_backend.ns3.trace.trace_ids = [0, 1, 2, 3]
    config.common_config.cmd_parameters.comm_scale = 1
    config.common_config.cmd_parameters.injection_scale = 1
    config.common_config.cmd_parameters.rendezvous_protocol = False
    return config


@pytest.fixture
def analytical_schema_config():
    """
    Fixture that generates an analytical configuration using astra-sim-sdk
    """
    config = astra_sim.Config()
    # workload
    config.common_config.workload = "allreduce/allreduce"
    # Communicator Group File

    config.common_config.communicator_group.add("0", [0, 1, 2, 3])
    # System Config file

    config.common_config.system.scheduling_policy = astra_sim.SystemConfiguration.LIFO
    config.common_config.system.endpoint_delay = 10
    config.common_config.system.active_chunks_per_dimension = 1
    config.common_config.system.all_gather_implementation = [
        astra_sim.SystemConfiguration.RING
    ]
    config.common_config.system.collective_optimization = (
        astra_sim.SystemConfiguration.LOCALBWAWARE
    )
    config.common_config.system.local_mem_bw = 1600
    # Remote Memory File

    config.common_config.remote_memory.memory_type = (
        astra_sim.RemoteMemory.NO_MEMORY_EXPANSION
    )
    # network backend
    config.network_backend.choice = config.network_backend.ANALYTICAL_CONGESTION_AWARE
    # Analytical Topology

    config.network_backend.analytical_congestion_aware.topology.network.add(
        "fullyconnected", 4, 100, 0.005
    )
    config.common_config.cmd_parameters.comm_scale = 1
    config.common_config.cmd_parameters.injection_scale = 1
    config.common_config.cmd_parameters.rendezvous_protocol = False
    return config


@pytest.fixture
def htsim_schema_config():
    """
    Fixture that generates a htsim configuration using astra-sim-sdk
    """
    config = astra_sim.Config()
    # workload
    config.common_config.workload = "allreduce/allreduce"
    # Communicator Group File
    config.common_config.communicator_group.add("0", [0, 1, 2, 3, 4, 5, 6, 7])
    # System Config file
    config.common_config.system.scheduling_policy = astra_sim.SystemConfiguration.LIFO
    config.common_config.system.endpoint_delay = 10
    config.common_config.system.active_chunks_per_dimension = 1
    config.common_config.system.all_gather_implementation = [
        astra_sim.SystemConfiguration.RING
    ]
    config.common_config.system.collective_optimization = (
        astra_sim.SystemConfiguration.LOCALBWAWARE
    )
    config.common_config.system.local_mem_bw = 1600
    # Remote Memory File
    config.common_config.remote_memory.memory_type = (
        astra_sim.RemoteMemory.NO_MEMORY_EXPANSION
    )
    # network backend
    # htsim Topology
    config.network_backend.htsim.topology.network_topology_configuration.network.add(
        "switch", 8, 100, 0.005
    )

    config.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.nodes = (
        8
    )
    config.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tiers = (
        3
    )
    config.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.podsize = (
        4
    )

    config.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.downlink_speed_gbps = (
        200
    )
    config.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.radix_up = (
        2
    )
    config.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.radix_down = (
        2
    )
    config.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.downlink_latency_ns = (
        200
    )

    config.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_1.downlink_speed_gbps = (
        200
    )
    config.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_1.radix_up = (
        2
    )
    config.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_1.radix_down = (
        2
    )
    config.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_1.downlink_latency_ns = (
        1000
    )
    config.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_1.bundle = (
        1
    )

    config.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_2.downlink_speed_gbps = (
        100
    )
    config.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_2.radix_down = (
        4
    )
    config.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_2.downlink_latency_ns = (
        1000
    )
    config.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_2.bundle = (
        2
    )

    config.network_backend.htsim.htsim_protocol.tcp.nodes = "10"

    config.common_config.cmd_parameters.comm_scale = 1
    config.common_config.cmd_parameters.injection_scale = 1
    config.common_config.cmd_parameters.rendezvous_protocol = False

    return config


@pytest.fixture
def infra_switch_factory():
    """
    Fixture that returns a generic switch device defined in Keysight infragraph repository
    """

    def _get_switch(port_count: int = 16):
        """Adds an InfraGraph device to infrastructure based on the following components:
        - 1 generic asic
        - nic_count number of ports
        - integrated circuitry connecting ports to asic
        """
        switch = Device()
        switch = switch.deserialize(Switch(port_count=port_count).serialize())
        return switch

    return _get_switch


@pytest.fixture
def get_dgx():
    """
    Fixture that returns a dgx device defined in Keysight infragraph repository
    """
    dgx = Device()
    dgx.deserialize(Dgx().serialize())
    return dgx


@pytest.fixture
def infra_multi_gpu_server_factory():
    """
    Fixture that returns a multi gpu server device defined in Keysight infragraph repository
    """

    def _get_server(npu_factor: int = 1):
        """Adds an InfraGraph device to infrastructure based on the following components:
        - 1 cpu for every 2 npus
        - 1 pcie switch for every 1 cpu
        - X npus = npu_factor * 2
        - 1 nic for every npu with 2 nics connected to a pcie switch
        - 1 nvswitch connected to all npus
        """
        server = Device()
        server.deserialize(Server(npu_factor).serialize())
        return server

    return _get_server


@pytest.fixture
def infra_single_gpu_server_factory():
    """
    Fixture that returns a single gpu server device defined in Keysight infragraph repository
    """

    def _get_server():
        server = Device()
        server.name = "server"
        server.description = "A generic server with npu_factor * 4 npu(s)"

        npu = server.components.add(
            name="npu",
            description="Generic GPU/NPU",
            count=1,
        )
        npu.choice = Component.NPU
        nvlsw = server.components.add(
            name="nvlsw",
            description="NVLink Switch",
            count=1,
        )
        nvlsw.choice = Component.SWITCH

        nic = server.components.add(
            name="nic",
            description="Generic Nic",
            count=1,
        )
        nic.choice = Component.NIC

        nvlink = server.links.add(name="nvlink")
        pcie = server.links.add(name="pcie")

        edge = server.edges.add(scheme=DeviceEdge.MANY2MANY, link=nvlink.name)  # type: ignore
        edge.ep1.component = npu.name
        edge.ep2.component = nvlsw.name

        edge = server.edges.add(scheme=DeviceEdge.ONE2ONE, link=pcie.name)  # type: ignore
        edge.ep1.component = npu.name
        edge.ep2.component = nic.name

        return server

    return _get_server
