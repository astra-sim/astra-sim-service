# ---
# jupyter:
#   jupytext:
#     text_representation:
#       extension: .py
#       format_name: percent
#       format_version: '1.3'
#       jupytext_version: 1.19.1
#   kernelspec:
#     display_name: Python 3
#     language: python
#     name: python3
# ---

# %% [markdown]
# ##### Import the required modules and configure the system path to locate them

# %%
import sys

# sys.path.append("../utils")
# from astra_sim import AstraSim, Collective, NetworkBackend
from service_client_utils.astra_sim import AstraSim, Collective, NetworkBackend

# %% [markdown]
# ##### Call the AstraSim client helper with the server endpoint and tag to connect to the ASTRA-sim gRPC server, initialize the SDK, and create a tagged folder for configs, results, and logs.

# %%
astra = AstraSim(server_endpoint="172.17.0.2:8989", tag="ns3_sample")

# %% [markdown]
# ##### Generate workload execution traces for each rank and set the required data size for AstraSim configuration

# %%
astra.configuration.common_config.workload = astra.generate_collective(
    collective=Collective.ALLREDUCE, coll_size=8 * 1024 * 1024, npu_range=[0, 8]
)
print(astra.configuration.common_config.workload)


# %% [markdown]
# ##### Configure ASTRA-sim system config

# %%
astra.configuration.common_config.system.scheduling_policy = astra.configuration.common_config.system.LIFO
astra.configuration.common_config.system.endpoint_delay = 10
astra.configuration.common_config.system.active_chunks_per_dimension = 1
astra.configuration.common_config.system.all_gather_implementation = [
    astra.configuration.common_config.system.RING
]
astra.configuration.common_config.system.all_to_all_implementation = [
    astra.configuration.common_config.system.DIRECT
]
astra.configuration.common_config.system.all_reduce_implementation = [
    astra.configuration.common_config.system.ONERING
]
astra.configuration.common_config.system.collective_optimization = (
    astra.configuration.common_config.system.LOCALBWAWARE
)
astra.configuration.common_config.system.local_mem_bw = 1600
print(astra.configuration.common_config.system)

# %% [markdown]
# ##### Configure ASTRA-sim remote memory configuration

# %%
astra.configuration.common_config.remote_memory.memory_type = (
    astra.configuration.common_config.remote_memory.NO_MEMORY_EXPANSION
)
print(astra.configuration.common_config.remote_memory)

# %% [markdown]
# ##### Configure the network backend

# %%
# astra.configuration.network_backend.choice = astra.configuration.network_backend.NS3
astra.configuration.network_backend.ns3.network.packet_payload_size = int(8192)
astra.configuration.network_backend.ns3.logical_topology.logical_dimensions = [8]
astra.configuration.network_backend.ns3.trace.trace_ids = [0, 1, 2, 3, 4, 5, 6, 7]
print("network backend choice set to:", astra.configuration.network_backend.ns3.topology.choice)
print(astra.configuration.network_backend.ns3.network.packet_payload_size)
print(astra.configuration.network_backend.ns3.logical_topology)
print(astra.configuration.network_backend.ns3.trace)

# %% [markdown]
# ##### Set up the network topology

# %%
# astra.configuration.network_backend.ns3.topology.choice = astra.configuration.network_backend.ns3.topology.NC_TOPOLOGY
# the topology configuration will be set automatically if we configure the nc_topology
astra.configuration.network_backend.ns3.topology.nc_topology.total_nodes = 9
astra.configuration.network_backend.ns3.topology.nc_topology.total_switches = 1
astra.configuration.network_backend.ns3.topology.nc_topology.total_links = 8
astra.configuration.network_backend.ns3.topology.nc_topology.switch_ids = [8]
astra.configuration.network_backend.ns3.topology.nc_topology.connections.clear()
astra.configuration.network_backend.ns3.topology.nc_topology.connections.add(0, 8, "100Gbps", "0.005ms", "0")
astra.configuration.network_backend.ns3.topology.nc_topology.connections.add(1, 8, "100Gbps", "0.005ms", "0")
astra.configuration.network_backend.ns3.topology.nc_topology.connections.add(2, 8, "100Gbps", "0.005ms", "0")
astra.configuration.network_backend.ns3.topology.nc_topology.connections.add(3, 8, "100Gbps", "0.005ms", "0")
astra.configuration.network_backend.ns3.topology.nc_topology.connections.add(4, 8, "100Gbps", "0.005ms", "0")
astra.configuration.network_backend.ns3.topology.nc_topology.connections.add(5, 8, "100Gbps", "0.005ms", "0")
astra.configuration.network_backend.ns3.topology.nc_topology.connections.add(6, 8, "100Gbps", "0.005ms", "0")
astra.configuration.network_backend.ns3.topology.nc_topology.connections.add(7, 8, "100Gbps", "0.005ms", "0")
print(astra.configuration.network_backend.ns3.topology.choice)
print(astra.configuration.network_backend.ns3.topology.nc_topology)


# %% [markdown]
# ##### Configure ASTRA-sim cmd parameters

# %%
astra.configuration.common_config.cmd_parameters.comm_scale = 1
astra.configuration.common_config.cmd_parameters.injection_scale = 1
astra.configuration.common_config.cmd_parameters.rendezvous_protocol = False

print(astra.configuration.common_config.cmd_parameters)

# %% [markdown]
# #### Start the simulation by specifying the network backend

# %%
astra.run_simulation(NetworkBackend.NS3)

# %% [markdown]
# ##### Download all the configurations as a zip

# %%
astra.download_configuration()


# %% [markdown]
# ##### Read output files

# %%
import pandas as pd
import os
from common import FileFolderUtils

df = pd.read_csv(os.path.join(FileFolderUtils.get_instance().OUTPUT_DIR, "fct.csv"))
df.head()
df = pd.read_csv(os.path.join(FileFolderUtils.get_instance().OUTPUT_DIR, "flow_stats.csv"))
df.head()
