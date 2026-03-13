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
sys.path.append("../utils")
from astra_sim import AstraSim, Collective, NetworkBackend

# %% [markdown]
# ##### Call the AstraSim client helper with the server endpoint and tag to connect to the ASTRA-sim gRPC server, initialize the SDK, and create a tagged folder for configs, results, and logs.

# %%
astra = AstraSim(server_endpoint ="172.17.0.2:8989", tag = "analytical_congestion_unaware_sample")

# %% [markdown]
# ##### Generate workload execution traces for each rank and set the required data size for AstraSim configuration

# %%
astra.configuration.common_config.workload = astra.generate_collective(collective=Collective.ALLREDUCE, coll_size= 1024*1024*1024, npu_range=[0,8])
print(astra.configuration.common_config.workload)


# %% [markdown]
# ##### Configure ASTRA-sim system config

# %%
astra.configuration.common_config.system.scheduling_policy = astra.configuration.common_config.system.LIFO
astra.configuration.common_config.system.endpoint_delay = 10
astra.configuration.common_config.system.active_chunks_per_dimension = 1
astra.configuration.common_config.system.all_gather_implementation = [astra.configuration.common_config.system.RING]
astra.configuration.common_config.system.all_to_all_implementation = [astra.configuration.common_config.system.DIRECT]
astra.configuration.common_config.system.all_reduce_implementation = [astra.configuration.common_config.system.RING]
astra.configuration.common_config.system.collective_optimization = astra.configuration.common_config.system.LOCALBWAWARE
astra.configuration.common_config.system.local_mem_bw = 1600
print(astra.configuration.common_config.system)


# %% [markdown]
# ##### Configure ASTRA-sim remote memory configuration

# %%
astra.configuration.common_config.remote_memory.memory_type = astra.configuration.common_config.remote_memory.NO_MEMORY_EXPANSION
print(astra.configuration.common_config.remote_memory)


# %% [markdown]
# ##### Configure the network backend and topology

# %%
# astra.configuration.network_backend.choice = astra.configuration.network_backend.ANALYTICAL_CONGESTION_UNAWARE
astra.configuration.network_backend.analytical_congestion_aware.topology.network.clear()
astra.configuration.network_backend.analytical_congestion_unaware.topology.network.add("fullyconnected", 8, 100, 0.005) # add(type_of_topology, number_of_nodes, bandwidth_in_gbps, latency_in_ns)
print("Network backend set to", astra.configuration.network_backend.choice)
print("network backend choice set to:",astra.configuration.network_backend.analytical_congestion_unaware.topology.choice)

# %% [markdown]
# ##### Configure ASTRA-sim cmd parameters

# %%
astra.configuration.common_config.cmd_parameters.comm_scale = 1
astra.configuration.common_config.cmd_parameters.rendezvous_protocol = False
astra.configuration.common_config.cmd_parameters.injection_scale = 1


# %% [markdown]
# #### Start the simulation by specifying the network backend

# %%
astra.run_simulation(NetworkBackend.ANALYTICAL_CONGESTION_UNAWARE)

# %% [markdown]
# ##### Download all the configurations as a zip

# %%
astra.download_configuration()

