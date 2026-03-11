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
sys.path.append("../../utils")
import networkx
import astra_sim_sdk.astra_sim_sdk as astra_sim_kit
from astra_sim import AstraSim, Collective, NetworkBackend
from infragraph.infragraph_service import InfraGraphService
from infragraph.blueprints.fabrics.clos_fat_tree_fabric import ClosFatTreeFabric
from infragraph.blueprints.devices.generic.server import Server
from infragraph.blueprints.devices.generic.generic_switch import Switch

# %% [markdown]
# ##### Call the AstraSim client helper with the server endpoint and tag to connect to the ASTRA-sim gRPC server, initialize the SDK, and create a tagged folder for configs, results, and logs

# %%
astra = AstraSim(server_endpoint = "172.17.0.2:8989", tag = "htsim_clos_fabric_3tier")

# %% [markdown]
# ##### Create a three-tier clos fabric using infragraph fabric blueprint

# %%
server = Server()
switch = Switch(port_count=8)
infrastructure = ClosFatTreeFabric(switch, server, 3,[])
astra.configuration.infragraph.infrastructure.deserialize(infrastructure.serialize())
print(astra.configuration.infragraph.infrastructure)

# %% [markdown]
# ##### Initialize the Infragraph service, display the fabric topology, and retrieve/set the total number of NPUs to generate the collective

# %%
service = InfraGraphService()
service.set_graph(infrastructure)
g = service.get_networkx_graph()
print(networkx.write_network_text(g, vertical_chains=True))
total_npus = 64

# %% [markdown]
# ##### Generate workload execution traces for each rank and set the required data size for AstraSim configuration

# %%
astra.configuration.common_config.workload = astra.generate_collective(collective=Collective.ALLREDUCE, coll_size= 1 *1024*1024, npu_range=[0, total_npus])

# %% [markdown]
# ##### Configure ASTRA-sim system config

# %%
astra.configuration.common_config.system.scheduling_policy = astra.configuration.common_config.system.LIFO
astra.configuration.common_config.system.endpoint_delay = 10
astra.configuration.common_config.system.active_chunks_per_dimension = 1
astra.configuration.common_config.system.preferred_dataset_splits = 4
astra.configuration.common_config.system.all_gather_implementation = [astra.configuration.common_config.system.RING]
astra.configuration.common_config.system.all_to_all_implementation = [astra.configuration.common_config.system.DIRECT]
astra.configuration.common_config.system.all_reduce_implementation = [astra.configuration.common_config.system.RING]
astra.configuration.common_config.system.collective_optimization = astra.configuration.common_config.system.LOCALBWAWARE
astra.configuration.common_config.system.local_mem_bw = 1600
astra.configuration.common_config.system.peak_perf = 900
astra.configuration.common_config.system.roofline_enabled = 0
print(astra.configuration.common_config.system)



# %% [markdown]
# ##### Configure ASTRA-sim remote memory configuration

# %%
astra.configuration.common_config.remote_memory.memory_type = astra.configuration.common_config.remote_memory.NO_MEMORY_EXPANSION
print(astra.configuration.common_config.remote_memory)

# %% [markdown]
# ##### Configure the selected network backend and the topology (infragraph or network_topology_configuration)

# %%
astra.configuration.network_backend.choice = astra.configuration.network_backend.HTSIM
astra.configuration.network_backend.htsim.topology.choice = astra.configuration.network_backend.htsim.topology.INFRAGRAPH

# %% [markdown]
# ##### Select htsim protocol

# %%
astra.configuration.network_backend.htsim.htsim_protocol.choice = astra.configuration.network_backend.htsim.htsim_protocol.TCP
print("Network backend set to", astra.configuration.network_backend.choice)
print("network topology choice set to:",astra.configuration.network_backend.htsim.topology.choice)
print("protocol set to", astra.configuration.network_backend.htsim.htsim_protocol)
astra.configuration.network_backend.htsim.htsim_protocol.tcp.nodes = str(total_npus)

# %% [markdown]
# ##### Adding ASTRA-sim - Infragraph specific annotation

# %%
host_device_spec = astra_sim_kit.AnnotationDeviceSpecifications()
host_device_spec.device_bandwidth_gbps = 1000
host_device_spec.device_latency_ms = 0.005
host_device_spec.device_name = "server"
host_device_spec.device_type = "host"
astra.configuration.infragraph.annotations.device_specifications.append(host_device_spec)

switch_device_spec = astra_sim_kit.AnnotationDeviceSpecifications()
switch_device_spec.device_bandwidth_gbps = 1000
switch_device_spec.device_latency_ms = 0.005
switch_device_spec.device_name = "switch"
switch_device_spec.device_type = "switch"
astra.configuration.infragraph.annotations.device_specifications.append(
    switch_device_spec
)

# %% [markdown]
# ##### Configure ASTRA-sim cmd parameters

# %%
astra.configuration.common_config.cmd_parameters.comm_scale = 1
astra.configuration.common_config.cmd_parameters.injection_scale = 1
astra.configuration.common_config.cmd_parameters.rendezvous_protocol = False

# %% [markdown]
# #### Start the simulation by specifying the network backend

# %%
astra.run_simulation(NetworkBackend.HTSIM)

# %% [markdown]
# ##### Download all the configurations as a zip

# %%
astra.download_configuration()

# %% [markdown]
# ##### Save infragraph as a yaml

# %%
import yaml
import os
from common import FileFolderUtils
with open(os.path.join(FileFolderUtils.get_instance().OUTPUT_DIR,"../infrastructure","htsim_clos_fabric_3tier.yaml"),"w") as f:
    data = infrastructure.serialize("dict")
    yaml.dump(data, f, default_flow_style=False, indent=4)

print("saved yaml to:", os.path.join(FileFolderUtils.get_instance().OUTPUT_DIR,"..","htsim_clos_fabric_3tier.yaml"))
