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
import os
sys.path.append("../utils")
from config_to_schema import TranslateConfig
import astra_sim_sdk.astra_sim_sdk as astra_sim

# %% [markdown]
# ##### Initialize astra-sim sdk

# %%
config = astra_sim.Config()

# %%
RESOURCES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../resourcess/")

# %% [markdown]
# ##### Translate Remote Memory

# %%
remote_mem_path = os.path.join(RESOURCES_DIR, "RemoteMemory.json")
TranslateConfig.translate_remote_memory(remote_mem_path, config)

# %% [markdown]
# ##### Translate System Configuration

# %%
system_config_path = os.path.join(RESOURCES_DIR, "system.json")
TranslateConfig.translate_system_configuration(system_config_path, config)

# %% [markdown]
# ##### Translate Communicator group Configuration

# %%
communicator_config_path = os.path.join(RESOURCES_DIR, "communicator_group.json")
TranslateConfig.translate_communicator_configuration(communicator_config_path, config)

# %% [markdown]
# ##### Translate nc-topology Configuration
#

# %%
nc_topology_file_path = os.path.join(RESOURCES_DIR, "nc-topology-file.txt")
TranslateConfig.translate_ns3_nc_topology_configuration(nc_topology_file_path, config)

# %% [markdown]
# ##### Translate network Configuration

# %%
network_config_path = os.path.join(RESOURCES_DIR, "network_config.txt")
TranslateConfig.translate_ns3_network_configuration(network_config_path, config)

# %% [markdown]
# ##### Translate logical Configuration

# %%
logical_dim_file = os.path.join(RESOURCES_DIR, "logical.json")
TranslateConfig.translate_ns3_logical_configuration(logical_dim_file, config)

# %% [markdown]
# ##### Translate analytical network Configuration

# %%
analytical_network_file = os.path.join(RESOURCES_DIR, "network.yaml")
# There are three available backends — analytical_congestion_aware, analytical_congestion_unaware, and HTsim — all of which use the analytical_network file format, so specify the backend_name
TranslateConfig.translate_analytical_network(analytical_network_file, config, "analytical_congestion_aware")

# %% [markdown]
# ##### Translate HTsim fat tree topology

# %%
htsim_fat_tree_file = os.path.join(RESOURCES_DIR, "8nodes.topo")
TranslateConfig.translate_htsim_fat_tree_topology(htsim_fat_tree_file, config)

# %% [markdown]
# ##### Translate ns3 trace file

# %%
ns3_trace_file = os.path.join(RESOURCES_DIR, "trace.txt")
TranslateConfig.translate_ns3_trace_file_to_schema(ns3_trace_file, config)

# %% [markdown]
# ##### Translate logging file to schema

# %%
logging_toml_file = os.path.join(RESOURCES_DIR, "logging_config.toml")
TranslateConfig.translate_logging_file_to_schema(logging_toml_file, config)
