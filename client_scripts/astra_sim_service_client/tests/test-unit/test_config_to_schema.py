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

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))


from utils.config_to_schema import TranslateConfig
from utils.common import Utilities


def test_translate_remote_memory(config, resources_dir):
    """
    Tests remote memory translation - script to schema
    """
    test_file_path = os.path.join(resources_dir, "RemoteMemory.json")
    TranslateConfig.translate_remote_memory(test_file_path, config)
    assert config.common_config.remote_memory.memory_type == "NO_MEMORY_EXPANSION"


def test_translate_nc_topology_configuration(config, resources_dir):
    """
    Tests ns3 nc topology translation - script to schema
    """
    test_file_path = os.path.join(resources_dir, "nc-topology-file.txt")
    expected_total_nodes = 37
    expected_len_switch_ids = 5
    TranslateConfig.translate_ns3_nc_topology_configuration(test_file_path, config)
    assert config.network_backend.ns3.topology.nc_topology.total_nodes == expected_total_nodes
    assert len(config.network_backend.ns3.topology.nc_topology.switch_ids) == expected_len_switch_ids


def test_translate_system_configuration(config, resources_dir):
    """
    Tests system configuration translation - script to schema
    """
    test_file_path = os.path.join(resources_dir, "system.json")
    TranslateConfig.translate_system_configuration(test_file_path, config)
    expected_endpoint_delay = 10
    system_dict = Utilities.to_dict(config.common_config.system)
    assert config.common_config.system.endpoint_delay == expected_endpoint_delay
    assert "latency" in system_dict
    assert "active-chunks-per-dimension" not in system_dict


def test_translate_communicator_configuration(config, resources_dir):
    """
    Tests communicator group configuration translation - script to schema
    """
    test_file_path = os.path.join(resources_dir, "communicator_group.json")
    TranslateConfig.translate_communicator_configuration(test_file_path, config)
    communicator_list = Utilities.to_dict(config.common_config.communicator_group)
    expected_no_of_groups = 2
    assert len(communicator_list) == expected_no_of_groups


def test_translate_ns3_network_configuration(config, resources_dir):
    """
    Tests ns3 network configuration translation - script to schema
    """
    test_file_path = os.path.join(resources_dir, "network_config.txt")
    TranslateConfig.translate_ns3_network_configuration(test_file_path, config)
    network_dict = Utilities.to_dict(config.network_backend.ns3.network)
    expected_buffer_size = 64
    assert network_dict.get("buffer_size", 0) == expected_buffer_size
    assert isinstance(network_dict["link_down"], list)
    assert all(isinstance(x, int) for x in network_dict["link_down"])
    for key in [
        "fct_output_file",
        "flow_file",
        "pfc_output_file",
        "qlen_mon_file",
        "trace_file",
        "trace_output_file",
        "topology_file",
    ]:
        assert isinstance(network_dict[key], str)
        assert network_dict[key] != ""
    for key in ["rate_ai", "rate_hai", "min_rate", "dctcp_rate_ai"]:
        assert isinstance(network_dict[key], str)
        assert network_dict[key].endswith("Mb/s") or network_dict[key].endswith("Gb/s")


def test_translate_ns3_logical_configuration(config, resources_dir):
    """
    Tests ns3 logical configuration translation - script to schema
    """
    test_file_path = os.path.join(resources_dir, "logical.json")
    TranslateConfig.translate_ns3_logical_configuration(test_file_path, config)
    logical_list = config.network_backend.ns3.logical_topology.logical_dimensions
    assert len(logical_list) >= 1
    for elem in logical_list:
        assert isinstance(elem, str)


def test_translate_analytical_network_configuration(config, resources_dir):
    """
    Tests analytical network configuration translation - script to schema
    """
    config.network_backend.choice = config.network_backend.ANALYTICAL_CONGESTION_AWARE
    test_file_path = os.path.join(resources_dir, "network.yaml")
    TranslateConfig.translate_analytical_network(test_file_path, config, "analytical_congestion_aware")
    backend_choice = config.network_backend.choice.lower()
    config_network = getattr(config.network_backend, backend_choice)
    config_topo = config_network.topology.network
    serialized = config_topo.serialize("dict")
    assert len(serialized) == 2
    for element in serialized:
        assert "topology" in element
        assert element["topology"] is not None
        assert isinstance(element["latency"], float)


def test_translate_htsim_fattree_topo_configuration(config, resources_dir):
    """
    Tests htsim fat tree topology translation - script to schema
    """
    test_file_path = os.path.join(resources_dir, "8nodes.topo")
    TranslateConfig.translate_htsim_fat_tree_topology(test_file_path, config)
    config_network_topo = (
        config.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree
    )
    assert config_network_topo.nodes == 8
    assert config_network_topo.tier_1.bundle == 1


def test_translate_ns3_trace_file_to_schema(config, resources_dir):
    """
    Tests ns3 trace file translation - script to schema
    """
    test_file_path = os.path.join(resources_dir, "trace.txt")
    TranslateConfig.translate_ns3_trace_file_to_schema(test_file_path, config)
    trace_list = config.network_backend.ns3.trace.trace_ids
    assert isinstance(trace_list, list)
    assert len(trace_list) != 0
    assert len(trace_list) == len(set(trace_list))


def test_translate_logging_configuration_to_schema(config, resources_dir):
    """
    Tests logging configuration file translation - script to schema
    """
    test_file_path = os.path.join(resources_dir, "logging_config.toml")
    TranslateConfig.translate_logging_file_to_schema(test_file_path, config)
    sinks = list(config.common_config.logging.sink)
    loggers = list(config.common_config.logging.logger)
    assert len(sinks) > 0
    assert len(loggers) > 0
