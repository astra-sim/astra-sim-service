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
import filecmp
import pytest
import json

from astra_server.configuration_handler import ConfigurationHandler
from astra_server.utils import Utilities

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESOURCES_DIR = os.path.join(SCRIPT_DIR, "..", "test-resources")


@pytest.mark.parametrize(
    "config, filename",
    [
        ("ns3_schema_config", "ns3_system.json"),
        ("analytical_schema_config", "analytical_system.json"),
    ],
)
def test_generate_system_configuration(config, filename, temp_dir, request):
    configuration = request.getfixturevalue(config)
    generated_file = os.path.join(temp_dir, filename)
    actual_file = os.path.join(RESOURCES_DIR, "system.json")
    ConfigurationHandler()._process_system_configuration(configuration, os.path.join(temp_dir, filename))
    assert Utilities.is_file_or_folder_present(generated_file) is True

    with open(actual_file) as f1, open(generated_file) as f2:
        actual = json.load(f1)
        expected = json.load(f2)
    assert expected == actual


@pytest.mark.parametrize(
    "config, filename",
    [
        ("ns3_schema_config", "ns3_comm_group.json"),
        ("analytical_schema_config", "analytical_comm_group.json"),
    ],
)
def test_generate_comm_group_configuration(config, filename, temp_dir, request):
    configuration = request.getfixturevalue(config)
    generated_file = os.path.join(temp_dir, filename)
    actual_file = os.path.join(RESOURCES_DIR, "communicator_group.json")
    ConfigurationHandler()._process_communicator_group_configuration(configuration, generated_file)
    assert Utilities.is_file_or_folder_present(generated_file) is True

    with open(actual_file) as f1, open(generated_file) as f2:
        actual = json.load(f1)
        expected = json.load(f2)
    assert expected == actual


@pytest.mark.parametrize(
    "config, filename",
    [
        ("ns3_schema_config", "ns3_remote_memory.json"),
        ("analytical_schema_config", "analytical_remote_memory.json"),
    ],
)
def test_generate_remote_memory_configuration(config, filename, temp_dir, request):
    configuration = request.getfixturevalue(config)
    generated_file = os.path.join(temp_dir, filename)
    actual_file = os.path.join(RESOURCES_DIR, "remote_memory.json")

    ConfigurationHandler()._process_remote_memory_configuration(configuration, generated_file)
    assert Utilities.is_file_or_folder_present(generated_file) is True
    with open(actual_file) as f1, open(generated_file) as f2:
        actual = json.load(f1)
        expected = json.load(f2)
    assert expected == actual


def test_generate_ns3_network_configuration(ns3_schema_config, temp_dir):
    generated_file = os.path.join(temp_dir, "ns3_network_config.txt")
    ConfigurationHandler()._generate_ns3_network_configuration(ns3_schema_config, generated_file)
    assert Utilities.is_file_or_folder_present(generated_file) is True


def test_generate_ns3_logical_topology(ns3_schema_config, temp_dir):
    generated_file = os.path.join(temp_dir, "ns3_logical_config.json")
    actual_file = os.path.join(RESOURCES_DIR, "ns3_logical_config.json")

    ConfigurationHandler()._generate_ns3_logical_topology(ns3_schema_config, generated_file)
    assert Utilities.is_file_or_folder_present(generated_file) is True
    with open(actual_file) as f1, open(generated_file) as f2:
        actual = json.load(f1)
        expected = json.load(f2)
    assert expected == actual


def test_generate_analytical_network_configuration(analytical_schema_config, temp_dir):
    generated_file = os.path.join(temp_dir, "analytical_network.yaml")
    ConfigurationHandler()._generate_analytical_network_configuration(
        analytical_schema_config, generated_file
    )
    assert Utilities.is_file_or_folder_present(generated_file) is True


def test_process_command_arguments(htsim_schema_config):
    print(ConfigurationHandler()._process_command_arguments(htsim_schema_config))
