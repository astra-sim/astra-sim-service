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
import logging
import json
import zipfile
import astra_sim_sdk.astra_sim_sdk as astra_sim
from google.protobuf import json_format

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESOURCE_DIR = os.path.join(SCRIPT_DIR, "..", "resources")

AR_4_NS3_MIX = os.path.join(RESOURCE_DIR, "ar_4_ns3_mix")
CONFIGURATION_ZIP = os.path.join(AR_4_NS3_MIX, "configuration.zip")


def set_config(api: astra_sim.GrpcApi):
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
    # topology
    config.network_backend.ns3.topology.choice = (
        config.network_backend.ns3.topology.NC_TOPOLOGY
    )
    # network backend
    config.network_backend.choice = config.network_backend.NS3
    # Logical topology
    config.network_backend.ns3.logical_topology.logical_dimensions = [4]
    # NC Topology - send as file for now
    config.network_backend.ns3.topology.nc_topology.total_nodes = 5
    config.network_backend.ns3.topology.nc_topology.total_switches = 1
    config.network_backend.ns3.topology.nc_topology.total_links = 4
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
    response = api.set_config(payload=config)
    return response


def upload_config(api: astra_sim.GrpcApi):
    # create zip
    with zipfile.ZipFile(CONFIGURATION_ZIP, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(AR_4_NS3_MIX):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, AR_4_NS3_MIX)
                zipf.write(file_path, arcname)
    with open(CONFIGURATION_ZIP, "rb") as f:
        file_data = f.read()
    stub = api._get_stub()
    stream_req = api._client_stream(stub, file_data)
    res_obj = stub.streamUploadConfig(stream_req, timeout=api._request_timeout)
    response = json_format.MessageToDict(res_obj, preserving_proto_field_name=True)
    result = response.get("server_response")
    return result


def get_status(api):
    response = api.get_status()
    return response.status


def get_metadata(api):
    result = api.result()
    result.choice = "metadata"
    response = api.get_result(result)
    bytes_data = response.read()
    json_str = bytes_data.decode("utf-8")
    data_dict = json.loads(json_str)
    filelist = []
    for filedata in data_dict:
        filelist.append(filedata["filename"])
    return filelist


def get_file(api, filename):
    result = api.result()
    result.filename = filename
    response = api.get_result(result)
    bytes_data = response.read()
    file_str = bytes_data.decode("utf-8")
    return file_str


def run_simulation(api):
    control = astra_sim.Control(choice="start")
    control.start.backend = astra_sim.ControlStart.NS3
    # control.start.action = astra_sim.ControlStart.NS3
    response = api.set_control_action(control)
    return response


def test_ns3_run(port_number):
    api = astra_sim.api(
        location="0.0.0.0:{}".format(port_number),  # type: ignore
        transport=astra_sim.Transport.GRPC,
        logger=None,
        loglevel=logging.DEBUG,
    )
    api.enable_grpc_streaming = False  # type: ignore
    api.request_timeout = 180  # type: ignore

    status = "running"
    try:
        print("Get Status")
        status = get_status(api)
        assert status != "running"
    except Exception as e:
        print(e)
        raise e

    try:
        print("Uploading configuration api")
        upload_config(api)  # type: ignore
    except Exception as e:
        print(e)
        raise e

    try:
        print("Set configuration")
        set_config(api)  # type: ignore
    except Exception as e:
        print(e)
        raise e

    try:
        print("Running simulation")
        run_simulation(api)
    except Exception as e:
        print(e)
        raise e

    status = "running"
    while status == "running":
        try:
            print("Get Status")
            status = get_status(api)
            print(status)
            assert status in ["running", "completed"]
            time.sleep(2)
        except Exception as e:
            print(e)
            raise e

    assert status == "completed"
    try:
        print("Testing metadata api")
        filelist = get_metadata(api)
        assert len(filelist) > 0
    except Exception as e:
        print(e)
        raise e

    try:
        print("Testing getfile api")
        filestr = get_file(api, "fct.txt")
        assert filestr is not None
        assert filestr != ""
    except Exception as e:
        print(e)
        raise e
