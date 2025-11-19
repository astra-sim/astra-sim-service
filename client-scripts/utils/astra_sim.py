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
import grpc
from enum import Enum
import pandas as pd

from chakra.schema.protobuf.et_def_pb2 import (
    Node as ChakraNode,
    BoolList,
    GlobalMetadata,
    AttributeProto as ChakraAttr,
    COMM_COLL_NODE,
    ALL_REDUCE,
    ALL_TO_ALL,
    BARRIER,
    REDUCE,
    REDUCE_SCATTER,
    GATHER,
)

from common import Utilities, FileFolderUtils, StatUtil

from astra_sim_client import AstraSimClient
import astra_sim_sdk.astra_sim_sdk as astra_sim_sdk

pd.options.mode.chained_assignment = None


class Collective(Enum):
    """
    Enum class that holds the collective name to string name
    """

    ALLREDUCE = "allreduce"
    ALLTOALL = "alltoall"
    BARRIER = "barrier"
    REDUCE = "reduce"
    REDUCESCATTER = "reducescatter"
    GATHER = "gather"


class NetworkBackend(Enum):
    """
    Enum class that holds the network backend name to string name
    """

    ANALYTICAL_CONGESTION_AWARE = "ANALYTICAL_CONGESTION_AWARE"
    ANALYTICAL_CONGESTION_UNAWARE = "ANALYTICAL_CONGESTION_UNAWARE"
    NS3 = "NS3"
    HTSIM = "HTSIM"


class AstraSim:
    """
    Root class that is used to configure the server, configure astra-sim and run simulation
    """

    def __init__(
        self,
        server_endpoint,
        tag="",
        backend_name="NS3",
    ):
        self._server_endpoint = server_endpoint
        self._astra_sim_client = AstraSimClient()
        FileFolderUtils(tag)
        self.configuration = astra_sim_sdk.Config()
        self._backend_name = backend_name
        self.tag = tag
        self._validate_server_endpoint()

    def _validate_server_endpoint(self):
        """
        Validate if a gRPC server is reachable.
        """
        try:
            channel = grpc.insecure_channel(self._server_endpoint)
            grpc.channel_ready_future(channel).result(timeout=2)
            print(f"Successfully connected to gRPC server at {self._server_endpoint}")

        except grpc.FutureTimeoutError as exc:
            raise ConnectionError(
                f"Could not connect to gRPC server at {self._server_endpoint}. "
                "Ensure the server is running and reachable."
            ) from exc

    def generate_collective(self, collective, coll_size, npu_range):
        """
        This is a wrapper on top of generate_chakra_node to generate the collective
        """
        if not npu_range:
            print("NPU range is not defined")
            return ""

        if len(npu_range) < 2:
            print("NPU range not set correctly")
            return ""

        return WorkloadConfiguration.generate_chakra_node(
            collective=collective, coll_size=coll_size, npu_range=npu_range, tag=self.tag
        )

    def run_simulation(self, network_backend):
        """
        A wrapper call over multiple operations allowing to upload, run, and download files for a simulation
        """
        self._astra_sim_client.set_url(self._server_endpoint)  # type: ignore
        self._astra_sim_client.pack_zip()
        self._astra_sim_client.upload_config()
        self._astra_sim_client.set_config(self.configuration)
        self._astra_sim_client.run_simulation(network_backend.value)
        self._astra_sim_client.get_config()
        while True:
            status = self._astra_sim_client.get_status()
            if status in ["completed", "failed", "terminated"]:
                break
            print(f"astra-sim server Status: {status}")
            time.sleep(2)
        self._astra_sim_client.get_file("simulation.log")
        if self._astra_sim_client.get_status() in ["failed", "terminated"]:
            print("Simulation " + self._astra_sim_client.get_status())
        else:
            print("Downloading Output files....")
            self._astra_sim_client.download_files()
            print("All files downloaded Successfully")
            if network_backend.value == "NS3":
                print("Translating Metrics...")
                if self._backend_name == "NS3":
                    StatUtil.ns3_fct_csv()
                    StatUtil.ns3_flow_statistics()
                print("All metrics translated successfully")
            print("Simulation completed")


class WorkloadConfiguration:
    """
    Static class that handles the chakra workload confiuration
    """

    @staticmethod
    def get_collectives():
        """
        Returns all the supported collective
        """
        return """
        Supported:
            ALL_REDUCE
            ALL_GATHER
            ALL_TO_ALL
            BARRIER
            REDUCE
            REDUCE_SCATTER_BLOCK
            GATHER
        Not Supported:
            REDUCE_SCATTER
            BROADCAST
            ALL_GATHER
"""

    @staticmethod
    def generate_chakra_node(collective, npu_range, coll_size, tag):
        """
        This generates the chakra node for the given npu range [m - n], the collective and collective_size inside the tag directory
        """
        collective = collective.value
        collective_dir = os.path.join(FileFolderUtils().CONFIG_DIR, FileFolderUtils().WORKLOAD_DIR)
        Utilities.delete_folder(collective_dir)

        os.makedirs(collective_dir)

        for npu_id in range(npu_range[0], npu_range[1]):
            output_filename = f"{collective_dir}/{tag}.{str(npu_id)}.et"
            with open(output_filename, "wb") as et:
                # Chakra Metadata
                Utilities.encode_message(et, GlobalMetadata(version="0.0.4"))

                # create Chakra Node
                node = ChakraNode()
                node.id = 1
                node.name = collective
                node.type = COMM_COLL_NODE

                # assign attributes
                node.attr.append(ChakraAttr(name="is_cpu_op", bool_val=False))
                if collective == "allreduce":
                    node.attr.append(ChakraAttr(name="comm_type", int64_val=ALL_REDUCE))
                elif collective == "alltoall":
                    node.attr.append(ChakraAttr(name="comm_type", int64_val=ALL_TO_ALL))
                elif collective == "barrier":
                    node.attr.append(ChakraAttr(name="comm_type", int64_val=BARRIER))
                elif collective == "reduce":
                    node.attr.append(ChakraAttr(name="comm_type", int64_val=REDUCE))
                elif collective == "reducescatter":
                    node.attr.append(ChakraAttr(name="comm_type", int64_val=REDUCE_SCATTER))
                elif collective == "gather":
                    node.attr.append(ChakraAttr(name="comm_type", int64_val=GATHER))
                node.attr.append(ChakraAttr(name="comm_size", int64_val=coll_size))
                node.attr.append(ChakraAttr(name="involved_dim", bool_list=BoolList(values=[True])))

                # store Chakra ET file
                Utilities.encode_message(et, node)
        print("Generated " + str(npu_range[1] - npu_range[0]) + " et in " + collective_dir)
        return os.path.join(FileFolderUtils().WORKLOAD_DIR, tag)
