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
import json
import logging
import threading

import astra_sim_sdk.astra_sim_sdk as astra_sim
from common import Utilities, FileFolderUtils


class AstraSimClient:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(AstraSimClient, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        self._url = ""
        self._api = astra_sim.api(
            location="localhost:50051",
            transport=astra_sim.Transport.GRPC,
            logger=None,
            loglevel=logging.ERROR,
        )
        self._api.enable_grpc_streaming = True  # type: ignore
        # api.chunk_size = 1
        self._api.request_timeout = 180  # type: ignore
        self._stopping_event = threading.Event()
        self._backend = None

    def set_url(self, url):
        """
        Set the service URL
        """
        self._url = url
        self._api = astra_sim.api(
            location=url,
            transport=astra_sim.Transport.GRPC,
            logger=None,
            loglevel=logging.ERROR,
        )
        self._api.enable_grpc_streaming = True  # type: ignore

    def get_api(self):
        """
        Returns the grpc api
        """
        return self._api

    def get_api_stub(self):
        """
        Returns the grpc api stub
        """
        return self.get_api()._get_stub()  # type: ignore

    def upload_config(self):
        """
        Function that uploads config from the zip path which is inside the <tag> dir name
        """
        with open(FileFolderUtils().ZIP_PATH, "rb") as f:
            file_data = f.read()
        return self.get_api().upload_config(payload=file_data)

    def set_config(self, config):
        """
        Function that sets the config in the service
        """
        response = self.get_api().set_config(payload=config)
        print(response)

    def run_simulation(self, backend):
        """
        Function that triggers simulation run in service directory
        """
        control = astra_sim.Control(choice="start")
        if "ANALYTICAL_CONGESTION_AWARE" == backend.upper():
            control.start.backend = astra_sim.ControlStart.ANALYTICAL_CONGESTION_AWARE
        elif "ANALYTICAL_CONGESTION_UNAWARE" == backend.upper():
            control.start.backend = astra_sim.ControlStart.ANALYTICAL_CONGESTION_UNAWARE
        elif "NS3" == backend.upper():
            control.start.backend = astra_sim.ControlStart.NS3
        elif "HTSIM" == backend.upper():
            control.start.backend = astra_sim.ControlStart.HTSIM
        # control.start.action = astra_sim.ControlStart.NS3
        response = self.get_api().set_control_action(control)
        print(response)

    def get_status(self):
        """
        Function to get the simulation status from service
        """
        response = self.get_api().get_status()
        return response.status  # type: ignore

    def get_file(self, filename):
        """
        Function to download the result file from service
        """
        result = self.get_api().result()
        result.filename = filename

        response = self.get_api().get_result(result)
        if response is None:
            open(os.path.join(FileFolderUtils().OUTPUT_DIR, filename), "w", encoding="utf-8").close()
        else:
            if response is not None:
                bytes_data = response.read()  # type: ignore
                # data_str = bytes_data.decode("utf-8")
                # Step 2: Decode bytes to string
                with open(os.path.join(FileFolderUtils().OUTPUT_DIR, filename), "wb") as f:
                    f.write(bytes_data)
            else:
                raise FileNotFoundError("Unable to read file")

    def get_metadata(self):
        """
        Function to download the result files metadata from service
        """
        # result = astra_sim.Result(choice="metadata")
        result = self.get_api().result()
        result.choice = "metadata"
        response = self.get_api().get_result(result)
        # Step 1: Read bytes from the stream
        bytes_data = response.read()  # type: ignore
        data = bytes_data.decode("utf-8")

        # Step 3: Parse string to dict
        data_dict = json.loads(data)
        filelist = []
        for filedata in data_dict:
            filelist.append(filedata["filename"])
        return filelist

    def download_files(self):
        """
        Function to download the result files from service
        """
        print("Transferring Files from ASTRA-sim server")
        metadata = self.get_metadata()
        if len(metadata) == 0:
            print("Result Files missing")
            return []

        # Utilities.delete_folder(FileFolderUtils().OUTPUT_DIR)

        for file in metadata:
            # download the file
            print(f"Downloading file: {file}")
            self.get_file(file)
        return metadata

    def pack_zip(self, config):
        """
        Function that zips all the workloads in the config dir
        """
        print("Generating Configuration ZIP")
        workload_dir = config.common_config.workload
        workload_parent_path = os.path.dirname(workload_dir)
        # check if zip is fine
        Utilities.zip_folder(os.path.join(workload_parent_path, ".."), FileFolderUtils().ZIP_PATH)
        print("pack_zip complete")

    def get_config(self):
        """
        Function that downloads the configuration in zip format consisting of all the files required for running the simulation.
        """
        config_response = self.get_api().get_config()
        if config_response is None:
            raise FileNotFoundError("Server couldn't return config")
        zip_bytes = config_response.read()
        print(f"Downloaded all configuration in {FileFolderUtils().SERVER_CONFIG_ZIP}")
        output_path = os.path.join(FileFolderUtils().OUTPUT_DIR, FileFolderUtils().SERVER_CONFIG_ZIP)
        with open(output_path, "wb") as f:
            f.write(zip_bytes)
