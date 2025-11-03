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
import shutil
import zipfile
from enum import Enum
import hashlib
from pathlib import Path
import datetime
import logging
import grpc

module_logger = logging.getLogger("ASTRA-sim Server:Utilities")
logger = logging.LoggerAdapter(module_logger)


class Constants:
    """
    A dataclass that holds various constants and strings
    """

    SERVER_PATH = os.path.abspath(__file__)
    SERVER_DIR = os.path.dirname(SERVER_PATH)
    DEFAULT_PORT_NUM = 8989

    TEST_RUN_DIR = os.path.join(SERVER_DIR, "test_run")
    CONFIGURATION_DIR = os.path.join(TEST_RUN_DIR, "configuration")
    SYSTEM_JSON = os.path.join(CONFIGURATION_DIR, "system.json")
    REMOTE_MEMORY_JSON = os.path.join(CONFIGURATION_DIR, "remote_memory.json")
    LOGGING_TOML_FILE = os.path.join(CONFIGURATION_DIR, "logging_conf.toml")
    COMMUNICATOR_GROUP_JSON = os.path.join(CONFIGURATION_DIR, "communicator_group.json")
    NS3_NETWORK_TXT = os.path.join(CONFIGURATION_DIR, "network_config.txt")
    NS3_LOGICAL_TOPOLOGY = os.path.join(CONFIGURATION_DIR, "logical.json")
    NS3_PHYSICAL_TOPOLOGY = os.path.join(CONFIGURATION_DIR, "nc-topology-file.txt")
    ANALYTICAL_NETWORK_TOPOLOGY = os.path.join(
        CONFIGURATION_DIR, "analytical_network.yml"
    )

    RESULTS_DIR = os.path.join(TEST_RUN_DIR, "results")
    RESULTS_ZIP = os.path.join(TEST_RUN_DIR, "results.zip")
    NS3_FLOW_FILE = os.path.join(RESULTS_DIR, "flow.txt")
    NS3_TRACE_FILE = os.path.join(CONFIGURATION_DIR, "trace.txt")
    NS3_TRACE_OUTPUT_FILE = os.path.join(RESULTS_DIR, "trace_out.tr")
    NS3_FCT_OUTPUT_FILE = os.path.join(RESULTS_DIR, "fct.txt")
    NS3_PFC_OUTPUT_FILE = os.path.join(RESULTS_DIR, "pfc.txt")
    NS3_QLEN_MON_FILE = os.path.join(RESULTS_DIR, "qlen.txt")
    NS3_GEN_TR_FILE = os.path.join(RESULTS_DIR, "generated_trace.csv")
    VALID_TARGETS = [
        "fct.txt",
        "qlen.txt",
        "flow.txt",
        "pfc.txt",
        "trace_out.tr",
        "trace.txt",
    ]

    HTSIM_TCPFLOW_LOG_FILENAME = "tcp_flow.log"
    HTSIM_TOPOLOGY = os.path.join(CONFIGURATION_DIR, "htsim.topo")

    CONFIGURATION = "configuration"
    SERVER_CONFIGURATION = "server_configuration"

    MOCK_OUT_DIR = os.path.join(SERVER_DIR, "..", "resources", "mock_output")

    RUN_STATUS_FILE = "run_status.txt"


class SimulationStatus(Enum):
    """
    enum class that holds the simulation status
    """

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TERMINATED = "terminated"
    INACTIVE = "inactive"


class Utilities:
    """
    Utilities class that hold various utilities
    """

    @staticmethod
    def move_file(src: str, dest: str) -> None:
        """
        Function that moves source file to destination path
        """
        shutil.move(src, dest)

    @staticmethod
    def reset_test_run_folder() -> None:
        """
        This resets the trial test run folder and creates new directories
        """
        Utilities.delete_folder(Constants.TEST_RUN_DIR)
        Utilities.delete_folder(Constants.CONFIGURATION_DIR)
        Utilities.delete_folder(Constants.RESULTS_DIR)

        Utilities.create_folder(Constants.TEST_RUN_DIR)
        Utilities.create_folder(Constants.CONFIGURATION_DIR)
        Utilities.create_folder(Constants.RESULTS_DIR)

    @staticmethod
    def is_file_or_folder_present(path: str) -> bool:
        """
        This checks if a file/folder is present
        """
        if os.path.exists(path):
            if os.path.isdir(path):
                if any(os.path.isfile(os.path.join(path, f)) for f in os.listdir(path)):
                    return True
                else:
                    return False
            return True
        return False

    @staticmethod
    def create_folder(folder: str) -> None:
        """
        Function that helps in creating nested directories from the path provided as an input
        """
        try:
            os.makedirs(folder, exist_ok=True)
        except PermissionError as e:
            logger.error(f"Permission denied: Cannot create folder at {folder}")
            raise PermissionError(
                "Permission denied: Cannot create folder",
                grpc.StatusCode.PERMISSION_DENIED,
                403,
            ) from e

        except FileNotFoundError as e:
            logger.error(f"Error creating folder {folder}: {e}")
            raise FileNotFoundError(
                "Unknown error: Failed to create folder", grpc.StatusCode.UNKNOWN, 500
            ) from e

    @staticmethod
    def delete_folder(folder: str) -> None:
        """
        Function that deletes the folder and its contents - path is provided as a input to the function
        """
        if not os.path.exists(folder):
            return
        for filename in os.listdir(folder):
            file_path = os.path.join(folder, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                logger.error(f"Error deleting {file_path}: {e}")
                raise Exception(
                    f"Failed to delete {file_path}", grpc.StatusCode.INTERNAL, 500
                ) from e
        os.rmdir(folder)

    @staticmethod
    def delete_file(file: str) -> None:
        """
        Function that deletes the file provided as an argument to the funtion
        """
        if os.path.exists(file):
            os.remove(file)
        else:
            logger.debug(f"{file} does not exist")

    @staticmethod
    def extract_zip(
        zip_path: str, output_path: str = Constants.CONFIGURATION_DIR
    ) -> bool:
        """
        Function that extracts the zipfile to the configuration directory
        """
        try:
            logger.info(f"Extracting {zip_path}")
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(output_path)
                logger.info(f"Extracted all files to: {output_path}")
            return True
        except zipfile.BadZipFile:
            return False

    @staticmethod
    def zip_folder(folder_path: str, output_path: str) -> None:
        """
        Function that zips the provided folder path to the output_path
        """
        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, folder_path)
                    zipf.write(file_path, arcname)

    @staticmethod
    def create_file(file_path: str) -> None:
        """
        Function that creates an empty file in the given filepath
        """
        with open(file_path, "w", encoding="utf-8") as _:
            pass

    @staticmethod
    def hex_to_ip(hex_str: str) -> str:
        """
        Function that translates hex to ip. Both are in string format
        """
        try:
            hex_str = hex_str.replace("a", "A")
            hex_str = hex_str.replace("b", "B")
            hex_str = hex_str.replace("c", "C")
            hex_str = hex_str.replace("d", "D")
            hex_str = hex_str.replace("e", "E")
            hex_str = hex_str.replace("f", "F")
            # Ensure it's exactly 6 hex digits
            # Convert to integer
            num = int(hex_str, 16)
            octet1 = (num >> 24) & 0xFF
            octet2 = (num >> 16) & 0xFF
            octet3 = (num >> 8) & 0xFF
            octet4 = num & 0xFF
            # Format as IPv4 address
            return f"{octet1}.{octet2}.{octet3}.{octet4}"
        except ValueError as e:
            logger.error("Invalid hex value encountered")
            raise ValueError(
                "Invalid Hex", grpc.StatusCode.INVALID_ARGUMENT, 400
            ) from e

    @staticmethod
    def read_json_file(file_path: str) -> dict:
        """
        Function that reads json file from the provided file_path and returns a dict
        """
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
        return data

    @staticmethod
    def copy_file(source_path: str, destination_path: str) -> None:
        """
        Function that copies a file from source_path to the destination_path
        """
        try:
            # Check if source file exists
            if not os.path.isfile(source_path):
                raise FileNotFoundError(
                    f"Source file not found: {source_path}",
                    grpc.StatusCode.NOT_FOUND,
                    404,
                )

            # Ensure destination directory exists
            os.makedirs(os.path.dirname(destination_path), exist_ok=True)

            # Copy the file
            shutil.copy(source_path, destination_path)
            logger.info(
                f"File copied successfully from '{source_path}' to '{destination_path}'"
            )

        except FileNotFoundError as fnf_error:
            logger.error(fnf_error)
            raise FileNotFoundError(
                str(fnf_error), grpc.StatusCode.NOT_FOUND, 404
            ) from fnf_error

        except PermissionError as perm_error:
            logger.error("Permission denied. Please check your access rights.")
            raise PermissionError(
                "Permission denied: Access is forbidden",
                grpc.StatusCode.PERMISSION_DENIED,
                403,
            ) from perm_error

        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")
            raise Exception(
                "Internal server error", grpc.StatusCode.UNKNOWN, 500
            ) from e

    @staticmethod
    def get_file_properties(file_path: str) -> dict:
        """
        Function that returns file properties for the provided file_path
        """
        path = Path(file_path)

        # 1. File name
        file_name = path.name

        # 2. File size (in bytes)
        file_size = path.stat().st_size

        # 3. File checksum (MD5)
        def md5_checksum(file_path, chunk_size=8192):
            md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    md5.update(chunk)
            return md5.hexdigest()

        file_checksum = md5_checksum(file_path)

        # 4. File creation date (as datetime object)
        creation_timestamp = path.stat().st_ctime
        creation_date = datetime.datetime.fromtimestamp(creation_timestamp)
        return {
            "filename": file_name,
            "size": file_size,
            "checksum": file_checksum,
            "created": creation_date.strftime("%Y-%m-%d %H:%M:%S"),
        }

    @staticmethod
    def add_directory_prefix_to_file_path_list(
        directory_prefix, file_paths_list
    ) -> list:
        """Prepend a directory path to each file path"""
        return [os.path.join(directory_prefix, path) for path in file_paths_list]
