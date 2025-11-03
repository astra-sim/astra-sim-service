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
import shutil
import json
import zipfile
import struct
import pandas as pd

pd.options.mode.chained_assignment = None


class FileFolderUtils:
    """
    Class that holds the file folder utilities and the paths
    """

    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(FileFolderUtils, cls).__new__(cls)
        return cls._instance

    @classmethod
    def get_instance(cls):
        """
        Returns the instance of the FileFolderUtils class
        """
        return cls._instance

    UTILS_PATH = os.path.abspath(__file__)
    SRC_DIR = os.path.dirname(UTILS_PATH)
    HOME_DIR = os.path.join(SRC_DIR, "..")

    def __init__(self, tag=""):
        if not self._initialized:
            self._initialized = True
            if tag == "":
                tag = "new_run"
            self.tag_name = tag
            self.TRIAL_DIR = ""
            self.TAG_DIR = ""
            self.INFRA_DIR = ""
            self.CONFIG_DIR = ""
            self.OUTPUT_DIR = ""
            self.ZIP_DIR = ""
            self.ZIP_FILE_NAME = r"config.zip"
            self.INFRA_JSON_FILENAME = "infra.json"
            self.BIND_JSON_FILENAME = "bind.json"
            self.NETWORK_CONFIGURATION_FILENAME = "network_config.txt"
            self.NS3_TOPOLOGY_FILENAME = "nc-topology-file.txt"
            self.REMOTE_MEMORY_FILENAME = "RemoteMemory.json"
            self.SYSTEM_CONFIGURATION_FILENAME = "system.json"
            self.LOGICAL_TOPOLOGY_FILENAME = "logical.json"
            self.ZIP_PATH = ""
            self.WORKLOAD_DIR = "workload"
            self.set_tag(tag)

    def set_tag(self, tag):
        """
        Sets the tag - creates the folders and subfolders with the tag name to provide unique testing configurations and results
        """
        self.tag_name = tag
        self.TRIAL_DIR = os.path.join(FileFolderUtils.HOME_DIR, "trial")
        self.TAG_DIR = os.path.join(self.TRIAL_DIR, self.tag_name)
        self.INFRA_DIR = os.path.join(self.TAG_DIR, "infrastructure")
        self.CONFIG_DIR = os.path.join(self.TAG_DIR, "configuration")
        self.OUTPUT_DIR = os.path.join(self.TAG_DIR, "output")
        self.ZIP_DIR = os.path.join(self.TAG_DIR, "zip_dir")
        self.ZIP_PATH = os.path.join(self.TAG_DIR, self.ZIP_FILE_NAME)
        self.reset_directories()

    def reset_directories(self):
        """
        Resets the directories: INFRA_DIR, CONFIG_DIR, OUTPUT_DIR, ZIP_DIR
        """
        print("Resetting test directory")
        Utilities.delete_folder(self.TAG_DIR)
        Utilities.delete_folder(self.INFRA_DIR)
        Utilities.delete_folder(self.CONFIG_DIR)
        Utilities.delete_folder(self.OUTPUT_DIR)
        Utilities.delete_folder(self.ZIP_DIR)

        Utilities.create_folder(self.TAG_DIR)
        Utilities.create_folder(self.INFRA_DIR)
        Utilities.create_folder(self.CONFIG_DIR)
        Utilities.create_folder(self.OUTPUT_DIR)
        Utilities.create_folder(self.ZIP_DIR)


class Utilities:
    """
    Utilities class that has multiple static function calls like zip_folder, delete_folder, create_folder and so on
    """

    @staticmethod
    def zip_folder(folder_path: str, output_path: str):
        """
        Function that zip a given folder - files and subdirectories inside it and dumps to an output path
        Note that the output path is a full path of the zip file and the directories mentioned in the path should exist
        """
        print("output_path: " + output_path)
        print("folder_path: " + folder_path)
        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, folder_path)
                    zipf.write(file_path, arcname)

    @staticmethod
    def delete_folder(folder):
        """
        Function that deletes a folder and its contents
        """
        if not os.path.exists(folder):
            # print(f"The folder {folder} does not exist.")
            return

        for filename in os.listdir(folder):
            file_path = os.path.join(folder, filename)

            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print(f"Failed to delete {file_path}. Reason: {e}")

        os.rmdir(folder)
        print("All contents of the folder " + folder + " have been deleted.")

    @staticmethod
    def create_folder(folder: str):
        """
        Function that creates a folder from the parameter: folder
        """
        try:
            if not os.path.exists(folder):
                os.makedirs(folder)
                # print(f"Folder created at: {folder}")
            else:
                print(f"Folder already exists at: {folder}")
        except Exception as e:
            print(f"An error occurred: {e}")

    @staticmethod
    def encode_variant_32(out_file, value):
        """
        The encoding of the Varint32 is copied from
        google.protobuf.internal.encoder and is only repeated here to
        avoid depending on the internal functions in the library.
        """
        bits = value & 0x7F
        value >>= 7
        while value:
            out_file.write(struct.pack("<B", 0x80 | bits))
            bits = value & 0x7F
            value >>= 7
        out_file.write(struct.pack("<B", bits))

    @staticmethod
    def encode_message(out_file, message):
        """
        Encoded a message with the length prepended as a 32-bit varint.
        """
        out = message.SerializeToString()
        Utilities.encode_variant_32(out_file, len(out))
        out_file.write(out)

    @staticmethod
    def serialize_ns3_configuration_to_dict(file_path: str) -> dict:
        """
        Function that parses the ns3 network file and returns a dictionary
        """
        config = {}
        special_keys = {"KMAX_MAP", "KMIN_MAP", "PMAX_MAP"}
        with open(file_path, "r", encoding="utf-8") as network_file:
            for line in network_file:
                line_parts = line.strip().split()
                if not line_parts:
                    continue
                key, values = line_parts[0], line_parts[1:]
                if key in special_keys:
                    config[key] = " ".join(values)
                else:
                    if len(values) == 1:
                        config[key] = values[0]
                    else:
                        config[key] = values
        return config

    @staticmethod
    def to_dict(obj):
        """Safe conversion: works whether serialize() returns str or dict."""
        serialized = obj.serialize()
        return json.loads(serialized) if isinstance(serialized, str) else serialized


class StatUtil:
    """
    Class that holds the utilities for statistics
    """

    @staticmethod
    def ns3_flow_statistics():
        """
        This generates ns3 flow statistics by reading fct.txt
        """
        df = pd.read_csv(
            os.path.join(FileFolderUtils().OUTPUT_DIR, "fct.txt"),
            delim_whitespace=True,
            header=None,
        )

        df.columns = [
            "Source ip",
            "Destination ip",
            "Source Port",
            "Destination Port",
            "Data size (B)",
            "Start Time",
            "FCT",
            "Standalone FCT",
        ]
        df["Source ip"] = df["Source ip"].apply(StatUtil.hex_to_ip)
        df["Destination ip"] = df["Destination ip"].apply(StatUtil.hex_to_ip)
        df["Total Bytes Tx"] = df["Data size (B)"]
        df["Total Bytes Rx"] = df["Total Bytes Tx"]
        df["Completion time (ms)"] = df["FCT"] / 1000000
        df["Start (ms)"] = df["Start Time"] / 1000000
        df["End (ms)"] = df["Start (ms)"] + df["Completion time (ms)"]
        df["FCT"] = df["FCT"].astype(int)

        df.to_csv(os.path.join(FileFolderUtils().OUTPUT_DIR, "flow_stats.csv"), index=False)
        print(
            "Generated: flow_stats.csv at: ",
            os.path.join(FileFolderUtils().OUTPUT_DIR, "flow_stats.csv"),
        )
        return df

    @staticmethod
    def ns3_fct_csv():
        """
        This generates ns3 fct statistics by reading fct.txt - creates a dataframe from the txt file
        """
        df = pd.read_csv(
            os.path.join(FileFolderUtils().OUTPUT_DIR, "fct.txt"),
            delim_whitespace=True,
            header=None,
        )
        df.columns = [
            "Source Hex ip",
            "Destination Hex ip",
            "Source Port",
            "Destination Port",
            "Data size (B)",
            "Start Time",
            "FCT",
            "Standalone FCT",
        ]

        df.to_csv(os.path.join(FileFolderUtils().OUTPUT_DIR, "fct.csv"), index=False)
        print("Generated fct.csv at: ", os.path.join(FileFolderUtils().OUTPUT_DIR, "fct.csv"))
        return df

    @staticmethod
    def hex_to_ip(hex_str):
        """
        static method that converts a hex string to an IP Address
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
        except ValueError:
            return "Invalid Hex"
