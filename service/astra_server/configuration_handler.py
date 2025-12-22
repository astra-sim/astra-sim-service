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
import logging
import json
from typing import Any, Dict, cast
import importlib.resources
import yaml
import toml
import grpc
import astra_sim_sdk.astra_sim_sdk as astra_sim

if __package__ is None or __package__ == "":
    from utils import Constants, Utilities
    from infrastructure.ns3_topology import NS3Topology
    from infrastructure.analytical_topology import AnalyticalTopology
    from infrastructure.htsim_topology import HTSimTopology
    from errors import ConfigurationError
else:
    from astra_server.utils import Constants, Utilities
    from astra_server.infrastructure.ns3_topology import NS3Topology
    from astra_server.infrastructure.analytical_topology import AnalyticalTopology
    from astra_server.infrastructure.htsim_topology import HTSimTopology
    from astra_server.errors import ConfigurationError

module_logger = logging.getLogger("ASTRA-sim Server:ConfigurationHandler")
logger = logging.LoggerAdapter(module_logger)


class SchemaProperty:
    """
    Class to hold the schema property like the property name, astra sim name and the type
    This is used to translate schema property names to astra sim names
    """

    def __init__(self, name, astra_sim_name, astra_sim_type):
        self.name = name
        self.astra_sim_name = astra_sim_name
        self.astra_sim_type = astra_sim_type


class Schema:
    """
    Class that holds the schemas and its properties and its mapping with astra-sim name
    """

    def __init__(self, name, astra_sim_name):
        self.name = name
        self.astra_sim_name = astra_sim_name
        self.properties = {}
        self.filename = ""


class ConfigurationHandler:
    """
    Singleton class that holds the validation and processing of configuration
    """

    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(ConfigurationHandler, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self._initialized = True
            self.swagger_schema = {}
            self.schema_properties = []
            self.schema_map = {}
            self.topology = ""
            self.command = []
            self.warn_messages = []
            self.load_schemas()

    def _load_swagger(self):
        module_logger.info("Loading Swagger")
        with importlib.resources.open_text("astra_sim_sdk", "openapi.yaml") as f:
            yaml_content = f.read()
        self.swagger_schema = yaml.safe_load(yaml_content)

    def _get_root_schema(self):
        return self.swagger_schema["components"]["schemas"]

    def load_schemas(self):
        """
        This loads the openapiart generated schema and creates a map of the schema with properties and astra sim name
        """
        # load the swagger
        self._load_swagger()
        # module_logger.info("Loading schema backend properties")
        for schema in self._get_root_schema():
            current_schema = self._get_root_schema()[schema]
            astra_sim_type = current_schema.get("x-astra-sim-type")
            if astra_sim_type is not None and astra_sim_type == "schema":
                new_schema = Schema(
                    name=schema,
                    astra_sim_name=schema,
                )

                for property_key, property_config in current_schema[
                    "properties"
                ].items():
                    p_name = property_config.get("x-astra-sim-name")
                    p_type = property_config.get("x-astra-sim-type")

                    if p_name:
                        # module_logger.info("Loading property: %s", property_key)
                        new_schema.properties[property_key] = SchemaProperty(
                            astra_sim_name=p_name,
                            astra_sim_type=p_type,
                            name=property_key,
                        )
                    # module_logger.info("Adding schema %s", schema)
                    self.schema_map[schema] = new_schema

    def _process_workload_configuration(self, configuration: astra_sim.Config):
        module_logger.info("Processing workload configuration")
        if configuration.common_config.get("workload") is None:
            raise ConfigurationError(
                "workload configuration not found", grpc.StatusCode.NOT_FOUND, 404
            )
        else:
            workload = configuration.common_config.workload
            # check if workload exists
            # process workload:
            module_logger.debug(
                "Checking workload in the configuration zip: %s",
                workload.split("/")[-2],
            )
            if not Utilities.is_file_or_folder_present(
                os.path.join(Constants.CONFIGURATION_DIR, workload.split("/")[-2])
            ):
                raise ConfigurationError(
                    "workload files not found", grpc.StatusCode.NOT_FOUND, 404
                )
            else:
                module_logger.debug("workload present in zip")
                configuration.common_config.workload = os.path.join(
                    Constants.CONFIGURATION_DIR,
                    workload.split("/")[-2],
                    workload.split("/")[-1],
                )
                self.command.append(
                    "--workload-configuration="
                    + os.path.join(
                        Constants.CONFIGURATION_DIR,
                        workload.split("/")[-2],
                        workload.split("/")[-1],
                    )
                )
        module_logger.info("Done processing workload configuration")

    def _process_system_configuration(
        self, configuration: astra_sim.Config, filename=""
    ):
        module_logger.info("Processing System Configuration")
        if configuration.common_config.get("system") is None:
            raise ConfigurationError(
                "system configuration not found", grpc.StatusCode.NOT_FOUND, 404
            )
        else:
            # system should be present
            # this will be a json file - we can dump it by mapping with system
            system_json = {}
            serialize_system_json = configuration.common_config.system.serialize("dict")
            clean_non_chakra = False
            schema = self.schema_map["System.Configuration"]
            for sys_prop in serialize_system_json:  # type: ignore
                if sys_prop in schema.properties:
                    # schema is present
                    # get the astra_sim_name
                    if schema.properties[sys_prop].astra_sim_name in [
                        "all-reduce-implementation-custom",
                        "all-gather-implementation-custom",
                        "all-to-all-implementation-custom",
                    ]:
                        # Prepend the config dir to the file paths
                        new_list = Utilities.add_directory_prefix_to_file_path_list(
                            Constants.CONFIGURATION_DIR, serialize_system_json[sys_prop]  # type: ignore
                        )
                        system_json[
                            schema.properties[sys_prop].astra_sim_name
                        ] = new_list
                        clean_non_chakra = True
                    else:
                        system_json[schema.properties[sys_prop].astra_sim_name] = serialize_system_json[sys_prop]  # type: ignore
            if clean_non_chakra:
                system_json.pop("all-reduce-implementation", None)
                system_json.pop("reduce-scatter-implementation", None)
                system_json.pop("all-to-all-implementation", None)
                system_json.pop("all-gather-implementation", None)

            # dump as file
            if filename is None or filename == "":
                filename = Constants.SYSTEM_JSON
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(system_json, f, indent=4, ensure_ascii=False)

            if Utilities.is_file_or_folder_present(filename):
                self.command.append("--system-configuration=" + filename)
            else:
                raise ConfigurationError(
                    "system configuration file not generated from schema",
                    grpc.StatusCode.FAILED_PRECONDITION,
                    412,
                )
        module_logger.info("Done Processing System Configuration")

    def _process_remote_memory_configuration(
        self, configuration: astra_sim.Config, filename=""
    ):
        module_logger.info("Processing remote memory configuration")
        if configuration.common_config.get("remote_memory") is None:
            raise ConfigurationError(
                "remote memory configuration not found", grpc.StatusCode.NOT_FOUND, 404
            )
        else:
            remote_memory_json = {}
            serialize_remote_json = configuration.common_config.remote_memory.serialize(
                "dict"
            )
            schema = self.schema_map["RemoteMemory"]
            for key, value in serialize_remote_json.items():  # type: ignore
                if key in schema.properties:
                    remote_memory_json[schema.properties[key].astra_sim_name] = value
            if filename is None or filename == "":
                filename = Constants.REMOTE_MEMORY_JSON
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(remote_memory_json, f, indent=4, ensure_ascii=False)

            if Utilities.is_file_or_folder_present(filename):
                self.command.append("--remote-memory-configuration=" + filename)
            else:
                raise ConfigurationError(
                    "remote memory configuration file not generated from schema",
                    grpc.StatusCode.FAILED_PRECONDITION,
                    412,
                )
        module_logger.info("Done processing remote memory configuration")

    def _process_logging_configuration(
        self, configuration: astra_sim.Config, filename=""
    ):
        module_logger.info("Processing logging configuration")
        if configuration.common_config.get("logging") is not None:
            toml_dict = {
                "sink": configuration.common_config.logging.sink.serialize("dict"),
                "logger": configuration.common_config.logging.logger.serialize("dict"),
            }
            if filename is None or filename == "":
                filename = Constants.LOGGING_TOML_FILE
            with open(filename, "w", encoding="utf-8") as f:
                toml.dump(toml_dict, f)
            if Utilities.is_file_or_folder_present(filename):
                self.command.append("--logging-configuration=" + filename)
            else:
                raise ConfigurationError(
                    "logging configuration file not generated from schema",
                    grpc.StatusCode.FAILED_PRECONDITION,
                    412,
                )
            module_logger.info("Done Processling logging configuration")

    def _process_communicator_group_configuration(
        self, configuration: astra_sim.Config, filename=""
    ):
        module_logger.info("Processing communicator group configuration")
        if configuration.common_config.get("communicator_group") is None:
            module_logger.info(
                "Communicator group configuration not present in the schema"
            )
            self.warn_messages.append(
                "Unable to generate communicator group message from schema - communicator group configuration empty"
            )
        else:
            # this will be a json file - we can dump it by mapping with system
            comm_group_json = {}
            if len(configuration.common_config.communicator_group) == 0:
                # empty
                raise ConfigurationError(
                    "Communicator group configuration present but has empty values",
                    grpc.StatusCode.INVALID_ARGUMENT,
                    400,
                )
            for comm_group in configuration.common_config.communicator_group:
                comm_group_json[comm_group.identifier] = comm_group.npu_list

            if filename is None or filename == "":
                filename = Constants.COMMUNICATOR_GROUP_JSON
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(comm_group_json, f, indent=4, ensure_ascii=False)
            if Utilities.is_file_or_folder_present(filename):
                self.command.append("--comm-group-configuration=" + filename)
            else:
                raise ConfigurationError(
                    "communicator group configuration file not generated from schema",
                    grpc.StatusCode.FAILED_PRECONDITION,
                    412,
                )

        module_logger.info("Done processing communicator group configuration")

    def _process_command_arguments(self, configuration: astra_sim.Config):
        module_logger.info("Processing command arguments")
        arg_list = []
        if configuration.common_config.get("cmd_parameters") is not None:
            # parse cmd_parameters
            cmd_params = configuration.common_config.cmd_parameters.serialize("dict")
            schema = self.schema_map["Command.Arguments"]
            for cmd_param, cmd_value in cmd_params.items():  # type: ignore
                if cmd_param in schema.properties:
                    arg_list.append(
                        schema.properties[cmd_param].astra_sim_name
                        + "="
                        + str(cmd_value)
                    )
        if arg_list is not None and len(arg_list) > 0:
            self.command.extend(arg_list)
        module_logger.info("Done processing command arguments")

    def _process_topology(self, configuration: astra_sim.Config):
        module_logger.info("Processing topology")
        if configuration.network_backend.choice == "ns3":
            if configuration.network_backend.ns3.get("topology") is None:
                raise ConfigurationError(
                    "topology configuration not found", grpc.StatusCode.NOT_FOUND, 404
                )
            else:
                if (
                    configuration.network_backend.ns3.topology.choice
                    == configuration.network_backend.ns3.topology.INFRAGRAPH
                ):
                    module_logger.info("Translating infragraph to ns3 nc tppology")
                    NS3Topology.generate_topology(configuration)
                if (
                    configuration.network_backend.ns3.topology.choice
                    == configuration.network_backend.ns3.topology.NC_TOPOLOGY
                ):
                    module_logger.info("NC topology set")
                    self.topology = (
                        configuration.network_backend.ns3.topology.NC_TOPOLOGY
                    )
                else:
                    raise ConfigurationError(
                        "topology configuration not found",
                        grpc.StatusCode.NOT_FOUND,
                        404,
                    )
            module_logger.info("Done processing topology")
        elif configuration.network_backend.choice == "analytical_congestion_aware":
            if (
                configuration.network_backend.analytical_congestion_aware.get(
                    "topology"
                )
                is None
            ):
                raise ConfigurationError(
                    "topology configuration not found", grpc.StatusCode.NOT_FOUND, 404
                )
            else:
                if (
                    configuration.network_backend.analytical_congestion_aware.topology.choice
                    == configuration.network_backend.analytical_congestion_aware.topology.INFRAGRAPH
                ):
                    module_logger.info(
                        "Translating infragraph to analytical network topology"
                    )
                    AnalyticalTopology.generate_topology(configuration)

                if (
                    configuration.network_backend.analytical_congestion_aware.topology.choice
                    == configuration.network_backend.analytical_congestion_aware.topology.NETWORK
                ):
                    module_logger.info("Network topology set")
                    self.topology = (
                        configuration.network_backend.analytical_congestion_aware.topology.NETWORK
                    )
                else:
                    raise ConfigurationError(
                        "topology configuration not found",
                        grpc.StatusCode.NOT_FOUND,
                        404,
                    )
            module_logger.info("Done processing topology")
        elif configuration.network_backend.choice == "analytical_congestion_unaware":
            if (
                configuration.network_backend.analytical_congestion_unaware.get(
                    "topology"
                )
                is None
            ):
                raise ConfigurationError(
                    "topology configuration not found", grpc.StatusCode.NOT_FOUND, 404
                )
            else:
                if (
                    configuration.network_backend.analytical_congestion_unaware.topology.choice
                    == configuration.network_backend.analytical_congestion_unaware.topology.INFRAGRAPH
                ):
                    module_logger.info(
                        "Translating Infragraph to analytical network topology"
                    )
                    AnalyticalTopology.generate_topology(configuration)

                if (
                    configuration.network_backend.analytical_congestion_unaware.topology.choice
                    == configuration.network_backend.analytical_congestion_unaware.topology.NETWORK
                ):
                    module_logger.info("Network topology set")
                    self.topology = (
                        configuration.network_backend.analytical_congestion_unaware.topology.NETWORK
                    )
                else:
                    raise ConfigurationError(
                        "topology configuration not found",
                        grpc.StatusCode.NOT_FOUND,
                        404,
                    )
            module_logger.info("Done processing topology")
        elif configuration.network_backend.choice == "htsim":
            if configuration.network_backend.htsim.get("topology") is None:
                raise ConfigurationError(
                    "topology configuration not found", grpc.StatusCode.NOT_FOUND, 404
                )
            else:
                if (
                    configuration.network_backend.htsim.topology.choice
                    == configuration.network_backend.htsim.topology.INFRAGRAPH
                ):
                    module_logger.info(
                        "Translating Infragraph to HTsim Network topology"
                    )
                    HTSimTopology.generate_topology(configuration)
                if (
                    configuration.network_backend.htsim.topology.choice
                    == configuration.network_backend.htsim.topology.NETWORK_TOPOLOGY_CONFIGURATION
                ):
                    module_logger.info("Network topology set")
                    self.topology = (
                        configuration.network_backend.htsim.topology.NETWORK_TOPOLOGY_CONFIGURATION
                    )
                else:
                    raise ConfigurationError(
                        "topology configuration not found",
                        grpc.StatusCode.NOT_FOUND,
                        404,
                    )
            module_logger.info("Done processing topology")
        else:
            raise ConfigurationError(
                "invalid network backend: " + configuration.network_backend.choice,
                grpc.StatusCode.INVALID_ARGUMENT,
                400,
            )

    def _process_network_backend(self, configuration: astra_sim.Config):
        module_logger.info("Processing network backend")
        if configuration.get("network_backend") is None:
            raise ConfigurationError(
                "network backend configuration not found",
                grpc.StatusCode.NOT_FOUND,
                404,
            )
        if configuration.network_backend.choice == "ns3":
            self._process_ns3_backend(configuration)
        elif "analytical" in configuration.network_backend.choice:
            self._process_analytical_backend(configuration)
        elif configuration.network_backend.choice == "htsim":
            self._process_htsim_backend(configuration)
        else:
            raise ConfigurationError(
                "invalid network backend: " + configuration.network_backend.choice,
                grpc.StatusCode.INVALID_ARGUMENT,
                400,
            )
        module_logger.info("Done processing network backend")

    def _process_ns3_backend(self, configuration: astra_sim.Config):
        module_logger.info("Processing ns3 network backend")
        if configuration.network_backend.ns3.get("network") is None:
            raise ConfigurationError(
                "ns3 network backend configuration not found",
                grpc.StatusCode.NOT_FOUND,
                404,
            )
        else:
            ns3_config_file = self._generate_ns3_network_configuration(configuration)
            if Utilities.is_file_or_folder_present(ns3_config_file):
                self.command.append("--network-configuration=" + ns3_config_file)
            else:
                raise ConfigurationError(
                    "ns3 network configuration file not generated from schema",
                    grpc.StatusCode.FAILED_PRECONDITION,
                    412,
                )
            if (
                configuration.network_backend.ns3.logical_topology.get(
                    "logical_dimensions"
                )
                is not None
            ):
                ns3_logical_topo = self._generate_ns3_logical_topology(configuration)
                if Utilities.is_file_or_folder_present(ns3_logical_topo):
                    self.command.append(
                        "--logical-topology-configuration=" + ns3_logical_topo
                    )
                else:
                    raise ConfigurationError(
                        "ns3 logical topology configuration file not generated from schema",
                        grpc.StatusCode.FAILED_PRECONDITION,
                        412,
                    )
        module_logger.info("Done processing ns3 network backend")

    def _generate_ns3_nc_topology_configuration(
        self, nc_topology: astra_sim.NCTopology, filename=""
    ):
        module_logger.info("Generating ns3 nc topology configuration")
        config = (
            str(nc_topology.total_nodes)
            + " "
            + str(nc_topology.total_switches)
            + " "
            + str(nc_topology.total_links)
        )
        config = config + "\n" + " ".join(str(num) for num in nc_topology.switch_ids)
        for connection in nc_topology.connections:
            config = (
                config
                + "\n"
                + str(connection.source_index)
                + " "
                + str(connection.destination_index)
                + " "
                + connection.bandwidth
                + " "
                + connection.latency
                + " "
                + str(connection.error_rate)
            )
        with open(filename, "w", encoding="utf-8") as file:
            file.write(config)
        module_logger.info("Done generating ns3 nc topology configuration")

    def _generate_ns3_network_configuration(
        self, configuration: astra_sim.Config, filename=""
    ):
        # this will be a json file - we can dump it by mapping with system
        module_logger.info("Processing ns3 network configuration")

        def generate_string(config):
            config_str = ""
            for c, v in config.items():
                if isinstance(v, list):
                    # Convert all items to str first, then join with spaces
                    space_separated = " ".join(map(str, v))
                    config_str = config_str + c + " " + space_separated + "\n"
                else:
                    config_str = config_str + c + " " + str(v) + "\n"
            return config_str

        # check for nc-topology
        nc_topology_filename = Constants.NS3_PHYSICAL_TOPOLOGY
        if configuration.network_backend.ns3.topology.get("nc_topology") is not None:
            # generate nc topology file
            self._generate_ns3_nc_topology_configuration(
                configuration.network_backend.ns3.topology.nc_topology,
                nc_topology_filename,
            )
        else:
            raise ConfigurationError(
                "Topology is set to native and ns3 nc-topology has empty values",
                grpc.StatusCode.INVALID_ARGUMENT,
                400,
            )

        # check for trace
        trace_present = False
        trace_filename = Constants.NS3_TRACE_FILE
        if configuration.network_backend.ns3.get("trace") is not None:
            trace_present = True
            if configuration.network_backend.ns3.trace.get("trace_ids") is not None:
                traces = str(len(configuration.network_backend.ns3.trace.trace_ids))
                traces = (
                    traces
                    + "\n"
                    + " ".join(
                        str(t)
                        for t in configuration.network_backend.ns3.trace.trace_ids
                    )
                )
                with open(Constants.NS3_TRACE_FILE, "w", encoding="utf-8") as f:
                    f.write(traces)
            else:
                raise ConfigurationError(
                    "ns3 trace configuration present does not have trace ids",
                    grpc.StatusCode.INVALID_ARGUMENT,
                    400,
                )
        else:
            self.warn_messages.append("ns3 backend trace is not set")

        # NS3 network configuration
        network = {}
        network_config = configuration.network_backend.ns3.serialize(encoding="dict")
        schema = self.schema_map["NS3.Network"]
        for net_prop in network_config["network"]:  # type: ignore
            if net_prop in schema.properties:
                # schema is present
                # get the astra_sim_name
                if "file" in net_prop:
                    if "topology_file" == net_prop:
                        network[
                            schema.properties[net_prop].astra_sim_name
                        ] = os.path.join(
                            Constants.CONFIGURATION_DIR, nc_topology_filename
                        )
                    elif "trace_file" == net_prop:
                        network[
                            schema.properties[net_prop].astra_sim_name
                        ] = trace_filename
                        if not trace_present:
                            Utilities.create_file(trace_filename)
                    else:
                        network[
                            schema.properties[net_prop].astra_sim_name
                        ] = os.path.join(
                            Constants.RESULTS_DIR, network_config["network"][net_prop]  # type: ignore
                        )
                else:
                    network[schema.properties[net_prop].astra_sim_name] = network_config["network"][net_prop]  # type: ignore
        # dump as file
        if filename is None or filename == "":
            filename = Constants.NS3_NETWORK_TXT
        with open(filename, "w", encoding="utf-8") as f:
            f.write(generate_string(network))
        # create other files
        Utilities.create_file(Constants.NS3_FLOW_FILE)
        Utilities.create_file(Constants.NS3_TRACE_OUTPUT_FILE)
        Utilities.create_file(Constants.NS3_FCT_OUTPUT_FILE)
        Utilities.create_file(Constants.NS3_PFC_OUTPUT_FILE)
        Utilities.create_file(Constants.NS3_QLEN_MON_FILE)
        module_logger.info("Done processing ns3 network configuration")
        return filename

    def _generate_ns3_logical_topology(
        self, configuration: astra_sim.Config, filename=""
    ):
        # this will be a json file - we can dump it by mapping with system
        module_logger.info("Processing ns3 logical topology")
        logical_json = {}

        if configuration.network_backend.ns3.get("logical_topology") is not None:
            if (
                configuration.network_backend.ns3.logical_topology.get(
                    "logical_dimensions"
                )
                is not None
            ):
                result = list(
                    map(
                        str,
                        configuration.network_backend.ns3.logical_topology.logical_dimensions,
                    )
                )
                logical_json["logical-dims"] = result
                if filename is None or filename == "":
                    filename = Constants.NS3_LOGICAL_TOPOLOGY
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(logical_json, f, indent=4, ensure_ascii=False)
            else:
                raise ConfigurationError(
                    "ns3 logical topology configuration present does not have logical dimensions",
                    grpc.StatusCode.INVALID_ARGUMENT,
                    400,
                )
        else:
            raise ConfigurationError(
                "ns3 logical topology configuration not found in schema",
                grpc.StatusCode.INVALID_ARGUMENT,
                400,
            )

        module_logger.info("Done processing ns3 logical topology")
        return filename

    def _process_analytical_backend(self, configuration: astra_sim.Config):
        module_logger.info("Processing analytical network backend")
        if "analytical" in configuration.network_backend.choice:
            network_backend = None
            if (
                configuration.network_backend.get("analytical_congestion_aware")
                is not None
            ):
                network_backend = (
                    configuration.network_backend.analytical_congestion_aware
                )
            elif (
                configuration.network_backend.get("analytical_congestion_unaware")
                is not None
            ):
                network_backend = (
                    configuration.network_backend.analytical_congestion_unaware
                )
            if network_backend is None:
                raise ConfigurationError(
                    "analytical network backend not found in schema",
                    grpc.StatusCode.NOT_FOUND,
                    404,
                )
            else:
                if network_backend.topology.get("network") is None:
                    raise ConfigurationError(
                        "analytical network backend configuration not found",
                        grpc.StatusCode.NOT_FOUND,
                        404,
                    )
                else:
                    analytical_network = (
                        self._generate_analytical_network_configuration(configuration)
                    )
                    if Utilities.is_file_or_folder_present(analytical_network):
                        self.command.append(
                            "--network-configuration=" + analytical_network
                        )
                    else:
                        raise ConfigurationError(
                            "analytical network configuration file not generated from schema",
                            grpc.StatusCode.FAILED_PRECONDITION,
                            412,
                        )
        module_logger.info("Done processing analytical network configuration")

    def _generate_analytical_network_configuration(
        self, configuration: astra_sim.Config, filename=""
    ):
        # this will be a json file - we can dump it by mapping with system
        module_logger.info("Generating analytical network configuration")
        analytical_json = {
            "topology": [],
            "npus_count": [],
            "bandwidth": [],
            "latency": [],
        }
        topology_map = {
            "fullyconnected": "FullyConnected",
            "ring": "Ring",
            "switch": "Switch",
        }
        analytical_config = None
        if configuration.network_backend.get("analytical_congestion_aware") is not None:
            analytical_config = (
                configuration.network_backend.analytical_congestion_aware.topology.network
            )
        elif (
            configuration.network_backend.get("analytical_congestion_unaware")
            is not None
        ):
            analytical_config = (
                configuration.network_backend.analytical_congestion_unaware.topology.network
            )
        elif configuration.network_backend.get("htsim") is not None:
            analytical_config = (
                configuration.network_backend.htsim.topology.network_topology_configuration.network
            )
        if analytical_config is None or len(analytical_config) == 0:
            raise ConfigurationError(
                "analytical configuration not found", grpc.StatusCode.NOT_FOUND, 404
            )
        # Force type hint: serialize("dict") returns list[Dict[str, Any]]
        serialized_analytical_config = cast(
            list[Dict[str, Any]], analytical_config.serialize("dict")
        )
        for config in serialized_analytical_config:
            analytical_json["topology"].append(topology_map[config["topology"]])
            analytical_json["npus_count"].append(config["npus_count"])
            analytical_json["bandwidth"].append(config["bandwidth"])
            analytical_json["latency"].append(config["latency"])

        if filename is None or filename == "":
            filename = Constants.ANALYTICAL_NETWORK_TOPOLOGY
        with open(filename, "w", encoding="utf-8") as yaml_file:
            for key, value in analytical_json.items():
                data = key + ": [ "
                for index, val in enumerate(value):
                    if index + 1 == len(value):
                        data = data + str(val) + " "
                    else:
                        data = data + str(val) + ", "
                data = data + "]"
                if key == "bandwidth":
                    data = data + " # GB/s"
                elif key == "latency":
                    data = data + " # ns"
                data = data + "\n"
                yaml_file.write(data)
        module_logger.info("Done generating analytical network configuration")
        return filename

    def _process_htsim_backend(self, configuration: astra_sim.Config):
        module_logger.info("Processing htsim backend")
        if (
            configuration.network_backend.htsim.topology.get(
                "network_topology_configuration"
            )
            is None
        ):
            raise ConfigurationError("htsim network configuration is not set")
        else:
            htsim_config_file = self._generate_analytical_network_configuration(
                configuration
            )
            if Utilities.is_file_or_folder_present(htsim_config_file):
                self.command.append("--network-configuration=" + htsim_config_file)
            else:
                raise ConfigurationError(
                    "analytical network configuration file not generated from schema",
                    grpc.StatusCode.FAILED_PRECONDITION,
                    412,
                )
            # check logical topology
            arg_list = self._process_htsim_arguments(configuration, self.topology)
            if arg_list is not None and len(arg_list) > 0:
                self.command.extend(arg_list)
        module_logger.info("Done processing htsim backend")

    def _generate_htsim_fat_tree_topology(
        self, fat_tree: astra_sim.HTSimTopologyFatTree, filename=""
    ):
        module_logger.info("Generating htsim fat tree topology")
        if filename == "":
            filename = Constants.HTSIM_TOPOLOGY

        # TODO: add validation at all levels
        config = "Nodes " + str(fat_tree.nodes)
        config = config + "\nTiers " + str(fat_tree.tiers)
        config = config + "\nPodsize " + str(fat_tree.podsize)

        if fat_tree.get("tier_0") is not None:
            config = config + "\nTier 0"
            if fat_tree.tier_0.get("downlink_speed_gbps") is not None:
                config = (
                    config
                    + "\ndownlink_speed_gbps "
                    + str(fat_tree.tier_0.downlink_speed_gbps)
                )
            if fat_tree.tier_0.get("radix_up") is not None:
                config = config + "\nradix_up " + str(fat_tree.tier_0.radix_up)
            if fat_tree.tier_0.get("radix_down") is not None:
                config = config + "\nradix_down " + str(fat_tree.tier_0.radix_down)
            if fat_tree.tier_0.get("queue_up") is not None:
                config = config + "\nqueue_up " + str(fat_tree.tier_0.queue_up)
            if fat_tree.tier_0.get("queue_down") is not None:
                config = config + "\nqueue_down " + str(fat_tree.tier_0.queue_down)
            if fat_tree.tier_0.get("oversubscribed") is not None:
                config = (
                    config + "\noversubscribed " + str(fat_tree.tier_0.oversubscribed)
                )
            if fat_tree.tier_0.get("bundle") is not None:
                config = config + "\nbundle " + str(fat_tree.tier_0.bundle)
            if fat_tree.tier_0.get("switch_latency_ns") is not None:
                config = (
                    config
                    + "\nswitch_latency_ns "
                    + str(fat_tree.tier_0.switch_latency_ns)
                )
            if fat_tree.tier_0.get("downlink_latency_ns") is not None:
                config = (
                    config
                    + "\ndownlink_latency_ns "
                    + str(fat_tree.tier_0.downlink_latency_ns)
                )
        if fat_tree.get("tier_1") is not None:
            config = config + "\nTier 1"
            if fat_tree.tier_1.get("downlink_speed_gbps") is not None:
                config = (
                    config
                    + "\ndownlink_speed_gbps "
                    + str(fat_tree.tier_1.downlink_speed_gbps)
                )
            if fat_tree.tier_1.get("radix_up") is not None:
                config = config + "\nradix_up " + str(fat_tree.tier_1.radix_up)
            if fat_tree.tier_1.get("radix_down") is not None:
                config = config + "\nradix_down " + str(fat_tree.tier_1.radix_down)
            if fat_tree.tier_1.get("queue_up") is not None:
                config = config + "\nqueue_up " + str(fat_tree.tier_1.queue_up)
            if fat_tree.tier_1.get("queue_down") is not None:
                config = config + "\nqueue_down " + str(fat_tree.tier_1.queue_down)
            if fat_tree.tier_1.get("oversubscribed") is not None:
                config = (
                    config + "\noversubscribed " + str(fat_tree.tier_1.oversubscribed)
                )
            if fat_tree.tier_1.get("bundle") is not None:
                config = config + "\nbundle " + str(fat_tree.tier_1.bundle)
            if fat_tree.tier_1.get("switch_latency_ns") is not None:
                config = (
                    config
                    + "\nswitch_latency_ns "
                    + str(fat_tree.tier_1.switch_latency_ns)
                )
            if fat_tree.tier_1.get("downlink_latency_ns") is not None:
                config = (
                    config
                    + "\ndownlink_latency_ns "
                    + str(fat_tree.tier_1.downlink_latency_ns)
                )
        if fat_tree.get("tier_2") is not None:
            config = config + "\nTier 2"
            if fat_tree.tier_2.get("downlink_speed_gbps") is not None:
                config = (
                    config
                    + "\ndownlink_speed_gbps "
                    + str(fat_tree.tier_2.downlink_speed_gbps)
                )
            if fat_tree.tier_2.get("radix_down") is not None:
                config = config + "\nradix_down " + str(fat_tree.tier_2.radix_down)
            if fat_tree.tier_2.get("queue_down") is not None:
                config = config + "\nqueue_down " + str(fat_tree.tier_2.queue_down)
            if fat_tree.tier_2.get("oversubscribed") is not None:
                config = (
                    config + "\noversubscribed " + str(fat_tree.tier_2.oversubscribed)
                )
            if fat_tree.tier_2.get("bundle") is not None:
                config = config + "\nbundle " + str(fat_tree.tier_2.bundle)
            if fat_tree.tier_2.get("switch_latency_ns") is not None:
                config = (
                    config
                    + "\nswitch_latency_ns "
                    + str(fat_tree.tier_2.switch_latency_ns)
                )
            if fat_tree.tier_2.get("downlink_latency_ns") is not None:
                config = (
                    config
                    + "\ndownlink_latency_ns "
                    + str(fat_tree.tier_2.downlink_latency_ns)
                )

        with open(filename, "w", encoding="utf-8") as f:
            f.write(config)
        module_logger.info("Done generating htsim fat tree topology")

    def _generate_htsim_topology(
        self, htsim_topology: astra_sim.HTSimTopology, filename=""
    ):
        """
        Generates htsim topology
        """
        module_logger.info("Processing htsim topology")
        if htsim_topology.get("fat_tree") is not None:
            # generate fat tree topology here
            self._generate_htsim_fat_tree_topology(htsim_topology.fat_tree, filename)
        else:
            raise ConfigurationError(
                "invalid htsim topology selected",
                grpc.StatusCode.INVALID_ARGUMENT,
                400,
            )
        module_logger.info("Done processing htsim topology")

    def _process_htsim_arguments(self, configuration: astra_sim.Config, topology):
        """
        Process htsim artguments, topology and protocol arguments
        """
        module_logger.info("Processing htsim command arguments")
        htsim_command = []
        topology_filename = Constants.HTSIM_TOPOLOGY
        if (
            topology
            == configuration.network_backend.htsim.topology.NETWORK_TOPOLOGY_CONFIGURATION
        ):
            if (
                configuration.network_backend.htsim.topology.network_topology_configuration.get(
                    "htsim_topology"
                )
                is not None
            ):
                self._generate_htsim_topology(
                    configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology,
                    topology_filename,
                )

        if configuration.network_backend.htsim.htsim_protocol.get("tcp") is not None:
            module_logger.info("Processing htsim tcp protocol command arguments")
            schema = self.schema_map["HTSim.Protocol.Tcp"]
            tcp_protocol_dict = (
                configuration.network_backend.htsim.htsim_protocol.tcp.serialize("dict")
            )

            for tcp_param, tcp_value in tcp_protocol_dict.items():  # type: ignore
                if tcp_param in schema.properties:
                    # check for topology
                    if schema.properties[tcp_param].astra_sim_name != "n/a":
                        htsim_command.append(
                            schema.properties[tcp_param].astra_sim_name
                        )
                    htsim_command.append(str(tcp_value))
            htsim_command.append("-topo")
            htsim_command.append(topology_filename)
            module_logger.info("Done processing htsim tcp protocol command arguments")
        else:
            raise ConfigurationError(
                "invalid htsim protocol",
                grpc.StatusCode.INVALID_ARGUMENT,
                400,
            )
        if len(htsim_command) > 0:
            htsim_command.insert(0, "--htsim_opts")
        module_logger.info("Done processing htsim command arguments")
        return htsim_command

    def validate_and_process_config(self, configuration: astra_sim.Config):
        """
        This processes the configuration received in set config call. This calls multiple private handlers that handles various sections of configuraion
        """
        module_logger.info("Validating and processing configuration")
        if configuration.get("common_config") is None:
            raise ConfigurationError(
                "Common configuration is absent in the provided configuration"
            )
        self.command = []
        self.warn_messages = []
        self.topology = ""
        self._process_workload_configuration(configuration)
        self._process_system_configuration(configuration)
        self._process_remote_memory_configuration(configuration)
        self._process_logging_configuration(configuration)
        self._process_communicator_group_configuration(configuration)
        self._process_command_arguments(configuration)
        self._process_topology(configuration)
        self._process_network_backend(configuration)
        module_logger.info("Done validating and processing configuration")
