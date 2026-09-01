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

import json
import yaml
import toml
import traceback
import astra_sim_sdk.astra_sim_sdk as astra_sim

try:
    from common import Utilities
except:
    from .common import Utilities


class TranslateConfig:
    """
    Class that holds translators that convert a file configuration to an astra-sim object config
    """

    @staticmethod
    def translate_remote_memory(remote_memory_file_path: str, configuration: astra_sim.Config):
        """
        This translates the remote memory file to astra-sim config
        The main inputs are the:
            - remote_memory_file_path - full file path of the remote memory configuration
            - configuration - which is astra-sim config
        The file values are set in the configuration object at: configuration.common_config.remote_memory
        """
        try:
            with open(remote_memory_file_path, "r", encoding="utf-8") as rm_file:
                rm = json.load(rm_file)
            new_conf = {}
            for key in rm:
                new_conf[key.replace("-", "_")] = rm[key]
            configuration.common_config.remote_memory.deserialize(new_conf)
        except Exception as e:
            print(f"Error translating remote memory configuration from file '{remote_memory_file_path}': {e}")
            traceback.print_exc()
            raise RuntimeError("Failed to translate remote memory file configuration.") from e

    @staticmethod
    def translate_system_configuration(system_config_file_path: str, configuration: astra_sim.Config):
        """
        This translates the system file to astra-sim config
        The main inputs are the:
            - system_config_file_path - full file location of system configuration
            - configuration - which is astra-sim config
        The file values are set in the configuration object at: configuration.common_config.system
        """
        try:
            with open(system_config_file_path, "r", encoding="utf-8") as sc_file:
                sc = json.load(sc_file)
            new_conf = {}
            for key in sc:
                new_conf[key.replace("-", "_")] = sc[key]
            if "L" in new_conf:
                new_conf["latency"] = new_conf["L"]
                del new_conf["L"]
            if "o" in new_conf:
                new_conf["overhead"] = new_conf["o"]
                del new_conf["o"]

            if "g" in new_conf:
                new_conf["gap"] = new_conf["g"]
                del new_conf["g"]

            if "G" in new_conf:
                new_conf["global_memory"] = new_conf["G"]
                del new_conf["G"]

            configuration.common_config.system.deserialize(new_conf)
        except Exception as e:
            print(f"Error translating system config configuration from file '{system_config_file_path}': {e}")
            traceback.print_exc()
            raise RuntimeError("Failed to translate system config file configuration.") from e

    @staticmethod
    def translate_communicator_configuration(
        communicator_config_file_path: str, configuration: astra_sim.Config
    ):
        """
        This translates the communicator group file to astra-sim config
        The main inputs are the:
            - communicator_config_file_path - full file path of communicator group configuration
            - configuration - which is astra-sim config
        The file values are set in the configuration object at: configuration.common_config.communicator_group
        """
        try:
            with open(communicator_config_file_path, "r", encoding="utf-8") as cg_file:
                cg = json.load(cg_file)
            for key, value in cg.items():
                configuration.common_config.communicator_group.add(key, value)
        except Exception as e:
            print(
                f"Error translating communicator configuration from file '{communicator_config_file_path}': {e}"
            )
            traceback.print_exc()
            raise RuntimeError("Failed to translate communicator file configuration.") from e

    @staticmethod
    def translate_ns3_nc_topology_configuration(
        nc_topology_config_file_path: str, configuration: astra_sim.Config
    ):
        """
        This translates the ns3 nc topology file to astra-sim config
        The main inputs are the:
            - nc_topology_config_file_path - full file path of ns3 nc topoology txt
            - configuration - which is astra-sim config
        The file values are set in the configuration object at: configuration.network_backend.ns3.topology.nc_topology
        """
        try:
            with open(nc_topology_config_file_path, "r", encoding="utf-8") as nc_topo_file:
                config_topo = configuration.network_backend.ns3.topology.nc_topology
                for line_number, line in enumerate(nc_topo_file):
                    line_list = line.strip().split()
                    if not line_list:
                        continue  # incase if there are no switches
                    if line_number == 0:
                        total_nodes, total_switches, total_links = line_list[0], line_list[1], line_list[2]
                        config_topo.total_nodes = int(total_nodes)
                        config_topo.total_switches = int(total_switches)
                        config_topo.total_links = int(total_links)
                    elif line_number == 1:
                        switch_list = [int(x) for x in line_list]
                        config_topo.switch_ids = switch_list

                    else:
                        src_index, dest_index, bandwidth, latency, error_rate = (
                            line_list[0],
                            line_list[1],
                            line_list[2],
                            line_list[3],
                            line_list[4],
                        )
                        config_topo.connections.add(
                            int(src_index), int(dest_index), bandwidth, latency, error_rate
                        )
        except Exception as e:
            print(
                f"Error translating nc topology configuration from file '{nc_topology_config_file_path}': {e}"
            )
            traceback.print_exc()
            raise RuntimeError("Failed to translate nc topology file configuration.") from e

    @staticmethod
    def translate_ns3_network_configuration(network_config_file_path: str, configuration: astra_sim.Config):
        """
        This translates the ns3 network file to astra-sim config
        The main inputs are the:
            - nc_topology_config_file_path - full file path of ns3 network configuration
            - configuration - which is astra-sim config
        The file values are set in the configuration object at: onfiguration.network_backend.ns3.network
        """
        try:
            network_dict = Utilities.serialize_ns3_configuration_to_dict(network_config_file_path)
            config_network = configuration.network_backend.ns3.network
            config_network.enable_qcn = int(network_dict["ENABLE_QCN"])
            config_network.use_dynamic_pfc_threshold = int(network_dict["USE_DYNAMIC_PFC_THRESHOLD"])
            config_network.packet_payload_size = int(network_dict["PACKET_PAYLOAD_SIZE"])
            config_network.topology_file = network_dict["TOPOLOGY_FILE"]
            config_network.flow_file = network_dict["FLOW_FILE"]
            config_network.trace_file = network_dict["TRACE_FILE"]
            config_network.trace_output_file = network_dict["TRACE_OUTPUT_FILE"]
            config_network.fct_output_file = network_dict["FCT_OUTPUT_FILE"]
            config_network.pfc_output_file = network_dict["PFC_OUTPUT_FILE"]
            config_network.qlen_mon_file = network_dict["QLEN_MON_FILE"]
            config_network.qlen_mon_start = int(network_dict["QLEN_MON_START"])
            config_network.qlen_mon_end = int(network_dict["QLEN_MON_END"])
            config_network.simulator_stop_time = float(network_dict["SIMULATOR_STOP_TIME"])
            config_network.cc_mode = int(network_dict["CC_MODE"])
            config_network.alpha_resume_interval = int(network_dict["ALPHA_RESUME_INTERVAL"])
            config_network.rate_decrease_interval = int(network_dict["RATE_DECREASE_INTERVAL"])
            config_network.clamp_target_rate = int(network_dict["CLAMP_TARGET_RATE"])
            config_network.rp_timer = int(network_dict["RP_TIMER"])
            config_network.ewma_gain = float(network_dict["EWMA_GAIN"])
            config_network.fast_recovery_times = int(network_dict["FAST_RECOVERY_TIMES"])
            config_network.rate_ai = network_dict["RATE_AI"]
            config_network.rate_hai = network_dict["RATE_HAI"]
            config_network.min_rate = network_dict["MIN_RATE"]
            config_network.dctcp_rate_ai = network_dict["DCTCP_RATE_AI"]
            config_network.error_rate_per_link = float(network_dict["ERROR_RATE_PER_LINK"])
            config_network.l2_chunk_size = int(network_dict["L2_CHUNK_SIZE"])
            config_network.l2_ack_interval = int(network_dict["L2_ACK_INTERVAL"])
            config_network.l2_back_to_zero = int(network_dict["L2_BACK_TO_ZERO"])
            config_network.has_win = int(network_dict["HAS_WIN"])
            config_network.global_t = int(network_dict["GLOBAL_T"])
            config_network.var_win = int(network_dict["VAR_WIN"])
            config_network.fast_react = int(network_dict["FAST_REACT"])
            config_network.u_target = float(network_dict["U_TARGET"])
            config_network.mi_thresh = int(network_dict["MI_THRESH"])
            config_network.int_multi = int(network_dict["INT_MULTI"])
            config_network.multi_rate = int(network_dict["MULTI_RATE"])
            config_network.sample_feedback = int(network_dict["SAMPLE_FEEDBACK"])
            config_network.pint_log_base = float(network_dict["PINT_LOG_BASE"])
            config_network.pint_prob = float(network_dict["PINT_PROB"])
            config_network.rate_bound = int(network_dict["RATE_BOUND"])
            config_network.ack_high_prio = int(network_dict["ACK_HIGH_PRIO"])
            config_network.link_down = [int(x) for x in network_dict["LINK_DOWN"]]
            config_network.enable_trace = int(network_dict["ENABLE_TRACE"])
            config_network.kmax_map = network_dict["KMAX_MAP"]
            config_network.kmin_map = network_dict["KMIN_MAP"]
            config_network.pmax_map = network_dict["PMAX_MAP"]
            config_network.buffer_size = int(network_dict["BUFFER_SIZE"])
            config_network.nic_total_pause_time = int(network_dict["NIC_TOTAL_PAUSE_TIME"])
        except Exception as e:
            print(
                f"Error translating ns3 network file configuration from file '{network_config_file_path}': {e}"
            )
            traceback.print_exc()
            raise RuntimeError("Failed to translate ns3 network file configuration.") from e

    @staticmethod
    def translate_ns3_logical_configuration(logical_config_file_path: str, configuration: astra_sim.Config):
        """
        This translates the ns3 logical configuration file to astra-sim config
        The main inputs are the:
            - nc_topology_config_file_path - full file path of ns3 network configuration
            - configuration - which is astra-sim config
        The file values are set in the configuration object at: configuration.network_backend.ns3.logical_topology.logical_dimensions
        """
        try:
            with open(logical_config_file_path, "r", encoding="utf-8") as lc_file:
                lc = json.load(lc_file)
            new_conf = {}
            logical_dims_value = lc.get("logical-dims")
            if not logical_dims_value:
                raise ValueError("no value for logical_dims")
            else:
                new_conf["logical_dims"] = logical_dims_value

            configuration.network_backend.ns3.logical_topology.deserialize(new_conf)

            configuration.network_backend.ns3.logical_topology.logical_dimensions = new_conf["logical_dims"]
        except Exception as e:
            print(f"Error translating ns3 logical configuration from file '{logical_config_file_path}': {e}")
            traceback.print_exc()
            raise RuntimeError("Failed to translate ns3 logical configuration.") from e

    @staticmethod
    def translate_analytical_network(
        network_config_file_path: str, configuration: astra_sim.Config, backend_name: str
    ):
        """
        This translates the analytical network configuration file to astra-sim config
        The main inputs are the:
            - network_config_file_path - full file path of analytical network configuration
            - configuration - which is astra-sim config
        The file values are set in the configuration object
        """
        try:
            backend_list = ["analytical_congestion_aware", "analytical_congestion_unaware", "htsim"]
            if backend_name in backend_list:
                config_network = getattr(configuration.network_backend, backend_name)
                config_topo = config_network.topology.network
                with open(network_config_file_path, "r", encoding="utf-8") as network_file:
                    network_yaml = yaml.safe_load(network_file)
                number_of_dim = len(network_yaml["topology"])
                for i in range(number_of_dim):
                    topo_value = network_yaml["topology"][i].lower()
                    npu_count = network_yaml["npus_count"][i]
                    bandwidth = network_yaml["bandwidth"][i]
                    latency = network_yaml["latency"][i]
                    config_topo.add(topo_value, npu_count, bandwidth, latency)
            else:
                return f"please select backend_name from {backend_list}"
        except Exception as e:
            print(
                f"Error translating analytical network configuration from file '{network_config_file_path}': {e}"
            )
            traceback.print_exc()
            raise RuntimeError("Failed to translate analytical network configuration.") from e

    @staticmethod
    def translate_htsim_fat_tree_topology(htsim_fat_tree_path: str, configuration: astra_sim.Config):
        """
        This translates the htsim network fat tree topology configuration file to astra-sim config
        The main inputs are the:
            - htsim_fat_tree_path - full file path of htsim fat tree
            - configuration - which is astra-sim config
        The file values are set in the configuration object: configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree
        """
        try:
            topo_dict = TranslateConfig._parse_htsim_topo(htsim_fat_tree_path)
            config_network_topo = (
                configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree
            )
            config_network_topo.nodes = topo_dict["Nodes"]
            config_network_topo.tiers = topo_dict["Tiers"]
            config_network_topo.podsize = topo_dict["Podsize"]

            for key, value in topo_dict.items():
                if not key.startswith("tier_"):
                    continue  # skip non-tier keys

                tier_obj = getattr(config_network_topo, key)
                mapping = {
                    "Downlink_speed_Gbps": "downlink_speed_gbps",
                    "Downlink_Latency_ns": "downlink_latency_ns",
                    "Radix_Down": "radix_down",
                    "Radix_Up": "radix_up",
                    "Bundle": "bundle",
                }

                for k, attr in mapping.items():
                    if k in value:
                        setattr(tier_obj, attr, value[k])
        except Exception as e:
            print(f"Error translating htsim fat tree configuration from file '{htsim_fat_tree_path}': {e}")
            traceback.print_exc()
            raise RuntimeError("Failed to translate htsim fat tree network configuration.") from e

    @staticmethod
    def translate_ns3_trace_file_to_schema(ns3_trace_file_path: str, configuration: astra_sim.Config):
        """
        This translates the ns3 trace file to astra-sim config
        The main inputs are the:
            - ns3_trace_file_path - full file path of ns3 trace txt
            - configuration - which is astra-sim config
        The file values are set in the configuration object at: configuration.network_backend.ns3.trace.trace_ids
        """
        try:
            trace_list = []
            with open(ns3_trace_file_path, "r", encoding="utf-8") as trace_file:
                next(trace_file)  # skip the first line, that is the number of npus
                trace_list = list(map(int, trace_file.readline().split()))
            configuration.network_backend.ns3.trace.trace_ids = trace_list
        except Exception as e:
            print(f"Error translating ns3 trace file configuration from file '{ns3_trace_file_path}': {e}")
            traceback.print_exc()
            raise RuntimeError("Failed to translate ns3 trace file configuration.") from e

    @staticmethod
    def translate_logging_file_to_schema(logging_file_path: str, configruation: astra_sim.Config):
        """
        This translates the logging configuration to astra-sim config
        The main inputs are the:
            - logging_file_path - full file path of logging toml file
            - configuration - which is astra-sim config
        The file values are set in the configuration object at: configruation.common_config.logging
        """
        try:
            with open(logging_file_path, "r", encoding="utf-8") as toml_file:
                toml_data = toml.load(toml_file)  # parses the TOML file into a Python dict

            for sink in toml_data.get("sink", []):
                configruation.common_config.logging.sink.add(**sink)
            for logger in toml_data.get("logger", []):
                configruation.common_config.logging.logger.add(**logger)
        except Exception as e:
            print(f"Error translating logging configuration from file '{logging_file_path}': {e}")
            traceback.print_exc()
            raise RuntimeError("Failed to translate logging configuration.") from e

    @staticmethod
    def _parse_htsim_topo(file_path: str) -> dict:
        """
        static private function used to parse htsim topology
        """
        result = {}
        current_tier = None
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                key = parts[0]

                # check for Tier Section
                if key == "Tier":
                    tier_num = parts[1]
                    current_tier = f"tier_{tier_num}"
                    result[current_tier] = {}
                    continue

                value = parts[1] if len(parts) > 1 else None
                if value is not None:
                    try:
                        value = int(value)
                    except ValueError:
                        try:
                            value = float(value)
                        except ValueError:
                            pass
                if current_tier:
                    result[current_tier][key] = value
                else:
                    result[key] = value
        return result
