def test_load_existing_et_example(port_number):

    try:

        # ##### Imports the necessary modules and sets the system path to locate them.

        import sys
        import os
        import pandas as pd
        sys.path.append("../client-scripts/utils")
        sys.path.append("../../client-scripts/utils")
        sys.path.append("./client-scripts/utils")
        from common import FileFolderUtils
        from astra_sim import AstraSim, Collective, NetworkBackend

        # ##### Connects the client to the AstraSim gRPC server, initializes the AstraSim SDK, and creates a folder (tagged as specified) containing all configuration details, generated results, and logs.

        astra = AstraSim(f"0.0.0.0:{port_number}", tag="ns3_trial_existing_ets")

        # ##### Add existing workload execution traces by giving the path to the workload with basename included, mandatory for AstraSim workload configuration.

        cwd = os.path.dirname(os.path.abspath(__file__))
        astra.configuration.common_config.workload = os.path.join(cwd, "../resources/example_workload/workload/all_reduce")
        print(astra.configuration.common_config.workload)

        # ##### Configure the system configurations

        astra.configuration.common_config.system.scheduling_policy = astra.configuration.common_config.system.LIFO
        astra.configuration.common_config.system.endpoint_delay = 10
        astra.configuration.common_config.system.active_chunks_per_dimension = 1
        astra.configuration.common_config.system.all_gather_implementation = [astra.configuration.common_config.system.RING]
        astra.configuration.common_config.system.all_to_all_implementation = [astra.configuration.common_config.system.DIRECT]
        astra.configuration.common_config.system.all_reduce_implementation = [astra.configuration.common_config.system.ONERING]
        astra.configuration.common_config.system.collective_optimization = astra.configuration.common_config.system.LOCALBWAWARE
        astra.configuration.common_config.system.local_mem_bw = 1600
        print(astra.configuration.common_config.system)

        # ##### Configure the remote memory configuration

        astra.configuration.common_config.remote_memory.memory_type = astra.configuration.common_config.remote_memory.NO_MEMORY_EXPANSION
        print(astra.configuration.common_config.remote_memory)

        # ##### Configure the Network_backend

        # astra.configuration.network_backend.choice = astra.configuration.network_backend.NS3
        astra.configuration.network_backend.ns3.network.packet_payload_size = int(8192)
        astra.configuration.network_backend.ns3.logical_topology.logical_dimensions = [8]
        astra.configuration.network_backend.ns3.trace.trace_ids = [0, 1, 2, 3,4 ,5 ,6, 7]
        print("network backend choice set to:",astra.configuration.network_backend.ns3.topology.choice)
        print(astra.configuration.network_backend.ns3.network.packet_payload_size)
        print(astra.configuration.network_backend.ns3.logical_topology)
        print(astra.configuration.network_backend.ns3.trace)

        # ##### Set up the network topology

        # astra.configuration.network_backend.ns3.topology.choice = astra.configuration.network_backend.ns3.topology.NC_TOPOLOGY
        # the topology configuration will be set automatically if we configure the nc_topology
        astra.configuration.network_backend.ns3.topology.nc_topology.total_nodes = 9
        astra.configuration.network_backend.ns3.topology.nc_topology.total_switches = 1
        astra.configuration.network_backend.ns3.topology.nc_topology.total_links = 8
        astra.configuration.network_backend.ns3.topology.nc_topology.switch_ids = [8]
        astra.configuration.network_backend.ns3.topology.nc_topology.connections.clear()
        astra.configuration.network_backend.ns3.topology.nc_topology.connections.add(0, 8, "100Gbps", "0.005ms", "0")
        astra.configuration.network_backend.ns3.topology.nc_topology.connections.add(1, 8, "100Gbps", "0.005ms", "0")
        astra.configuration.network_backend.ns3.topology.nc_topology.connections.add(2, 8, "100Gbps", "0.005ms", "0")
        astra.configuration.network_backend.ns3.topology.nc_topology.connections.add(3, 8, "100Gbps", "0.005ms", "0")
        astra.configuration.network_backend.ns3.topology.nc_topology.connections.add(4, 8, "100Gbps", "0.005ms", "0")
        astra.configuration.network_backend.ns3.topology.nc_topology.connections.add(5, 8, "100Gbps", "0.005ms", "0")
        astra.configuration.network_backend.ns3.topology.nc_topology.connections.add(6, 8, "100Gbps", "0.005ms", "0")
        astra.configuration.network_backend.ns3.topology.nc_topology.connections.add(7, 8, "100Gbps", "0.005ms", "0")
        print(astra.configuration.network_backend.ns3.topology.choice)
        print(astra.configuration.network_backend.ns3.topology.nc_topology)

        # ##### Configure the cmd parameters, non-mandatory parameters

        astra.configuration.common_config.cmd_parameters.comm_scale = 1
        astra.configuration.common_config.cmd_parameters.injection_scale = 1
        astra.configuration.common_config.cmd_parameters.rendezvous_protocol = False

        print(astra.configuration.common_config.cmd_parameters)

        # #### Start the simulation by providing the network backend name in uppercase letters.

        astra.run_simulation(NetworkBackend.NS3)

        # ##### Download all the configurations as a zip

        astra.download_configuration()

        # ##### Read output files

        df = pd.read_csv(os.path.join(FileFolderUtils.get_instance().OUTPUT_DIR, "fct.csv"))
        df.head()

        df = pd.read_csv(os.path.join(FileFolderUtils.get_instance().OUTPUT_DIR, "flow_stats.csv"))
        df.head()

        assert True
    except Exception as e:
        assert False, f'Unexpected exception: {e}'
