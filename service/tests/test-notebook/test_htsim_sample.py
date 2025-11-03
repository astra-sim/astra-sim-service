def test_htsim_sample(port_number):

    try:

        # ##### Imports the necessary modules and sets the system path to locate them.

        import sys
        sys.path.append("../client-scripts/utils")
        sys.path.append("../../client-scripts/utils")
        sys.path.append("./client-scripts/utils")
        from astra_sim import AstraSim, Collective, NetworkBackend

        # ##### Connects the client to the AstraSim gRPC server, initializes the AstraSim SDK, and creates a folder (tagged as specified) containing all configuration details, generated results, and logs.

        astra = AstraSim(f"0.0.0.0:{port_number}",tag = "htsim_trial")

        # ##### Generates workload execution traces for each rank and configures the data size, which is mandatory for AstraSim workload configuration.

        astra.configuration.common_config.workload = astra.generate_collective(collective=Collective.ALLREDUCE, coll_size= 8 * 1024 * 1024, npu_range=[0, 8])
        print(astra.configuration.common_config.workload)

        # ##### Configure the system configurations

        astra.configuration.common_config.system.scheduling_policy = astra.configuration.common_config.system.LIFO
        astra.configuration.common_config.system.endpoint_delay = 10
        astra.configuration.common_config.system.active_chunks_per_dimension = 1
        astra.configuration.common_config.system.preferred_dataset_splits = 4
        astra.configuration.common_config.system.all_gather_implementation = [astra.configuration.common_config.system.RING]
        astra.configuration.common_config.system.all_to_all_implementation = [astra.configuration.common_config.system.DIRECT]
        astra.configuration.common_config.system.all_reduce_implementation = [astra.configuration.common_config.system.RING]
        astra.configuration.common_config.system.collective_optimization = astra.configuration.common_config.system.LOCALBWAWARE
        astra.configuration.common_config.system.local_mem_bw = 1600
        astra.configuration.common_config.system.peak_perf = 900
        astra.configuration.common_config.system.roofline_enabled = 0
        print(astra.configuration.common_config.system)

        # ##### Configure the remote memory configuration

        astra.configuration.common_config.remote_memory.memory_type = astra.configuration.common_config.remote_memory.NO_MEMORY_EXPANSION
        print(astra.configuration.common_config.remote_memory)

        # ##### Configure the Network_backend, topology and protocol

        astra.configuration.network_backend.htsim.topology.network_topology_configuration.network.clear()
        astra.configuration.network_backend.htsim.topology.network_topology_configuration.network.add("ring", 8, 100, 0.005)
        astra.configuration.network_backend.htsim.htsim_protocol.choice = astra.configuration.network_backend.htsim.htsim_protocol.TCP
        print("Network backend set to", astra.configuration.network_backend.choice)
        print("network backend choice set to:",astra.configuration.network_backend.htsim.topology.choice)
        print("protocol set to", astra.configuration.network_backend.htsim.htsim_protocol.choice)

        # ##### Configure the fat tree topology.

        # Configuring topo file
        astra.configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.nodes = 8
        astra.configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.podsize = 4
        astra.configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tiers = 3

        # Configuring values for each tiers
        # Configuring values for tier 0
        astra.configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.set(
            downlink_speed_gbps=200
        )
        astra.configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.radix_down = 2
        astra.configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.radix_up = 2
        astra.configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_0.downlink_latency_ns = 1000

        # Configuring values for tier 1
        astra.configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_1.set(
            downlink_speed_gbps=200
        )
        astra.configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_1.radix_down = 2
        astra.configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_1.radix_up = 4
        astra.configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_1.downlink_latency_ns = 1000
        astra.configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_1.bundle = 1

        # Configuring values for tier 2
        astra.configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_2.set(
            downlink_speed_gbps=100
        )
        astra.configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_2.radix_down = 4
        astra.configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_2.downlink_latency_ns = 1000
        astra.configuration.network_backend.htsim.topology.network_topology_configuration.htsim_topology.fat_tree.tier_2.bundle = 2

        astra.configuration.network_backend.htsim.htsim_protocol.tcp.nodes = "8"
        print(astra.configuration.network_backend.htsim.topology.network_topology_configuration)

        # #### Start the simulation by providing the network backend name in uppercase letters.

        astra.run_simulation(NetworkBackend.HTSIM)


        assert True
    except Exception as e:
        assert False, f'Unexpected exception: {e}'
