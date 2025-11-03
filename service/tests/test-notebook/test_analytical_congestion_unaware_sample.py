def test_analytical_congestion_unaware_sample(port_number):

    try:

        # ##### Imports the necessary modules and sets the system path to locate them.

        import sys
        sys.path.append("../client-scripts/utils")
        sys.path.append("../../client-scripts/utils")
        sys.path.append("./client-scripts/utils")
        from astra_sim import AstraSim, Collective, NetworkBackend

        # ##### Connects the client to the AstraSim gRPC server, initializes the AstraSim SDK, and creates a folder (tagged as specified) containing all configuration details, generated results, and logs.

        astra = AstraSim(f"0.0.0.0:{port_number}", tag = "analytical_unaware_trial")

        # ##### Generates workload execution traces for each rank and configures the data size, which is mandatory for AstraSim workload configuration.

        astra.configuration.common_config.workload = astra.generate_collective(collective=Collective.ALLREDUCE, coll_size= 1024*1024*1024, npu_range=[0,8])
        print(astra.configuration.common_config.workload)

        # ##### Configure the system configurations

        astra.configuration.common_config.system.scheduling_policy = astra.configuration.common_config.system.LIFO
        astra.configuration.common_config.system.endpoint_delay = 10
        astra.configuration.common_config.system.active_chunks_per_dimension = 1
        astra.configuration.common_config.system.all_gather_implementation = [astra.configuration.common_config.system.RING]
        astra.configuration.common_config.system.all_to_all_implementation = [astra.configuration.common_config.system.DIRECT]
        astra.configuration.common_config.system.all_reduce_implementation = [astra.configuration.common_config.system.RING]
        astra.configuration.common_config.system.collective_optimization = astra.configuration.common_config.system.LOCALBWAWARE
        astra.configuration.common_config.system.local_mem_bw = 1600
        print(astra.configuration.common_config.system)

        # ##### Configure the remote memory configuration

        astra.configuration.common_config.remote_memory.memory_type = astra.configuration.common_config.remote_memory.NO_MEMORY_EXPANSION
        print(astra.configuration.common_config.remote_memory)

        # ##### Configure the Network_backend and topology

        # astra.configuration.network_backend.choice = astra.configuration.network_backend.ANALYTICAL_CONGESTION_UNAWARE
        astra.configuration.network_backend.analytical_congestion_aware.topology.network.clear()
        astra.configuration.network_backend.analytical_congestion_unaware.topology.network.add("fullyconnected", 8, 100, 0.005)
        print("Network backend set to", astra.configuration.network_backend.choice)
        print("network backend choice set to:",astra.configuration.network_backend.analytical_congestion_unaware.topology.choice)

        # ##### Configure the cmd parameters, non-mandatory parameters

        astra.configuration.common_config.cmd_parameters.comm_scale = 1
        astra.configuration.common_config.cmd_parameters.rendezvous_protocol = False
        astra.configuration.common_config.cmd_parameters.injection_scale = 1

        # #### Start the simulation by providing the network backend name in uppercase letters.

        astra.run_simulation(NetworkBackend.ANALYTICAL_CONGESTION_UNAWARE)


        assert True
    except Exception as e:
        assert False, f'Unexpected exception: {e}'
