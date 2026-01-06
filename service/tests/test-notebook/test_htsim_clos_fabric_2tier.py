def test_htsim_clos_fabric_2tier(port_number):

    try:

        # ##### Imports the necessary modules and sets the system path to locate them.

        import sys
        import networkx
        import astra_sim_sdk.astra_sim_sdk as astra_sim_kit
        sys.path.append("../client-scripts/utils")
        sys.path.append("../../client-scripts/utils")
        sys.path.append("./client-scripts/utils")
        from astra_sim import AstraSim, Collective, NetworkBackend
        from infragraph.infragraph_service import InfraGraphService
        from infragraph.blueprints.fabrics.clos_fat_tree_fabric import ClosFatTreeFabric
        from infragraph.blueprints.devices.server import Server
        from infragraph.blueprints.devices.generic_switch import Switch

        # ##### Connects the client to the AstraSim gRPC server, initializes the AstraSim SDK, and creates a folder (tagged as specified) containing all configuration details, generated results, and logs.

        astra = AstraSim(f"0.0.0.0:{port_number}", tag = "htsim_clos_2tier_trial")

        # ##### Creating Infragraph for 2 tier clos fabric

        server = Server()
        switch = Switch(port_count=8)
        clos_fat_tree = ClosFatTreeFabric(switch, server, 2,[])
        astra.configuration.infragraph.infrastructure.deserialize(clos_fat_tree.serialize())
        print(astra.configuration.infragraph.infrastructure)

        # ##### Initialize Infragraph service and Display Fabric

        service = InfraGraphService()
        service.set_graph(clos_fat_tree)
        g = service.get_networkx_graph()
        print(networkx.write_network_text(g, vertical_chains=True))

        total_npus = 16

        # ##### Generates workload execution traces for each rank and configures the data size, which is mandatory for AstraSim workload configuration.

        astra.configuration.common_config.workload = astra.generate_collective(collective=Collective.ALLREDUCE, coll_size= 1 *1024*1024, npu_range=[0, total_npus])

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

        # ##### Configure the network backend choice and the topology choice for that backend
        # 

        astra.configuration.network_backend.choice = astra.configuration.network_backend.HTSIM
        astra.configuration.network_backend.htsim.topology.choice = astra.configuration.network_backend.htsim.topology.INFRAGRAPH

        # ##### Configure the protocol choice

        astra.configuration.network_backend.htsim.htsim_protocol.choice = astra.configuration.network_backend.htsim.htsim_protocol.TCP
        print("Network backend set to", astra.configuration.network_backend.choice)
        print("network topology choice set to:",astra.configuration.network_backend.htsim.topology.choice)
        print("protocol set to", astra.configuration.network_backend.htsim.htsim_protocol)
        astra.configuration.network_backend.htsim.htsim_protocol.tcp.nodes = str(total_npus)

        # ##### Adding ASTRA-sim specific annotation

        host_device_spec = astra_sim_kit.AnnotationDeviceSpecifications()
        host_device_spec.device_bandwidth_gbps = 1000
        host_device_spec.device_latency_ms = 0.005
        host_device_spec.device_name = "server"
        host_device_spec.device_type = "host"
        astra.configuration.infragraph.annotations.device_specifications.append(host_device_spec)

        switch_device_spec = astra_sim_kit.AnnotationDeviceSpecifications()
        switch_device_spec.device_bandwidth_gbps = 1000
        switch_device_spec.device_latency_ms = 0.005
        switch_device_spec.device_name = "switch"
        switch_device_spec.device_type = "switch"
        astra.configuration.infragraph.annotations.device_specifications.append(
            switch_device_spec
        )

        # ##### Configure ASTRA-sim cmd parameters

        astra.configuration.common_config.cmd_parameters.comm_scale = 1
        astra.configuration.common_config.cmd_parameters.injection_scale = 1
        astra.configuration.common_config.cmd_parameters.rendezvous_protocol = False

        # #### Start the simulation by providing the network backend name in uppercase letters.

        astra.run_simulation(NetworkBackend.HTSIM)

        # ##### Download all the configurations as a zip

        astra.download_configuration()

        # ##### Save infragraph as a yaml

        import yaml
        import os
        from common import FileFolderUtils
        with open(os.path.join(FileFolderUtils.get_instance().OUTPUT_DIR,"../infrastructure","2tier.yaml"),"w") as f:
            data = clos_fat_tree.serialize("dict")
            yaml.dump(data, f, default_flow_style=False, indent=4)

        print("saved yaml to:", os.path.join(FileFolderUtils.get_instance().OUTPUT_DIR,"..","2tier.yaml"))

        assert True
    except Exception as e:
        assert False, f'Unexpected exception: {e}'
