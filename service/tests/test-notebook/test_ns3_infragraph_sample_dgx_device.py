def test_ns3_infragraph_sample_dgx_device(port_number):

    try:

        # ##### Imports the necessary modules and sets the system path to locate them.

        import sys
        sys.path.append("../client-scripts/utils")
        sys.path.append("../../client-scripts/utils")
        sys.path.append("./client-scripts/utils")
        from astra_sim import AstraSim, Collective, NetworkBackend
        from infragraph.blueprints.devices.dgx import Dgx
        from infragraph.blueprints.fabrics.single_tier_fabric import SingleTierFabric
        import networkx
        from infragraph.infragraph_service import InfraGraphService
        import astra_sim_sdk.astra_sim_sdk as astra_sim_kit

        # ##### Connects the client to the AstraSim gRPC server, initializes the AstraSim SDK, and creates a folder (tagged as specified) containing all configuration details, generated results, and logs.

        astra = AstraSim(f"0.0.0.0:{port_number}", tag = "infragraph_dgx_trial")

        # ##### Creating Infragraph with 2 dgx Hosts & 1 rack switch
        # 

        dgx_count = 2
        fabric = SingleTierFabric(Dgx(), dgx_count)
        astra.configuration.infragraph.infrastructure.deserialize(fabric.serialize())
        total_npus = dgx_count * 8 # dgx has 8 npus to total npus = dgx_count * npu_count_per_dgx

        # ##### Display Fabric

        service = InfraGraphService()
        service.set_graph(fabric)

        g = service.get_networkx_graph()
        print(networkx.write_network_text(g, vertical_chains=True))

        # ##### Generates workload execution traces for each rank and configures the data size, which is mandatory for AstraSim workload configuration.

        astra.configuration.common_config.workload = astra.generate_collective(collective=Collective.ALLREDUCE, coll_size= 8 *1024*1024, npu_range=[0, total_npus])

        # ##### Configure the system configurations

        astra.configuration.common_config.system.scheduling_policy = astra.configuration.common_config.system.LIFO
        astra.configuration.common_config.system.endpoint_delay = 10
        astra.configuration.common_config.system.active_chunks_per_dimension = 1
        astra.configuration.common_config.system.all_gather_implementation = [astra.configuration.common_config.system.RING]
        astra.configuration.common_config.system.all_to_all_implementation = [astra.configuration.common_config.system.DIRECT]
        astra.configuration.common_config.system.all_reduce_implementation = [astra.configuration.common_config.system.ONERING]
        astra.configuration.common_config.system.collective_optimization = astra.configuration.common_config.system.LOCALBWAWARE
        astra.configuration.common_config.system.local_mem_bw = 1600

        # ##### Configure the remote memory configuration

        astra.configuration.common_config.remote_memory.memory_type = astra.configuration.common_config.remote_memory.NO_MEMORY_EXPANSION
        print(astra.configuration.common_config.remote_memory)

        # ##### Configure the network backend choice and the topology choice for that backend
        # 

        astra.configuration.network_backend.choice = astra.configuration.network_backend.NS3
        astra.configuration.network_backend.ns3.topology.choice = astra.configuration.network_backend.ns3.topology.INFRAGRAPH
        astra.configuration.network_backend.ns3.network.packet_payload_size = int(8192)

        # ##### Adding ns3 trace and logical dimension 

        astra.configuration.network_backend.ns3.logical_topology.logical_dimensions = [total_npus]
        astra.configuration.network_backend.ns3.trace.trace_ids = []
        for i in range(0, total_npus):
            astra.configuration.network_backend.ns3.trace.trace_ids.append(i)

        # ##### Adding ASTRA-sim specific annotation

        host_device_spec = astra_sim_kit.AnnotationDeviceSpecifications()
        host_device_spec.device_bandwidth_gbps = 100
        host_device_spec.device_latency_ms = 0.05
        host_device_spec.device_name = "dgx"
        host_device_spec.device_type = "host"
        astra.configuration.infragraph.annotations.device_specifications.append(host_device_spec)

        switch_device_spec = astra_sim_kit.AnnotationDeviceSpecifications()
        switch_device_spec.device_bandwidth_gbps = 100
        switch_device_spec.device_latency_ms = 0.05
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

        astra.run_simulation(NetworkBackend.NS3)

        # ##### Read output files

        import pandas as pd
        import os
        from common import FileFolderUtils
        df = pd.read_csv(os.path.join(FileFolderUtils.get_instance().OUTPUT_DIR, "fct.csv"))
        df.head()

        df = pd.read_csv(os.path.join(FileFolderUtils.get_instance().OUTPUT_DIR, "flow_stats.csv"))

        assert True
    except Exception as e:
        assert False, f'Unexpected exception: {e}'
