def test_ns3_single_dgx_device(port_number):

    try:

        # ##### Import the required modules and configure the system path to locate them

        import sys
        sys.path.append("../client-scripts/utils")
        sys.path.append("../../client-scripts/utils")
        sys.path.append("./client-scripts/utils")
        import networkx
        import astra_sim_sdk.astra_sim_sdk as astra_sim_kit
        from astra_sim import AstraSim, Collective, NetworkBackend
        from infragraph.infragraph_service import InfraGraphService
        from infragraph.blueprints.devices.nvidia.dgx import NvidiaDGX, DgxProfile
        from infragraph import Infrastructure

        # ##### Call the AstraSim client helper with the server endpoint and tag to connect to the ASTRA-sim gRPC server, initialize the SDK, and create a tagged folder for configs, results, and logs

        astra = AstraSim(f"0.0.0.0:{port_number}", tag = "ns3_single_dgx")

        # ##### Get all available DGX variants

        from typing import get_args
        print(get_args(DgxProfile))

        # ##### Create a Nvidia DGX device fabric using infragraph device blueprint

        server = NvidiaDGX("dgx_h100")
        infrastructure = Infrastructure()
        infrastructure.devices.append(server)
        infrastructure.instances.add(name=server.name, device=server.name, count=1)
        astra.configuration.infragraph.infrastructure.deserialize(infrastructure.serialize())
        print(astra.configuration.infragraph.infrastructure)

        # ##### Initialize the Infragraph service, display the fabric topology, and retrieve/set the total number of NPUs to generate the collective

        service = InfraGraphService()
        service.set_graph(infrastructure)
        total_npus = service.get_component(device=server, type="xpu").count
        g = service.get_networkx_graph()
        print(networkx.write_network_text(g, vertical_chains=True))

        # ##### Generate workload execution traces for each rank and set the required data size for AstraSim configuration

        astra.configuration.common_config.workload = astra.generate_collective(collective=Collective.ALLREDUCE, coll_size= 1 *1024*1024, npu_range=[0, total_npus])

        # ##### Configure ASTRA-sim system config

        astra.configuration.common_config.system.scheduling_policy = astra.configuration.common_config.system.LIFO
        astra.configuration.common_config.system.endpoint_delay = 10
        astra.configuration.common_config.system.active_chunks_per_dimension = 1
        astra.configuration.common_config.system.all_gather_implementation = [astra.configuration.common_config.system.RING]
        astra.configuration.common_config.system.all_to_all_implementation = [astra.configuration.common_config.system.DIRECT]
        astra.configuration.common_config.system.all_reduce_implementation = [astra.configuration.common_config.system.ONERING]
        astra.configuration.common_config.system.collective_optimization = astra.configuration.common_config.system.LOCALBWAWARE
        astra.configuration.common_config.system.local_mem_bw = 1600

        # ##### Configure ASTRA-sim remote memory configuration

        astra.configuration.common_config.remote_memory.memory_type = astra.configuration.common_config.remote_memory.NO_MEMORY_EXPANSION
        print(astra.configuration.common_config.remote_memory)

        # ##### Configure the selected network backend and the topology (infragraph or nc_topology)

        astra.configuration.network_backend.choice = astra.configuration.network_backend.NS3
        astra.configuration.network_backend.ns3.topology.choice = astra.configuration.network_backend.ns3.topology.INFRAGRAPH
        astra.configuration.network_backend.ns3.network.packet_payload_size = int(8192)

        # ##### Adding ns3 trace and logical dimension 

        astra.configuration.network_backend.ns3.logical_topology.logical_dimensions = [total_npus]
        astra.configuration.network_backend.ns3.trace.trace_ids = []
        for i in range(0, total_npus):
            astra.configuration.network_backend.ns3.trace.trace_ids.append(i)

        # ##### Adding ASTRA-sim - Infragraph specific annotation for Nvidia DGX

        host_device_spec = astra_sim_kit.AnnotationDeviceSpecifications()
        host_device_spec.device_bandwidth_gbps = 100
        host_device_spec.device_latency_ms = 0.05
        host_device_spec.device_name = server.name
        host_device_spec.device_type = "host"
        astra.configuration.infragraph.annotations.device_specifications.append(host_device_spec)

        # ##### Configure ASTRA-sim cmd parameters

        astra.configuration.common_config.cmd_parameters.comm_scale = 1
        astra.configuration.common_config.cmd_parameters.injection_scale = 1
        astra.configuration.common_config.cmd_parameters.rendezvous_protocol = False

        # #### Start the simulation by specifying the network backend

        astra.run_simulation(NetworkBackend.NS3)

        # ##### Download all the configurations as a zip

        astra.download_configuration()

        # ##### Read output files

        import pandas as pd
        import os
        from common import FileFolderUtils
        df = pd.read_csv(os.path.join(FileFolderUtils.get_instance().OUTPUT_DIR, "fct.csv"))
        df.head()

        # ##### Save infragraph as a yaml

        import yaml
        import os
        from common import FileFolderUtils
        with open(os.path.join(FileFolderUtils.get_instance().OUTPUT_DIR,"../infrastructure","ns3_single_dgx"),"w") as f:
            data = infrastructure.serialize("dict")
            yaml.dump(data, f, default_flow_style=False, indent=4)

        print("saved yaml to:", os.path.join(FileFolderUtils.get_instance().OUTPUT_DIR,"..","ns3_single_dgx.yaml"))

        assert True
    except Exception as e:
        assert False, f'Unexpected exception: {e}'
