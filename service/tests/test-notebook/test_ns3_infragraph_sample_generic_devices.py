def test_ns3_infragraph_sample_generic_devices(port_number):

    try:

        # ##### Imports the necessary modules and sets the system path to locate them.

        import sys
        sys.path.append("../client-scripts/utils")
        sys.path.append("../../client-scripts/utils")
        sys.path.append("./client-scripts/utils")
        from astra_sim import AstraSim, Collective, NetworkBackend
        from astra_sim_sdk import Device, Component
        from infragraph import Component, InfrastructureEdge
        from infragraph.infragraph_service import InfraGraphService
        from infragraph.blueprints.devices.server import Server
        from infragraph.blueprints.devices.generic_switch import Switch
        import astra_sim_sdk.astra_sim_sdk as astra_sim_kit

        # ##### Connects the client to the AstraSim gRPC server, initializes the AstraSim SDK, and creates a folder (tagged as specified) containing all configuration details, generated results, and logs.

        astra = AstraSim(f"0.0.0.0:{port_number}", tag = "infragraph_trial")

        # ##### Generates workload execution traces for each rank and configures the data size, which is mandatory for AstraSim workload configuration.

        astra.configuration.common_config.workload = astra.generate_collective(collective=Collective.ALLREDUCE, coll_size= 8 *1024*1024, npu_range=[0,8])
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

        # ##### Configure the network backend choice and the topology choice for that backend
        # 

        # We need to configure the network backend here since we are translating the topology from infragraph and not creating it directly from the sdk.

        astra.configuration.network_backend.choice = astra.configuration.network_backend.NS3
        astra.configuration.network_backend.ns3.topology.choice = astra.configuration.network_backend.ns3.topology.INFRAGRAPH
        astra.configuration.network_backend.ns3.network.packet_payload_size = int(8192)
        astra.configuration.network_backend.ns3.logical_topology.logical_dimensions = [8]
        astra.configuration.network_backend.ns3.trace.trace_ids = [0, 1, 2, 3, 4, 5, 6, 7]

        # ##### Creating Infrastructure with 4 Hosts & 1 Rack Device
        # 

        astra.configuration.infragraph.infrastructure.name = "1host-4ranks"

        server = Device()
        server.deserialize((Server(npu_factor=1).serialize()))

        hosts = astra.configuration.infragraph.infrastructure.instances.add(
            name="host", device=server.name, count=4
        )
        switch = Device()
        switch.deserialize(Switch(port_count=16).serialize())

        rack_switch = astra.configuration.infragraph.infrastructure.instances.add(
            name="rack_switch", device=switch.name, count=1
        )

        astra.configuration.infragraph.infrastructure.devices.append(server).append(switch)

        # ##### Creating Links

        rack_link = astra.configuration.infragraph.infrastructure.links.add(
            name="rack-link",
            description="Link characteristics for connectivity between servers and rack switch",
        )
        rack_link.physical.bandwidth.gigabits_per_second = 200

        # ##### Adding edges and annotations

        host_component = InfraGraphService.get_component(server, Component.NIC)
        switch_component = InfraGraphService.get_component(switch, Component.PORT)
        # link each host to one leaf switch
        for idx in range(hosts.count):
            edge = astra.configuration.infragraph.infrastructure.edges.add(
                scheme=InfrastructureEdge.ONE2ONE, link=rack_link.name
            )
            edge.ep1.instance = f"{hosts.name}[{idx}]"
            edge.ep1.component = f"{host_component.name}[0]"
            edge.ep2.instance = f"{rack_switch.name}[0]"
            edge.ep2.component = f"{switch_component.name}[{idx * 2}]"
            edge = astra.configuration.infragraph.infrastructure.edges.add(
                scheme=InfrastructureEdge.ONE2ONE, link=rack_link.name
            )
            edge.ep1.instance = f"{hosts.name}[{idx}]"
            edge.ep1.component = f"{host_component.name}[1]"
            edge.ep2.instance = f"{rack_switch.name}[0]"
            edge.ep2.component = f"{switch_component.name}[{idx * 2 + 1}]"

        # annotation
        host_device_spec = astra_sim_kit.AnnotationDeviceSpecifications()
        host_device_spec.device_bandwidth_gbps = 200
        host_device_spec.device_latency_ms = 0.05
        host_device_spec.device_name = "server"
        host_device_spec.device_type = "host"
        astra.configuration.infragraph.annotations.device_specifications.append(host_device_spec)

        switch_device_spec = astra_sim_kit.AnnotationDeviceSpecifications()
        switch_device_spec.device_bandwidth_gbps = 200
        switch_device_spec.device_latency_ms = 0.05
        switch_device_spec.device_name = "switch"
        switch_device_spec.device_type = "switch"
        astra.configuration.infragraph.annotations.device_specifications.append(
            switch_device_spec
        )

        # ##### Configure the cmd parameters, non-mandatory parameters

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
        df.head()

        assert True
    except Exception as e:
        assert False, f'Unexpected exception: {e}'
