# Client Scripts

This directory contains the client-scripts, which include utility modules and sample Jupyter notebooks for interacting with different simulation backends.

## Directory Structure

- **notebooks/**
  Contains sample notebooks for all supported backends. The notebooks are present in the notebooks folder and are as follows:

    | Notebook Path                                           | Description |
    |--------------------------------------------------------|-------------|
    | analytical_congestion_aware_sample.ipynb               | Notebook demonstrating simulation runs using the analytical congestion-aware backend |
    | analytical_congestion_unaware_sample.ipynb             | Notebook demonstrating simulation runs using the analytical congestion-unaware backend |
    | config_to_schema_sample.ipynb                          | Notebook showing how configuration files are translated into the Astra-sim schema format |
    | htsim_sample.ipynb                                     | Notebook demonstrating simulation runs using the htsim backend. |
    | load_existing_et_example.ipynb                         | Notebook demonstrating a simulation run that loads an existing execution trace and runs it on the ns-3 backend |
    | ns3_sample.ipynb                                       | Notebook demonstrating simulation runs using the ns-3 backend |
    | infragraph/htsim_clos_fabric_2tier.ipynb               | Notebook demonstrating a simulation run on the htsim backend using a two-tier Clos fabric defined in Infragraph |
    | infragraph/htsim_clos_fabric_3tier.ipynb               | Notebook demonstrating a simulation run on the htsim backend using a three-tier Clos fabric defined in Infragraph |
    | infragraph/ns3_clos_fabric_2tier.ipynb                 | Notebook demonstrating a simulation run on the ns-3 backend using a two-tier Clos fabric defined in Infragraph |
    | infragraph/ns3_clos_fabric_3tier.ipynb                 | Notebook demonstrating a simulation run on the ns-3 backend using a three-tier Clos fabric defined in Infragraph |
    | infragraph/ns3_infragraph_sample_dgx_device.ipynb      | Notebook demonstrating a simulation run on the ns-3 backend using a single-tier fabric with a switch and DGX host device defined in Infragraph |
    | infragraph/ns3_infragraph_sample_generic_devices.ipynb | Notebook demonstrating a simulation run on the ns-3 backend using a single-tier fabric with a switch and generic host devices defined in Infragraph |




- **notebooks/infragraph/**
  Contains the Infragraph notebook for the NS3 backend.
  Users can build fabrics using Infragraph and execute corresponding NS3 simulations.

- **notebooks/config_to_schema_sample.ipynb**
    This notebook holds samples which allows to convert a given ASTRA-sim file configuration to the schema. A folder infragraph/mock_configuration holds all the available schemas and this notebook translates all the file to the schema model using utilities and sdk.

## Notebook Sections

Each notebook follows a structured workflow, divided into these main sections:

1. **Importing the utilities**
   Load the helper modules required for client-side interactions.

2. **Creating the AstraSim object**
   The user initializes an AstraSim object by connecting to the service using its IP address and port number and assigning a tag for identification.

3. **Creating configurations with the SDK**
   The AstraSim object contains a configuration object that allows defining both the AstraSim and Infragraph configurations.
   Users can also define workloads by specifying:
   - The target collective operation
   - The data size
   - The NPU range `[0, n]`
    The repo uses mlcommons chakra to create execution trace for the specified npu range


   This enables flexible workload generation tailored to various simulation setups.

4. **Running the simulation**
   The simulation is triggered using a single function that abstracts multiple backend API calls.
   This operation handles the following automatically:
   - Uploading the workload
   - Setting the configuration
   - Running the simulation
   - Polling the simulation status

   Once the status is marked as completed, the tool downloads the generated result files.
   At present, a basic NS3 translator is available for interpreting these output files.

## Notes on Tags

Tags are identifiers used to distinguish simulation runs or client instances.
They help organize configurations and manage simulation results efficiently.
