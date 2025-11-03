# ASTRA-sim Service

ASTRA-sim Service provides a unified interface for configuring and running ASTRA-sim as a gRPC-based service. It enables researchers and developers to co-design AI and HPC systems using a model-driven, vendor-neutral API built on the [openapiart](https://github.com/open-traffic-generator/openapiart/tree/main) framework.

---

## Overview

The ASTRA-sim Service architecture consists of the following key components:

- Models: Define the schema for ASTRA-sim configuration and infrastructure descriptions. These models are specified using [openapiart](https://github.com/open-traffic-generator/openapiart/tree/main), providing a neutral and extensible format for capturing system and simulation details.
- Service: Implements the ASTRA-sim server that runs using gRPC. It serves as the execution backend for simulation requests from clients.
- Client Scripts: Provide user-facing interfaces, including Jupyter notebooks, that allow users to configure simulations, trigger runs, and visualize results.

The combination of these components supports model-driven simulation workflows where users can define ASTRA-sim setups programmatically, launch remote simulations, and analyze outcomes—all from interactive notebooks.

---

## Repository Structure

The repository is organized into three primary submodules:

1. models/ – [Read the model documentation](models/README.md)
   Contains schema definitions for ASTRA-sim and InfraGraph (version 0.5.0) configuration.
2. client-scripts/ – [Read the client-scripts documentation](client-scripts/README.md)
   Provides client utilities and example notebooks for launching and managing simulation sessions.
3. service/ – [Read the service documentation](service/README.md)
   Hosts the gRPC-based simulation service that runs the ASTRA-sim backend.

---

## Getting Started

### Build the Service

To build the ASTRA-sim Service:
```
make install-prerequisites
make build-all
```

- `make install-prerequisites`: Installs all required dependencies, libraries, and supporting tools.
- `make build-all`: Executes the full build pipeline:
  1. Builds the model artifacts.
  2. Runs tests for client scripts.
  3. Builds and tests the service components.

---

### Run the Service

After a successful build, the service can be started locally using:

```
cd service/astra_server
python3 __main__.py
```


This command launches the ASTRA-sim gRPC server, exposing it for client connections.

---

### Using the Client Notebooks

Client Jupyter notebooks are provided under `client-scripts/notebooks`. You can open them using the VS Code Jupyter extension, configure connections to the running ASTRA-sim service (via the server IP and port), and run simulation workflows interactively.

---

## Docker Build and Deployment

The repository provides a Docker-based build for deploying the ASTRA-sim service in an isolated environment.

To build the Docker image:

```
make build-service-docker
```

To run the Docker image:

```
docker run -it astra_sim_service:<tag>
```

Where tag == version. For example for version 0.0.6, the command would be

```
docker run -it astra_sim_service:0.0.6
```


Once built, the image can be run independently and accessed remotely using the exposed host IP and port. Clients (via notebooks or scripts) can connect to this containerized service for distributed simulation execution.

---

## Development Environment

The project uses VS Code Dev Containers to ensure a reproducible and isolated development setup.

- Base image: ubuntu:22.04
- Preinstalled dependencies: Python 3.x, gRPC tools, Make, CMake, and simulation dependencies.
- The dev container automatically sets up your environment, installs packages, and provides consistent build behavior across developers.

This environment is particularly useful for contributors who want a ready-to-use setup for model updates, client testing, or service development.

---

## Contributing

You can contribute to ASTRA-sim Service in the following ways:

- Open an issue in the repository to report bugs or request features.
- Fork the models repository and submit a pull request (PR) with your changes or extensions.

Contributions are welcome across all submodules—models, client, and service—to improve schema definitions, enhance automation scripts, and extend backend performance.

