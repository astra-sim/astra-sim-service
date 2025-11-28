# Astra Server

The Astra Server orchestrates simulation workflows using the **Astra-Sim** engine, providing a robust interface for managing trials, configuration, and results from start to finish.

## Overview

Astra-Sim Server integrates with **astra-sim** and the **Astra-Sim plugin** to handle the entire lifecycle of a simulation—setup, workload upload, execution, and result retrieval. Each stage is coordinated via gRPC endpoints, enabling streamlined trial management.

## Dependencies

The core server relies on the following packages:

| Dependency         | Version  |
|--------------------|----------|
| astra-sim-schema   | 0.0.6    |
| infragraph         | 0.6.1    |
| astra-sim          | 6d9c0d2  |

It also leverages the **astra-sim-sdk**, which provides gRPC stubs implemented in `__main__`.

### gRPC Endpoints

The principal gRPC interfaces are:

- UploadConfig
- SetConfig
- GetConfig
- GetStatus
- SetControlAction
- GetResult
- GetVersion

## Simulation Workflow

### 1. Workload Upload

- Send a zipped collection of execution trace files to the server using `UploadConfig`.
- The server extracts and stores these files for use in simulation.

### 2. Simulator Configuration

- Use `SetConfig` to transmit simulation parameters and setup options.
- The server validates and saves configurations via the plugin. If a simulation is already running, an error is returned.

### 3. Simulation Execution

- Trigger the simulation by calling `SetControlAction` with the action `"start"` and selecting a backend.
- The server starts a new simulation unless another trial is in progress.

### 4. Monitoring Progress

- Check simulation status with `GetStatus`. Status options include `RUNNING`, `FAILED`, `TERMINATED`, `COMPLETED`, and `INACTIVE`.
- Upon success, status returns `COMPLETED`.

### 5. Results Retrieval

- Obtain metadata on generated files by calling `GetResult` with the payload `"metadata"`.
- Download individual result files or simulation logs by providing their filenames to `GetResult`, which streams file bytes.

## Additional Controls

The server offers further API commands for enhanced control:

- `GetConfig`: Download the current configuration as a zip archive.
- `SetControlAction` with `"stop"`: Gracefully terminate a running simulation.

## Code Organization

The project is structured in modular components:

- `__main__.py`: Entry point for starting the server and initializing gRPC interfaces.
- `server_handler.py`: Backend manager class; orchestrates requests and sub-handlers (using a singleton approach).
- `config_handler.py`: Handles configuration validation, file processing, and simulation argument construction.
- `simulation_handler.py`: Controls simulation lifecycle, process IDs, and state transitions.
- `errors.py`: Custom exception definitions for error handling.
- `utils.py`: Helper methods for simulation management and utility tasks.
- `infrastructure/`: Translation modules for **Infragraph**, including support for NS3 backends.
  - Read more on [NS3 Translation](docs/infragraph/ns3_translation.md), [HTSim Translation](docs/infragraph/htsim_translation.md) and [Annotation handling](docs/infragraph/annotations.md) in supplied documentation.

