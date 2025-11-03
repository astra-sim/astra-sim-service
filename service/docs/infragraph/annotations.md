# Design Document: Topology Annotation System

## Overview

The **Annotation System** adds extra information to the network topology.
It helps define three main parts of the simulation setup:

- Device Specification
- Link Specification
- Rank Assignment

These annotations are used by Astra-sim network backends like **HTSim** and **NS3** to understand how devices and links behave during simulation.

---

## 1. Device Specification

This section defines the properties of each device (host or switch) in the network.

### Parameters
- device_latency_ms
- device_bandwidth_gbps
- radix_up
- radix_down
- queue_up
- queue_down
- device_type
- device_name

### Purpose
- Parameters like latency, bandwidth, radix, and queues are required in **HTSim** topologies.
- `device_type` helps identify if a device is a **switch** or a **host**.
- `device_name` connects these settings with the specific device node.
- These parameters are important for consistent topology behavior across simulation backends.

---

## 2. Link Specification

This defines how each link behaves between devices.

### Parameters
- link_name
- packet_loss_rate
- link_error_rate

### Purpose
- These describe the quality and reliability of each link.
- Both **HTSim** and **NS3** use these values during simulation.
- For **NS3**, link bandwidth and latency are taken from the infrastructure graph (`infragraph`).
- If some link data is missing, the system adds **default link values** automatically.

---

## 3. Rank Assignment

This part assigns a unique rank ID to each host or NPU device.

### Purpose
- Links communicator group settings with the infrastructure graph.
- Needed by **NS3** to assign unique IDs to hosts.
- If no rank is given by the user, an internal logic automatically assigns one.

---

## 4. Annotation Class

The **Annotation Class** (part of `infra_utils`) handles reading, storing, and formatting the annotations.

### What It Does
- Takes input annotations and builds dictionaries for use in translation.
- Is used by all **topology translators** while generating backend-specific topologies.
- Makes sure all annotation data is consistent and easy to use.

### How It Works
1. The topology translator creates an `Annotation` object.
2. The annotations are read and checked for errors.
3. The processed data is merged into the topology graph.
4. The backend uses this data during simulation setup.

---

