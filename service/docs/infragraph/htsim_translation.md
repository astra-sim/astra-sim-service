# Design Document: Infragraph to HTSim Fat Tree Topology Translation

## Overview

The **HTSim Topology Translation** process converts an **Infragraph** (infrastructure graph) into a topology compatible with the **HTSim Fat Tree** model.
This translation defines all nodes, their device relationships, and connections between **hosts**, **switches**, and **NICs**.

### Key Components of HTSim Fat Tree

- Total number of nodes
- Pod size
- Number of tiers
- For each tier, detailed information including:
  - `downlink_speed_gbps`
  - `radix_up`
  - `radix_down`
  - `queue_up`
  - `queue_down`
  - `oversubscribed`
  - `bundle`
  - `switch_latency_ns`
  - `downlink_latency_ns`

Both the **Infragraph** and a **NetworkX graph** enhanced with annotations are used to generate the final output compatible with HTSim Fat Tree.

---

## Goal

To translate the Infragraph by analyzing the graph structure to deduce:
- The nodes present
- Pod size
- Number of tiers
- Tier-based parameters and configurations

---

## Steps to Generate HTSim Topology

1. **Detect the Host Tier**
   - Identify all host devices from the Infragraph using device annotations.
   - Generate initial tier information for hosts.

2. **Detect Tier0, Tier1, and Tier2 Devices**
   - Derive the Tier0 (ToR) tier from the host tier.
   - Use Tier0 devices to find the Pod tier (Tier1).
   - Use Tier1 devices to find the Spine tier (Tier2).
   - Store these devices in a tier map with keys: `host`, `tier0`, `tier1`, and `tier2`.

3. **Gather Tier Information**
   - Collect attributes for Tier0 by analyzing connections between hosts and Tier1 devices.
   - Collect attributes for Tier1 by analyzing connections between Tier1 and Tier2 devices.
   - Collect attributes for Tier2 devices.
   - Gather detailed parameters such as `bundle`, `oversubscribed`, `radix_up`, `radix_down`, `downlink_speed_gbps`, etc.
   - Create a **top-to-bottom map**: a mapping from each top-level device to all devices connected one tier below.

4. **Determine Pod Size**
   - Using the top-to-bottom and tier maps, select one Pod switch.
   - Traverse downward to count connected hosts.
   - Summing the hosts for that Pod determines the pod size.

---

## Processing Notes

- Parse the NetworkX graph generated from the Infragraph, analyzing all edges to extract tier-based information.
- Validate that the number of tiers is between 2 and 3 inclusive.
- Fill missing device and link parameters from annotations, such as device radix, bandwidth, bundle, and oversubscription factors.
- The Infragraph analysis yields the device nodes, tiers, pod size, and essential tier-specific parameters for HTSim.

---

## Output

The output is the fully defined HTSim Fat Tree topology, including:
- Total nodes count
- Pod size
- Number of tiers
- Detailed tier information (as listed above) for every tier in the topology

This serves as the input topology definition for HTSim simulations based on fat tree designs.
