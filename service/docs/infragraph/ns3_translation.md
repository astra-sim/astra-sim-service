# Design Document: Infragraph to NS3 Topology Translation

## Overview

The **NS3 Topology Translation** process converts an **Infragraph** (infrastructure graph) into an **NS3-compatible topology**.
This translation defines nodes, their device relationships, and the network connections between **hosts**, **switches**, and **NICs**.

An **NS3 topology** requires every device to have a **unique identifier** and separates **switches** from **NPUs**.

### Key Components

- **Total nodes:** GPUs + switches
- **Switch count**
- **Total connections**
- **Connection list**, where each entry includes:
  - Source identifier
  - Destination identifier
  - Bandwidth
  - Latency
  - Error rate

Both the **Infragraph** and a **NetworkX graph** (enriched with annotations) are used during the translation to generate the final NS3-compatible output.

---

## Goal

Translate the Infragraph into a fully connected and annotated NS3 topology by assigning unique device identifiers, defining ranks, and including all link specifications.

---

## Steps to Generate NS3 Topology

1. **Detect Hosts**
   - Identify all host devices from the Infragraph.

2. **Assign Rank Identifiers to NPUs**
   - Use **rank assignment** to give unique IDs to NPUs.
   - If no rank data is provided, generate ranks internally.

3. **Assign Identifiers to Internal Switches**
   - For internal switches (e.g., NVSwitch, PCIe), assign unique IDs only when connected to multiple NPUs.
   - Skip single-NPU connections for efficiency.

4. **Assign Identifiers to Host NICs**
   - Each NIC receives the same ID as the NPU it connects to.
   - Follow the rule: **number of NICs = number of NPUs**.
   - If NIC mapping is indirect, assign sequential ranks.

5. **Assign Identifiers to External Switches**
   - Detect **Top-of-Rack (ToR)** and higher-level switches.
   - Assign each switch a unique switch ID.
   - All ports of a single switch share the same switch ID (e.g., `switch.0.port.0` and `switch.0.port.1`).
   - Maintain a **switch registry** for all assigned switch IDs.

6. **Generate External Connections**
   - Use the **Infragraph Service** to expand the topology into a **NetworkX graph**.
   - Extract nodes and edges, assign device identifiers, and handle same-device or invalid connections.
   - Add annotated link attributes such as bandwidth, latency, and error rate.

---

## 1. Detect Hosts

The first step is identifying **hosts** from the Infragraph.

- Use the **Annotation: Device Specification**, which defines `device_type = host`.
- Parse the Infragraph to create a **device-instance mapping** between each device and its instances.
- Using this mapping along with annotations, all host devices can be accurately detected and indexed.

---

## 2. Rank Assignment

Rank assignment ensures that every NPU under each host gets a unique NS3 identifier.

### Purpose

- Assigns a unique rank to each NPU across all hosts.
- Links **communicator group configurations** to topology nodes.
- Enables **Chakra trace execution**, as ranks are required to define process groups.

### From Infragraph and Annotations

- The **Infragraph** describes devices and component-level connections.
- The **Annotation** schema provides rank details.
- If ranks are not provided, the translator automatically generates them to maintain consistency.

---

## 3. Internal Switch Identifier Assignment

After rank assignment:

- Check all internal switches within each host.
- If a switch connects to multiple NPUs, assign a **unique switch ID**.
- For single-NPU connections, skip creating a separate ID to avoid redundancy.

---

## 4. Host NIC Identifier Assignment

- Each NIC is mapped to an NPU and given the same rank ID.
- If NICs are not directly connected to NPUs, assign rank IDs sequentially.

**Rule:**
`Number of NICs = Number of NPUs`

This ensures consistent mapping between NPUs and NICs.

---

## 5. External Switch Identifier Assignment

- Trace connections from each host to higher-level switches such as **Top-of-Rack (ToR)** or **aggregation** switches.
- Assign a **unique identifier** to each external switch.
- Apply the same ID to all ports belonging to that switch (e.g., `switch.0.port.0` and `switch.0.port.1`).
- Store these IDs in a **switch registry list** for later topology assembly.

---

## 6. Generating External Connections

This step builds the finalized network connectivity graph.

- Use the **Infragraph Service** to generate a **NetworkX graph** representation.
- Extract all nodes and edges from the graph.
- Filter out unwanted edges, such as:
  - Same-device internal links
  - Non-network or logical-only connections
- Assign the previously generated **device identifiers** to each valid edge.
- Retrieve link-level data (like bandwidth, latency, and error rate) from the **Annotation: Link Specification** using the `link_name`.
- Add these parameters to each connection entry.

---

## Output

The result of the translation is a complete **NS3 topology object** that includes:

- Hosts and NPUs with unique assigned rank identifiers
- NICs mapped one-to-one with NPUs
- Internal switches (only when connected to multiple NPUs)
- External switches with unique IDs
- A detailed connection list containing:
  - Source and destination identifiers
  - Bandwidth
  - Latency
  - Error rate

This final structure contains all necessary information to initialize and run **NS3-based Astra-sim network simulations**.
