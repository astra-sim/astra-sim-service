# Models

The **models** define a model-driven and vendor-neutral API for capturing Astra-sim configurations in addition to supporting [infragraph](https://github.com/Keysight/infragraph).

These models are designed and maintained using [openapiart](https://github.com/open-traffic-generator/openapiart/tree/main), a tooling framework for generating consistent APIs, SDKs, and documentation from OpenAPI specifications.
Model development follows the [openapiart Model Guide](https://github.com/open-traffic-generator/openapiart/blob/main/MODELGUIDE.md).

---

## Structure

The model definitions are organized into two major parts:

1. **APIs** – Define the operations and endpoints.
2. **Schemas** – Define the data models and configuration structures.

The schema directory includes subfolders for various model components:

- `api/`
- `config/`
- `control/`
- `infragraph/`
- `result/`

All modifications should be done within these schema subfolders following the modeling guidelines. Once updates are complete, the SDK is generated using the openapiart generator.

---

## Building the SDK

To build the SDK, run:

```
make build
```


This process:
- Pulls the openapiart dependency from the repository.
- Pulls infragraph and copies the model schemas.
- Runs the generator on the defined models.
- Produces the **astra-sim-sdk** package.

The resulting SDK is used by both client scripts and the service backend to manage configuration and runtime operations.

---

## Documentation Generation

To generate API documentation using Redocly, run:

```
make redocly
```


This command:
- Generates an `openapi.html` documentation file inside the `artifacts` directory.
- Builds the latest SDK and API reference.
- Provides a convenient browser-accessible overview of the models and their usage.

---

## Summary

The `models` directory serves as the foundation for defining, generating, and documenting the configuration and operational interface for Astra-sim and InfraGraph. Changes to model definitions should always comply with the openapiart guidelines to ensure consistency across the SDK and documentation artifacts.
