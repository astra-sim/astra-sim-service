import openapiart

"""
The following command produces these artifacts:
    - ./art/openapi.yaml
    - ./art/openapi.json
    - ./art/otg-convergence.proto
"""
import sys
import os

# Passed as env variable.
PACKAGE_NAME = os.getenv("PACKAGE_NAME")
if PACKAGE_NAME is None:
    print("Please provide PACKAGE_NAME as env variable.")
    sys.exit(1)

# Passed as env variable.
VERSION = os.getenv("VERSION")
if VERSION is None:
    print("Please provide VERSION as env variable.")
    sys.exit(1)

openapiart.OpenApiArt(
    api_files=["schema/api/api.yaml"],
    protobuf_name="astra",
    artifact_dir="artifacts",
    generate_version_api=True,
).GeneratePythonSdk(package_name=PACKAGE_NAME, sdk_version=VERSION)
