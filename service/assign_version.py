import toml

PYPROJECT_TOML_FILE_PATH = "pyproject.toml"
MODELS_SDK_VERSION = "../models/.GENERATED_VERSION"
with open(PYPROJECT_TOML_FILE_PATH, "r", encoding="utf-8") as f:
    toml_dict = toml.load(f)

with open(".GENERATED_VERSION", "r", encoding="utf-8") as f:
    version = f.read().strip()

with open(MODELS_SDK_VERSION, "r", encoding="utf-8") as sdk_version_file:
    models_sdk_version = sdk_version_file.read().strip()

print("TOML as Python dictionary:")
toml_dict["project"]["version"] = version
dependencies = toml_dict["project"]["dependencies"]
for dep in dependencies:
    if dep.startswith("astra_sim_sdk"):
        dependencies.remove(dep)
        dependencies.append(f"astra_sim_sdk==={models_sdk_version}")
        break
toml_dict["project"]["dependencies"] = dependencies

print(toml_dict)

with open(PYPROJECT_TOML_FILE_PATH, "w", encoding="utf-8") as f:
    toml.dump(toml_dict, f)

print(f"\nUpdated TOML written to {PYPROJECT_TOML_FILE_PATH}")
