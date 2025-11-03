import re
from pathlib import Path
from nbconvert import PythonExporter
import nbformat
import textwrap


def wrap_notebook_in_function(input_nb_path: Path, output_py_path: Path, function_name: str):
    """
    Converts a Jupyter notebook (.ipynb) to a Python script wrapped inside a function.
    """
    with open(input_nb_path, "r", encoding="utf-8") as f:
        notebook = nbformat.read(f, as_version=4)

    exporter = PythonExporter()
    script_body, _ = exporter.from_notebook_node(notebook)

    cleaned_code = []
    for line in script_body.splitlines():
        if re.match(r"^#\s*In\[.*\]:", line):
            continue
        if "# coding:" in line or line.strip().startswith("#!/usr/bin/env"):
            continue
        cleaned_code.append(line)

    cleaned_script = "\n".join(cleaned_code)
    cleaned_script = re.sub(r"\n\s*\n+", "\n\n", cleaned_script)
    cleaned_script = re.sub(
        r"sys\.path\.append\s*\(.*?\)",
        'sys.path.append("../client-scripts/utils")\nsys.path.append("../../client-scripts/utils")\nsys.path.append("./client-scripts/utils")',
        cleaned_script,
    )
    cleaned_script = re.sub(
        r'(server_endpoint\s*=\s*")[\d\.]+:\d+(")', r'f"0.0.0.0:{port_number}"', cleaned_script
    )
    indented_code = textwrap.indent(cleaned_script, "        ")
    wrapped_code = (
        f"def {function_name}(port_number):\n\n"
        f"    try:\n"
        f"{indented_code}\n"
        f"        assert True\n"
        f"    except Exception as e:\n"
        f"        assert False, f'Unexpected exception: {{e}}'\n"
    )
    output_py_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_py_path, "w", encoding="utf-8") as f:
        f.write(wrapped_code)

    print(f"Converted: {input_nb_path} → {output_py_path}")


def convert_all_notebooks(root_dir: str = "../client-scripts/notebooks"):
    """
    Recursively converts all .ipynb notebooks under `root_dir` into Python files
    wrapped in functions, saving them under a `tests/` subfolder.
    """
    for notebook_path in Path(root_dir).rglob("*.ipynb"):
        if ".ipynb_checkpoints" in notebook_path.parts:
            continue
        if not notebook_path.stem.startswith("config_to_schema"):
            output_name = f"test_{notebook_path.stem}.py"
            output_path = Path("tests") / "test-notebook" / output_name

            function_name = output_path.stem

            wrap_notebook_in_function(notebook_path, output_path, function_name)


if __name__ == "__main__":
    convert_all_notebooks()
