"""
MIT License

Copyright (c) 2025 Keysight Technologies

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import threading
import queue
import os
import subprocess
import logging
import psutil
import grpc

if __package__ is None or __package__ == "":
    from utils import Constants, SimulationStatus, Utilities
    from errors import SimulationError
else:
    from astra_server.utils import Constants, SimulationStatus, Utilities
    from astra_server.errors import SimulationError

module_logger = logging.getLogger("ASTRA-sim Server:SimulationHandler")
logger = logging.LoggerAdapter(module_logger)


class SimulationHandler:
    """
    Singleton class that handles the simulation execution
    """

    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(SimulationHandler, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self._initialized = True
            self.simulation_pid = -1
            self._log_queue = None
            self._log_file = None
            self.process_death_event = threading.Event()
            self.backends = {}
            self.backend_filename = "backends.json"
            self.was_terminated = False
            self.simulation_status = SimulationStatus.INACTIVE.value
            self.load_backends()

    def terminate_simulation(self):
        """
        terminates the ongoing simulation by using the stored pid
        """
        process = psutil.Process(self.simulation_pid)
        if process:
            self.was_terminated = True
            process.terminate()
            self.simulation_pid = -1
            return SimulationStatus.TERMINATED.value

    @staticmethod
    def _process_active(pid: int) -> bool:
        """
        checks if a given process is active by checking the pid passed as argument
        """
        try:
            process = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return False
        if process.status() not in (psutil.STATUS_DEAD, psutil.STATUS_ZOMBIE):
            return True
        return False

    def execute_astra_sim(self, command):
        """
        This executes the astra-sim binary by using the command passed as an argument
        """
        self._log_file = os.path.join(Constants.RESULTS_DIR, "simulation.log")
        if os.path.exists(self._log_file):
            os.remove(self._log_file)

        with open(self._log_file, "w", encoding="utf-8"):
            pass

        if self._log_file is None:
            logger.error("Log file does not exist")
            raise FileNotFoundError(
                "Log file does not exist", grpc.StatusCode.NOT_FOUND, 404
            )

        log_file = self._log_file
        self._log_queue = queue.Queue(maxsize=65536)
        self.process_death_event = threading.Event()

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )
        except SimulationError as e:
            logger.exception(f"Failed to start subprocess - {e}")
            raise SimulationError(
                "Failed to start subprocess", grpc.StatusCode.INTERNAL, 500
            ) from e

        self.simulation_pid = process.pid

        try:
            if process.stdout:
                for line in iter(process.stdout.readline, ""):
                    logger.info(line.strip())
                    with open(log_file, "a", encoding="utf-8") as outfile:
                        outfile.write(line)
                        outfile.flush()
                        self._log_queue.put(line)

            if process.stderr:
                for line in iter(process.stderr.readline, ""):
                    self.process_death_event.set()
                    logger.error(line.strip())
                    with open(log_file, "a", encoding="utf-8") as outfile:
                        outfile.write(line)
                        outfile.flush()
                        self._log_queue.put(line)
                    process.terminate()
                    self.simulation_pid = -100

        except SimulationError as e:
            logger.exception(f"Exception while reading process output {e}")
            self.process_death_event.set()
            self.simulation_pid = -1

        finally:
            if process:
                process.wait()
            self._log_queue.put(None)

    def load_backends(self) -> None:
        """
        This function reads the backend config and creates a dictionary which stores all the backends
        """
        backend_config = {
            "analytical_congestion_aware": {
                "binary_name": "AstraSim_Analytical_Congestion_Aware",
                "build_directory": "build/astra_analytical/build/bin",
            },
            "analytical_congestion_unaware": {
                "binary_name": "AstraSim_Analytical_Congestion_Unaware",
                "build_directory": "build/astra_analytical/build/bin",
            },
            "ns3": {
                "binary_name": "ns3.42-AstraSimNetwork-default",
                "build_directory": "extern/network_backend/ns-3/build/scratch",
            },
            "htsim": {
                "binary_name": "AstraSim_HTSim",
                "build_directory": "build/astra_htsim/build/bin",
            },
        }
        astra_sim_path = os.getenv("ASTRA_SIM_PATH", "/app/astra-sim")
        if not os.path.exists(astra_sim_path):
            script_path = os.path.dirname(os.path.abspath(__file__))
            astra_sim_path = os.path.join(script_path, "..", "astra-sim")
        logger.info(f"Using astra_sim_path: {astra_sim_path}")

        for backend_name, backend in backend_config.items():
            binary_name = backend["binary_name"]
            build_directory = os.path.join(astra_sim_path, backend["build_directory"])
            if Utilities.is_file_or_folder_present(
                os.path.join(build_directory, binary_name)
            ):
                logger.info("Backend %s exists", backend_name)
                self.backends[backend_name] = BackendManager(
                    binary_name=binary_name,
                    binary_path=build_directory,
                )
            else:
                logger.warning("Backend %s does not exist", backend_name)


class BackendManager:
    """
    Data class that holds the binary name and the path of binary
    """

    def __init__(self, binary_name: str, binary_path: str):
        self.binary_name = binary_name
        self.binary_path = binary_path
