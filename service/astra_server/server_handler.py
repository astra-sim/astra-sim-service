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
import os
import logging
import shutil
import grpc
import astra_sim_sdk.astra_sim_sdk as astra_sim

if __package__ is None or __package__ == "":
    from simulation_handler import SimulationHandler
    from utils import Constants, Utilities, SimulationStatus
    from configuration_handler import ConfigurationHandler
    from errors import (
        SimulationAlreadyRunningError,
        ConfigurationError,
        SimulationError,
        ResultError,
    )

else:
    from astra_server.simulation_handler import SimulationHandler
    from astra_server.utils import Constants, Utilities, SimulationStatus
    from astra_server.configuration_handler import ConfigurationHandler
    from astra_server.errors import (
        SimulationAlreadyRunningError,
        ConfigurationError,
        SimulationError,
        ResultError,
    )


if os.path.exists(os.path.join(Constants.SERVER_DIR, "logs")):
    shutil.rmtree(os.path.join(Constants.SERVER_DIR, "logs"))
os.makedirs(os.path.join(Constants.SERVER_DIR, "logs"))

module_logger = logging.getLogger("ASTRA-sim Server:ServerHandler")
logger = logging.LoggerAdapter(module_logger)


class ServerHandler:
    """
    A singleton class that implements the grpc api calls as a middleware
    """

    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(ServerHandler, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self._initialized = True
            self.config_handler = ConfigurationHandler()
            self.simulation_handler = SimulationHandler()

    def upload_config(self):
        """
        checks whether the simulation is running and then extracts the files from the uploaded zip
        """
        if self.simulation_handler.simulation_status == SimulationStatus.RUNNING.value:
            raise SimulationAlreadyRunningError(
                "A simulation is already running", grpc.StatusCode.UNAVAILABLE, 409
            )

        if Utilities.extract_zip(
            os.path.join(Constants.TEST_RUN_DIR, Constants.CONFIGURATION + ".zip")
        ):
            return
        else:
            raise ConfigurationError(
                "issue with configuration zip file", grpc.StatusCode.NOT_FOUND, 404
            )

    def set_config(self, configuration: astra_sim.Config):
        """
        sets the config - takes the configuration from payload and generates files from the schema - also validates the workload uploaded
        """
        if self.simulation_handler.simulation_status == SimulationStatus.RUNNING.value:
            raise SimulationAlreadyRunningError(
                "A simulation is already running", grpc.StatusCode.UNAVAILABLE, 409
            )
        self.config_handler.validate_and_process_config(configuration)

        warn_messages = ""
        if len(self.config_handler.warn_messages) > 0:
            warn_messages = "warnings: " + "\n".join(self.config_handler.warn_messages)
        return warn_messages

    def get_config(self):
        """
        returns the config as a zip
        """
        Utilities.delete_file(
            os.path.join(
                Constants.TEST_RUN_DIR, Constants.SERVER_CONFIGURATION + ".zip"
            )
        )
        Utilities.zip_folder(
            Constants.CONFIGURATION_DIR,
            os.path.join(
                Constants.TEST_RUN_DIR, Constants.SERVER_CONFIGURATION + ".zip"
            ),
        )
        if Utilities.is_file_or_folder_present(
            os.path.join(
                Constants.TEST_RUN_DIR, Constants.SERVER_CONFIGURATION + ".zip"
            )
        ):
            return os.path.join(
                Constants.TEST_RUN_DIR, Constants.SERVER_CONFIGURATION + ".zip"
            )
        else:
            raise ConfigurationError(
                "unable to generate configuration zip", grpc.StatusCode.NOT_FOUND, 404
            )

    def get_status(self):
        """
        returns the simulation status
        """
        return self.simulation_handler.simulation_status

    def terminate_simulation(self):
        """
        terminates an ongoing simulation
        """
        if (
            self.simulation_handler.terminate_simulation()
            == SimulationStatus.TERMINATED.value
        ):
            return
        else:
            raise SimulationError(
                "Failed to terminate simulation due to an unexpected error",
                grpc.StatusCode.FAILED_PRECONDITION,
                409,
            )

    def run_simulation(self, backend_name):
        """
        Runs the simulation for a specific backend provided as a parameter
        """
        if self.simulation_handler.simulation_status == SimulationStatus.RUNNING.value:
            raise SimulationAlreadyRunningError(
                "A simulation is already running", grpc.StatusCode.UNAVAILABLE, 409
            )

        if backend_name not in self.simulation_handler.backends:
            available_backends = ", ".join(self.simulation_handler.backends.keys())
            raise SimulationError(
                "Invalid backend specified in the request. A backend must be selected from "
                + available_backends,
                grpc.StatusCode.INVALID_ARGUMENT,
                400,
            )

        bm = self.simulation_handler.backends[backend_name]
        self.simulation_handler.simulation_status = SimulationStatus.RUNNING.value

        if len(self.config_handler.command) == 0:
            raise ConfigurationError(
                "Unable to generate the simulation runtime command due to internal server error.",
                grpc.StatusCode.INTERNAL,
                500,
            )

        command = [bm.binary_path + "/" + bm.binary_name]
        command.extend(self.config_handler.command)
        module_logger.info(
            "Running for backend %s and executing command %s", backend_name, command
        )
        thread = threading.Thread(
            target=self._execute_simulation, args=(command,), daemon=True
        )
        thread.start()
        return

    def _execute_simulation(self, command):
        """
        Runs the simulation from the command sent as the argument
        """
        self.simulation_handler.simulation_pid = -1
        self.simulation_handler.was_terminated = False  # New flag

        try:
            self.simulation_handler.execute_astra_sim(command)
        except SimulationError as e:
            module_logger.exception(
                "Simulation execution failed due to an exception - %s.", e
            )
            self.simulation_handler.simulation_status = SimulationStatus.FAILED.value
            return

        if self.simulation_handler.was_terminated:
            module_logger.warning("Simulation was externally terminated.")
            self.simulation_handler.simulation_status = (
                SimulationStatus.TERMINATED.value
            )
        elif (
            self.simulation_handler.process_death_event.is_set()
            or self.simulation_handler.simulation_pid == -1
        ):
            module_logger.warning("Simulation process failed or exited unexpectedly.")
            self.simulation_handler.simulation_status = SimulationStatus.FAILED.value
        else:
            self.simulation_handler.simulation_status = SimulationStatus.COMPLETED.value

    def get_result_metadata(self):
        """
        Returns the generated results metadata for a given simulation run
        """
        if not os.path.exists(Constants.RESULTS_DIR):
            raise ResultError(
                "Output directory does not exist", grpc.StatusCode.NOT_FOUND, 404
            )
        file_details = []
        for filename in os.listdir(Constants.RESULTS_DIR):
            module_logger.info(
                "Collecting stat for file: %s at %s", filename, Constants.RESULTS_DIR
            )
            file_path = os.path.join(Constants.RESULTS_DIR, filename)
            if os.path.isfile(file_path):
                # get the propertoes
                file_details.append(Utilities.get_file_properties(file_path))
        if len(file_details) == 0:
            raise ResultError("result files not found", grpc.StatusCode.NOT_FOUND, 404)
        return file_details

    def get_result_file(self, filename):
        """
        Returns the file passed as an argument to this function
        """
        if filename == "*":
            Utilities.zip_folder(Constants.RESULTS_DIR, Constants.RESULTS_ZIP)
            return Constants.RESULTS_ZIP
        else:
            file_path = os.path.join(Constants.RESULTS_DIR, filename)
            if os.path.exists(file_path):
                return file_path
            else:
                raise FileNotFoundError(
                    filename + " not found", grpc.StatusCode.NOT_FOUND, 404
                )
