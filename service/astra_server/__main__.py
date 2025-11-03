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

from concurrent import futures
import sys
import json
import logging
import os
import argparse
import base64
import grpc
from astra_sim_sdk import astra_sim_sdk as astra_sim
import astra_sim_sdk.astra_pb2 as pb2
import astra_sim_sdk.astra_pb2_grpc as pb2_grpc
from google.protobuf import json_format
from google.protobuf.json_format import MessageToJson

if __package__ is None or __package__ == "":
    from server_handler import ServerHandler
    from errors import ServerError
    from utils import Constants, Utilities
else:
    from astra_server.server_handler import ServerHandler
    from astra_server.errors import ServerError
    from astra_server.utils import Constants, Utilities


log_dir = os.path.join(Constants.SERVER_DIR, "logs")
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(log_dir, "astra_server.log")),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("ASTRA-sim Server:__main__")


# Implement the service defined in the proto
class OpenapiServicer(pb2_grpc.OpenapiServicer):
    def __init__(self):
        self._prefix_config = None
        super(OpenapiServicer, self).__init__()

    def UploadConfig(self, request, context):
        try:
            logger.info("Executing UploadConfig")
            Utilities.reset_test_run_folder()
            with open(
                os.path.join(Constants.TEST_RUN_DIR, Constants.CONFIGURATION + ".zip"),
                "wb",
            ) as f:
                f.write(request.request_bytes)
            ServerHandler().upload_config()
            sr = astra_sim.ServerResponse()
            sr.message = "Upload configuration successfully executed"
            logger.info("Done executing UploadConfig")
            return json_format.Parse(json.dumps({"server_response": sr.serialize("dict")}), pb2.SetConfigResponse())  # type: ignore
        except ServerError as e:
            err = astra_sim.Error()
            err.code = e.grpc_code
            err.errors = [e.message]
            logger.error(e.message)
            context.set_code(e.grpc_code)
            context.set_details(err.serialize())
            return pb2.SetConfigResponse()  # type: ignore

    def streamUploadConfig(self, request_iterator, context):
        try:
            logger.info("Executing streamUploadConfig")
            Utilities.reset_test_run_folder()
            full_str = b""
            for data in request_iterator:
                full_str += data.datum

            with open(
                os.path.join(Constants.TEST_RUN_DIR, Constants.CONFIGURATION + ".zip"),
                "wb",
            ) as f:
                f.write(full_str)

            ServerHandler().upload_config()
            sr = astra_sim.ServerResponse()
            sr.message = "Upload configuration successfully executed"
            logger.info("Done executing streamUploadConfig")
            return json_format.Parse(json.dumps({"server_response": sr.serialize("dict")}), pb2.SetConfigResponse())  # type: ignore
        except ServerError as e:
            err = astra_sim.Error()
            err.code = e.grpc_code
            err.errors = [e.message]
            logger.error(e.message)
            context.set_code(e.grpc_code)
            context.set_details(err.serialize())
            return pb2.SetConfigResponse()  # type: ignore

    def SetConfig(self, request, context):
        try:
            logger.info("Executing SetConfig")
            json_str = MessageToJson(request.config, preserving_proto_field_name=True)
            conf = astra_sim.Config()
            conf.deserialize(json_str)
            warnings = ServerHandler().set_config(conf)
            sr = astra_sim.ServerResponse()
            sr.message = "Configuration applied successfully."
            logger.info("Done executing SetConfig")
            if warnings != "":
                sr.message = sr.message + " " + warnings
                logger.info("warnings: %s", warnings)
            return json_format.Parse(json.dumps({"server_response": sr.serialize("dict")}), pb2.SetConfigResponse())  # type: ignore

        except ServerError as e:
            err = astra_sim.Error()
            err.code = e.grpc_code
            err.errors = [e.message]
            logger.error(e.message)
            context.set_code(e.grpc_code)
            context.set_details(err.serialize())
            return pb2.SetConfigResponse()  # type: ignore

    def streamGetConfig(self, request, context):
        try:
            logger.info("Executing streamGetConfig")
            filepath = ServerHandler().get_config()
            with open(filepath, "rb") as file:
                file_data = file.read()
                chunk_size = 3 * 1024 * 1024
                for i in range(0, len(file_data), chunk_size):
                    if i + chunk_size > len(file_data):
                        chunk = file_data[i : len(file_data)]
                    else:
                        chunk = file_data[i : i + chunk_size]
                    yield pb2.Data(datum=chunk)  # type: ignore
            logger.info("Done executing streamGetConfig")
        except ServerError as e:
            err = astra_sim.Error()
            err.code = e.grpc_code
            err.errors = [e.message]
            logger.error(e.message)
            context.set_code(e.grpc_code)
            res_obj = pb2.GetResultResponse()  # type: ignore
            return res_obj

    def GetConfig(self, request, context):
        try:
            logger.info("Executing GetConfig")
            configuration_path = ServerHandler().get_config()
            with open(configuration_path, "rb") as file:
                file_data = file.read()
            file_bytes = base64.b64encode(file_data).decode("utf-8")
            logger.info("Done executing GetConfig")
            return json_format.Parse(json.dumps({"response_bytes": file_bytes}), pb2.GetConfigResponse())  # type: ignore
        except ServerError as e:
            err = astra_sim.Error()
            err.code = e.grpc_code
            err.errors = [e.message]
            logger.error(e.message)
            context.set_code(e.grpc_code)
            context.set_details(err.serialize())
            return pb2.GetConfigResponses()  # type: ignore

    def GetStatus(self, request, context):
        try:
            logger.info("Executing GetStatus")
            status = ServerHandler().get_status()
            control_obj = astra_sim.ControlStatus()
            control_obj.status = status
            control_obj_json = control_obj.serialize("dict")
            logger.info("Done executing GetStatus")
            return json_format.Parse(json.dumps({"control_status": control_obj_json}), pb2.GetStatusResponse())  # type: ignore
        except ServerError as e:
            err = astra_sim.Error()
            err.code = e.grpc_code
            err.errors = [e.message]
            logger.error(e.message)
            context.set_code(e.grpc_code)
            context.set_details(err.serialize())
            return pb2.SetConfigResponse()  # type: ignore

    def SetControlAction(self, request, context):
        try:
            logger.info("Executing SetControlAction")
            choice = request.control.choice
            choice_name = pb2.Control.Choice.Enum.Name(choice)  # type: ignore
            if choice_name == "undefined":
                logger.error("Simulation control is undefined")
                raise ServerError(
                    "control choice is undefined", grpc.StatusCode.INVALID_ARGUMENT
                )
            elif choice_name == "stop":
                logger.info("Terminating simulation")
                ServerHandler().terminate_simulation()
                sr = astra_sim.ServerResponse()
                sr.message = "Simulation terminated successfully"
                logger.info("Done terminating simulation")
                logger.info("Done executing SetControlAction")
                return json_format.Parse(json.dumps({"server_response": sr.serialize("dict")}), pb2.SetControlActionResponse())  # type: ignore
            elif choice_name == "start":
                backend = request.control.start.backend
                backend_name = pb2.ControlStart.Backend.Enum.Name(backend)  # type: ignore
                logger.info("Starting %s simulation", backend_name)
                if backend_name == "unspecified":
                    raise ServerError(
                        "control choice is undefined", grpc.StatusCode.INVALID_ARGUMENT
                    )
                ServerHandler().run_simulation(backend_name)
                sr = astra_sim.ServerResponse()
                sr.message = "Simulation started successfully"
                logger.info("Simulation started successfully")
                logger.info("Done executing SetControlAction")
                return json_format.Parse(json.dumps({"server_response": sr.serialize("dict")}), pb2.SetControlActionResponse())  # type: ignore
        except ServerError as e:
            err = astra_sim.Error()
            err.code = e.grpc_code
            err.errors = [e.message]
            logger.error(e.message)
            context.set_code(e.grpc_code)
            context.set_details(err.serialize())
            return pb2.SetControlActionResponse()  # type: ignore

    def streamGetResult(self, request, context):
        try:
            logger.info("Executing streamGetResult")
            # get the request choice:
            choice = request.result.choice
            choice_name = pb2.Result.Choice.Enum.Name(choice)  # type: ignore
            if choice_name == "metadata":
                logger.info("Fetching result metadata")
                metadata = ServerHandler().get_result_metadata()
                metadata_str = json.dumps(metadata, indent=4)
                file_data = metadata_str.encode("utf-8")
                chunk_size = 3 * 1024 * 1024
                for i in range(0, len(file_data), chunk_size):
                    if i + chunk_size > len(file_data):
                        chunk = file_data[i : len(file_data)]
                    else:
                        chunk = file_data[i : i + chunk_size]
                    yield pb2.Data(datum=chunk)  # type: ignore
                logger.info("Done fetching result metadata")
                logger.info("Done executing streamGetResult")
            elif choice_name == "filename":
                filename = request.result.filename
                logger.info("Fetching Result File %s", filename)
                filepath = ServerHandler().get_result_file(filename)
                with open(filepath, "rb") as file:
                    file_data = file.read()
                    chunk_size = 3 * 1024 * 1024
                    for i in range(0, len(file_data), chunk_size):
                        if i + chunk_size > len(file_data):
                            chunk = file_data[i : len(file_data)]
                        else:
                            chunk = file_data[i : i + chunk_size]
                        yield pb2.Data(datum=chunk)  # type: ignore
                logger.info("Done fetching result file %s", filename)
                logger.info("Done executing streamGetResult")
        except ServerError as e:
            err = astra_sim.Error()
            err.code = e.grpc_code
            err.errors = [e.message]
            logger.error(e.message)
            context.set_code(e.grpc_code)
            context.set_details(err.serialize())
            return pb2.GetResultResponse()  # type: ignore

    def GetResult(self, request, context):
        try:
            logger.info("Executing GetResult")
            result_str = MessageToJson(request.result, preserving_proto_field_name=True)
            result_configuration = astra_sim.Result()
            result_configuration.deserialize(result_str)
            if result_configuration.choice == "metadata":
                logger.info("Fetching result metadata")
                metadata = ServerHandler().get_result_metadata()
                metadata_str = json.dumps(metadata, indent=4)
                text_bytes = metadata_str.encode("utf-8")
                text_bytes = base64.b64encode(text_bytes).decode("utf-8")
                logger.info("Done fetching result metadata")
                logger.info("Done executing GetResult")
                return json_format.Parse(json.dumps({"response_bytes": text_bytes}), pb2.GetResultResponse())  # type: ignore
            elif result_configuration.choice == "filename":
                filename = result_configuration.filename
                logger.info("Fetching Result File %s", filename)
                filepath = ServerHandler().get_result_file(filename)
                with open(filepath, "rb") as file:
                    file_data = file.read()
                file_bytes = base64.b64encode(file_data).decode("utf-8")
                logger.info("Done fetching result file %s", filename)
                logger.info("Done executing GetResult")
                return json_format.Parse(json.dumps({"response_bytes": file_bytes}), pb2.GetResultResponse())  # type: ignore
        except ServerError as e:
            err = astra_sim.Error()
            err.code = e.grpc_code
            err.errors = [e.message]
            logger.error(e.message)
            context.set_code(e.grpc_code)
            context.set_details(err.serialize())
            return pb2.GetResultResponse()  # type: ignore

    def GetVersion(self, request, context):
        try:
            logger.info("Executing GetVersion")
            # Create a GRPC API object
            api_obj = astra_sim.api(
                transport=astra_sim.Transport.GRPC,
                logger=logger,
                loglevel=logging.INFO,
            )
            version_obj = api_obj.get_local_version()

            version_obj_json = version_obj.serialize("dict")
            logger.info("Done executing GetVersion")
            return json_format.Parse(json.dumps({"version": version_obj_json}), pb2.GetVersionResponse())  # type: ignore
        except ServerError as e:
            err = astra_sim.Error()
            err.code = e.grpc_code
            err.errors = [e.message]
            logger.error(e.message)
            context.set_code(e.grpc_code)
            context.set_details(err.serialize())
            return pb2.GetVersionResponse()  # type: ignore


def serve(port):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    pb2_grpc.add_OpenapiServicer_to_server(OpenapiServicer(), server)
    server.add_insecure_port("[::]:" + str(port))
    server.start()
    ips = os.popen("hostname -I").read().strip().split()
    for ip in ips:
        logger.info("gRPC server running on: %s:%s", ip, port)
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        server.stop(5)
        logger.info("Server shutdown gracefully")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--port_number",
        help="Port number for the ASTRA-sim server",
        default=Constants.DEFAULT_PORT_NUM,
    )
    args = parser.parse_args()
    _ = ServerHandler()
    Utilities.reset_test_run_folder()
    if args.port_number is None or args.port_number == "":
        serve(port="8989")
    else:
        serve(port=args.port_number)


if __name__ == "__main__":
    main()
