# ASTRA-sim APIs 1.0.0
# License: MIT

import importlib
import logging
import json
import platform
import yaml
import requests
import urllib3
import io
import sys
import time
import grpc
import semantic_version
import types
import platform
import base64
import re
from google.protobuf import json_format

try:
    from astra_sim_sdk import astra_pb2_grpc as pb2_grpc
except ImportError:
    import astra_pb2_grpc as pb2_grpc
try:
    from astra_sim_sdk import astra_pb2 as pb2
except ImportError:
    import astra_pb2 as pb2

try:
    from typing import Union, Dict, List, Any, Literal
except ImportError:
    from typing_extensions import Literal


if sys.version_info[0] == 3:
    unicode = str


openapi_warnings = []

# instantiate the logger
stderr_handler = logging.StreamHandler(sys.stderr)
formatter = logging.Formatter(
    fmt="%(asctime)s.%(msecs)03d [%(name)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
formatter.converter = time.gmtime
stderr_handler.setFormatter(formatter)
log = logging.getLogger("astra_sim_sdk")
#log.addHandler(stderr_handler)


class Transport:
    HTTP = "http"
    GRPC = "grpc"


def api(
    location=None,
    transport=None,
    verify=True,
    logger=None,
    loglevel=logging.WARN,
    ext=None,
    version_check=False,
    otel_collector=None,
    otel_collector_transport="http",
):
    """Create an instance of an Api class

    generator.Generator outputs a base Api class with the following:
    - an abstract method for each OpenAPI path item object
    - a concrete properties for each unique OpenAPI path item parameter.

    generator.Generator also outputs an HttpApi class that inherits the base
    Api class, implements the abstract methods and uses the common HttpTransport
    class send_recv method to communicate with a REST based server.

    Args
    ----
    - location (str): The location of an Open Traffic Generator server.
    - transport (enum["http", "grpc"]): Transport Type
    - verify (bool): Verify the server's TLS certificate, or a string, in which
      case it must be a path to a CA bundle to use. Defaults to `True`.
      When set to `False`, requests will accept any TLS certificate presented by
      the server, and will ignore hostname mismatches and/or expired
      certificates, which will make your application vulnerable to
      man-in-the-middle (MitM) attacks. Setting verify to `False`
      may be useful during local development or testing.
    - logger (logging.Logger): A user defined logging.logger, if none is provided
      then a default logger with a stderr handler will be provided
    - loglevel (logging.loglevel): The logging package log level.
      The default loglevel is logging.INFO
    - ext (str): Name of an extension package
    """
    params = locals()

    if logger is not None:
        global log
        log = logger
    log.setLevel(loglevel)

    if version_check is False:
        log.warning("Version check is disabled")

    if otel_collector is not None:
        if sys.version_info[0] == 3 and sys.version_info[1] >= 7:
            log.info("Telemetry feature enabled")
        else:
            raise Exception(
                "Telemetry feature is only available for python version >= 3.7"
            )

    transport_types = ["http", "grpc"]
    if ext is None:
        transport = "http" if transport is None else transport
        if transport not in transport_types:
            raise Exception(
                "{transport} is not within valid transport types {transport_types}".format(
                    transport=transport, transport_types=transport_types
                )
            )
        if transport == "http":
            log.info("Transport set to HTTP")
            return HttpApi(**params)
        else:
            log.info("Transport set to GRPC")
            return GrpcApi(**params)
    try:
        if transport is not None:
            raise Exception(
                "ext and transport are not mutually exclusive. Please configure one of them."
            )
        lib = importlib.import_module("sanity_{}.astra_sim_sdk_api".format(ext))
        return lib.Api(**params)
    except ImportError as err:
        msg = "Extension %s is not installed or invalid: %s"
        raise Exception(msg % (ext, err))


class HttpTransport(object):
    def __init__(self, **kwargs):
        """Use args from api() method to instantiate an HTTP transport"""
        self.location = (
            kwargs["location"]
            if "location" in kwargs and kwargs["location"] is not None
            else "https://localhost:443"
        )
        self.verify = kwargs["verify"] if "verify" in kwargs else False
        log.debug(
            "HttpTransport args: {}".format(
                ", ".join(["{}={!r}".format(k, v) for k, v in kwargs.items()])
            )
        )
        self.set_verify(self.verify)
        self._session = requests.Session()

    def set_verify(self, verify):
        self.verify = verify
        if self.verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            log.warning("Certificate verification is disabled")

    def _parse_response_error(self, response_code, response_text):
        error_response = ""
        try:
            error_response = yaml.safe_load(response_text)
        except Exception as _:
            error_response = response_text

        err_obj = Error()
        try:
            err_obj.deserialize(error_response)
        except Exception as _:
            err_obj.code = response_code
            err_obj.errors = [str(error_response)]

        raise Exception(err_obj)

    def send_recv(
        self,
        method,
        relative_url,
        payload=None,
        return_object=None,
        headers=None,
        request_class=None,
    ):
        url = "%s%s" % (self.location, relative_url)
        data = None
        headers = headers or {"Content-Type": "application/json"}
        if payload is not None:
            if isinstance(payload, bytes):
                data = payload
                headers["Content-Type"] = "application/octet-stream"
            elif isinstance(payload, (str, unicode)):
                if request_class is not None:
                    request_class().deserialize(payload)
                data = payload
            elif isinstance(payload, OpenApiBase):
                data = payload.serialize()
            else:
                raise Exception("Type of payload provided is unknown")
        log.debug("Request url - " + str(url))
        log.debug("Method - " + str(method))
        log.debug("Request headers - " + str(headers))
        log.debug("Request payload - " + str(data))
        response = self._session.request(
            method=method,
            url=url,
            data=data,
            verify=False,
            allow_redirects=True,
            # TODO: add a timeout here
            headers=headers,
        )
        log.debug("Response status code - " + str(response.status_code))
        log.debug("Response header - " + str(response.headers))
        log.debug("Response content - " + str(response.content))
        log.debug("Response text - " + str(response.text))
        if response.ok:
            if "application/json" in response.headers["content-type"]:
                # TODO: we might want to check for utf-8 charset and decode
                # accordingly, but current impl works for now
                response_dict = yaml.safe_load(response.text)
                if return_object is None:
                    # if response type is not provided, return dictionary
                    # instead of python object
                    return response_dict
                else:
                    return return_object.deserialize(response_dict)
            elif "application/octet-stream" in response.headers["content-type"]:
                return io.BytesIO(response.content)
            else:
                # TODO: for now, return bare response object for unknown
                # content types
                return response
        else:
            self._parse_response_error(response.status_code, response.text)


class OpenApiStatus:
    messages = {}
    # logger = logging.getLogger(__module__)

    @classmethod
    def warn(cls, key, object):
        if cls.messages.get(key) is not None:
            if cls.messages[key] in object.__warnings__:
                return
            # cls.logger.warning(cls.messages[key])
            logging.warning(cls.messages[key])
            object.__warnings__.append(cls.messages[key])
            log.warning(
                "["
                + OpenApiStatus.warn.__name__
                + "] cls.messages[key]-"
                + cls.messages[key]
            )
            # openapi_warnings.append(cls.messages[key])

    @staticmethod
    def deprecated(func_or_data):
        def inner(self, *args, **kwargs):
            OpenApiStatus.warn(
                "{}.{}".format(type(self).__name__, func_or_data.__name__),
                self,
            )
            return func_or_data(self, *args, **kwargs)

        if isinstance(func_or_data, types.FunctionType):
            return inner
        OpenApiStatus.warn(func_or_data)
        log.warning(
            "[" + OpenApiStatus.deprecated.__name__ + "] func_or_data-" + func_or_data
        )

    @staticmethod
    def under_review(func_or_data):
        def inner(self, *args, **kwargs):
            OpenApiStatus.warn(
                "{}.{}".format(type(self).__name__, func_or_data.__name__),
                self,
            )
            return func_or_data(self, *args, **kwargs)

        if isinstance(func_or_data, types.FunctionType):
            return inner
        OpenApiStatus.warn(func_or_data)
        log.warning(
            "[" + OpenApiStatus.under_review.__name__ + "] func_or_data-" + func_or_data
        )


class OpenApiBase(object):
    """Base class for all generated classes"""

    JSON = "json"
    YAML = "yaml"
    DICT = "dict"

    __slots__ = ()

    __constraints__ = {"global": []}
    __validate_latter__ = {"unique": [], "constraint": []}

    def __init__(self):
        pass

    def serialize(self, encoding=JSON):
        """Serialize the current object according to a specified encoding.

        Args
        ----
        - encoding (str[json, yaml, dict]): The object will be recursively
            serialized according to the specified encoding.
            The supported encodings are json, yaml and python dict.

        Returns
        -------
        - obj(Union[str, dict]): A str or dict object depending on the specified
            encoding. The json and yaml encodings will return a str object and
            the dict encoding will return a python dict object.
        """
        # TODO: restore behavior
        # self._clear_globals()
        if encoding == OpenApiBase.JSON:
            data = json.dumps(self._encode(), indent=2, sort_keys=True)
        elif encoding == OpenApiBase.YAML:
            data = yaml.safe_dump(self._encode())
        elif encoding == OpenApiBase.DICT:
            data = self._encode()
        else:
            raise NotImplementedError("Encoding %s not supported" % encoding)
        # TODO: restore behavior
        # self._validate_coded()
        return data

    def _encode(self):
        raise NotImplementedError()

    def deserialize(self, serialized_object):
        """Deserialize a python object into the current object.

        If the input `serialized_object` does not match the current
        openapi object an exception will be raised.

        Args
        ----
        - serialized_object (Union[str, dict]): The object to deserialize.
            If the serialized_object is of type str then the internal encoding
            of the serialized_object must be json or yaml.

        Returns
        -------
        - obj(OpenApiObject): This object with all the
            serialized_object deserialized within.
        """
        # TODO: restore behavior
        # self._clear_globals()
        if isinstance(serialized_object, (str, unicode)):
            serialized_object = yaml.safe_load(serialized_object)
        self._decode(serialized_object)
        # TODO: restore behavior
        # self._validate_coded()
        return self

    def _decode(self, dict_object):
        raise NotImplementedError()

    def warnings(self):
        warns = list(self.__warnings__)
        if "2.7" in platform.python_version().rsplit(".", 1)[0]:
            del self.__warnings__[:]
        else:
            self.__warnings__.clear()
        return warns


class OpenApiValidator(object):

    __slots__ = ()

    _validation_errors = []

    def __init__(self):
        pass

    def _clear_errors(self):
        if "2.7" in platform.python_version().rsplit(".", 1)[0]:
            del self._validation_errors[:]
        else:
            self._validation_errors.clear()

    def validate_mac(self, mac):
        if mac is None or not isinstance(mac, (str, unicode)) or mac.count(" ") != 0:
            return False
        try:
            if len(mac) != 17:
                return False
            return all([0 <= int(oct, 16) <= 255 for oct in mac.split(":")])
        except Exception:
            log.debug("Validating MAC address - " + str(mac) + " failed ")
            return False

    def validate_ipv4(self, ip):
        if ip is None or not isinstance(ip, (str, unicode)) or ip.count(" ") != 0:
            return False
        if len(ip.split(".")) != 4:
            return False
        try:
            return all([0 <= int(oct) <= 255 for oct in ip.split(".", 3)])
        except Exception:
            log.debug("Validating IPv4 address - " + str(ip) + " failed")
            return False

    def validate_ipv6(self, ip):
        if ip is None or not isinstance(ip, (str, unicode)):
            return False
        ip = ip.strip()
        if (
            ip.count(" ") > 0
            or ip.count(":") > 7
            or ip.count("::") > 1
            or ip.count(":::") > 0
        ):
            return False
        if (ip[0] == ":" and ip[:2] != "::") or (ip[-1] == ":" and ip[-2:] != "::"):
            return False
        if ip.count("::") == 0 and ip.count(":") != 7:
            return False
        if ip == "::":
            return True
        if ip[:2] == "::":
            ip = ip.replace("::", "0:")
        elif ip[-2:] == "::":
            ip = ip.replace("::", ":0")
        else:
            ip = ip.replace("::", ":0:")
        try:
            return all(
                [
                    True
                    if (0 <= int(oct, 16) <= 65535) and (1 <= len(oct) <= 4)
                    else False
                    for oct in ip.split(":")
                ]
            )
        except Exception:
            log.debug("Validating IPv6 address - " + str(ip) + " failed")
            return False

    def validate_hex(self, hex):
        if hex is None or not isinstance(hex, (str, unicode)):
            return False
        try:
            int(hex, 16)
            return True
        except Exception:
            log.debug("Validating HEX value - " + str(hex) + " failed")
            return False

    def validate_integer(self, value, min, max, type_format=None):
        if value is None or not isinstance(value, int):
            return False
        if min is not None and value < min:
            return False
        if max is not None and value > max:
            return False
        if type_format is not None:
            if type_format == "uint32" and (value < 0 or value > 4294967295):
                return False
            elif type_format == "uint64" and (
                value < 0 or value > 18446744073709551615
            ):
                return False
            elif type_format == "int32" and (value < -2147483648 or value > 2147483647):
                return False
            elif type_format == "int64" and (
                value < -9223372036854775808 or value > 9223372036854775807
            ):
                return False
        return True

    def validate_float(self, value):
        return isinstance(value, (int, float))

    def validate_string(self, value, min_length, max_length, pattern):
        if value is None or not isinstance(value, (str, unicode)):
            return False
        if min_length is not None and len(value) < min_length:
            return False
        if max_length is not None and len(value) > max_length:
            return False
        if pattern is not None and not re.match(pattern, value):
            return False
        return True

    def validate_bool(self, value):
        return isinstance(value, bool)

    def validate_list(self, value, itemtype, min, max, min_length, max_length, pattern):
        if value is None or not isinstance(value, list):
            return False
        v_obj = getattr(self, "validate_{}".format(itemtype), None)
        if v_obj is None:
            raise AttributeError("{} is not a valid attribute".format(itemtype))
        v_obj_lst = []
        for item in value:
            if itemtype == "integer":
                v_obj_lst.append(v_obj(item, min, max))
            elif itemtype == "string":
                v_obj_lst.append(v_obj(item, min_length, max_length, pattern))
            else:
                v_obj_lst.append(v_obj(item))
        return v_obj_lst

    def validate_binary(self, value):
        if isinstance(value, bytes):
            return True

        if not isinstance(value, str):
            return False

        try:
            base64.b64decode(value, validate=True)
            return True
        except Exception:
            pass

        # Fallback: validate as a string of '0's and '1's
        if not value:  # An empty string is not a valid binary string in this context
            return False

        return all(char in "01" for char in value)

    def validate_oid(self, value):
        segments = value.split(".")
        if len(segments) < 2:
            return False
        for segment in segments:
            if not segment.isnumeric():
                return False
            if not (0 <= int(segment) <= 4294967295):
                return False
        return True

    def types_validation(
        self,
        value,
        type_,
        err_msg,
        itemtype=None,
        min=None,
        max=None,
        min_length=None,
        max_length=None,
        pattern=None,
    ):
        type_map = {
            int: "integer",
            str: "string",
            float: "float",
            bool: "bool",
            list: "list",
            "int64": "integer",
            "int32": "integer",
            "uint64": "integer",
            "uint32": "integer",
            "double": "float",
        }
        type_format = type_
        if type_ in type_map:
            type_ = type_map[type_]
        if itemtype is not None and itemtype in type_map:
            itemtype = type_map[itemtype]
        v_obj = getattr(self, "validate_{}".format(type_), None)
        if v_obj is None:
            msg = "{} is not a valid or unsupported format".format(type_)
            raise TypeError(msg)
        if type_ == "list":
            verdict = v_obj(value, itemtype, min, max, min_length, max_length, pattern)
            if all(verdict) is True:
                return
            err_msg = "{} \n {} are not valid".format(
                err_msg,
                [value[index] for index, item in enumerate(verdict) if item is False],
            )
            verdict = False
        elif type_ == "integer":
            verdict = v_obj(value, min, max, type_format)
            if verdict is True:
                return
            min_max = ""
            if min is not None:
                min_max = ", expected min {}".format(min)
            if max is not None:
                min_max = min_max + ", expected max {}".format(max)
            err_msg = "{} \n got {} of type {} {}".format(
                err_msg, value, type(value), min_max
            )
        elif type_ == "string":
            verdict = v_obj(value, min_length, max_length, pattern)
            if verdict is True:
                return
            msg = ""
            if min_length is not None:
                msg = ", expected min {}".format(min_length)
            if max_length is not None:
                msg = msg + ", expected max {}".format(max_length)
            if pattern is not None:
                msg = msg + ", expected pattern '{}'".format(pattern)
            err_msg = "{} \n got {} of type {} {}".format(
                err_msg, value, type(value), msg
            )
        else:
            verdict = v_obj(value)
        if verdict is False:
            raise TypeError(err_msg)

    def _validate_unique_and_name(self, name, value, latter=False):
        if self._TYPES[name].get("unique") is None or value is None:
            return
        if latter is True:
            self.__validate_latter__["unique"].append(
                (self._validate_unique_and_name, name, value)
            )
            return
        class_name = type(self).__name__
        unique_type = self._TYPES[name]["unique"]
        if class_name not in self.__constraints__:
            self.__constraints__[class_name] = dict()
        if unique_type == "global":
            values = self.__constraints__["global"]
        else:
            values = self.__constraints__[class_name]
        if value in values:
            self._validation_errors.append(
                "{} with {} already exists".format(name, value)
            )
            return
        if isinstance(values, list):
            values.append(value)
        self.__constraints__[class_name].update({value: self})

    def _validate_constraint(self, name, value, latter=False):
        cons = self._TYPES[name].get("constraint")
        if cons is None or value is None:
            return
        if latter is True:
            self.__validate_latter__["constraint"].append(
                (self._validate_constraint, name, value)
            )
            return
        found = False
        for c in cons:
            klass, prop = c.split(".")
            names = self.__constraints__.get(klass, {})
            props = [obj._properties.get(prop) for obj in names.values()]
            if value in props:
                found = True
                break
        if found is not True:
            self._validation_errors.append(
                "{} is not a valid type of {}".format(value, "||".join(cons))
            )
            return

    def _validate_coded(self):
        for item in self.__validate_latter__["unique"]:
            item[0](item[1], item[2])
        for item in self.__validate_latter__["constraint"]:
            item[0](item[1], item[2])
        self._clear_vars()
        if len(self._validation_errors) > 0:
            errors = "\n".join(self._validation_errors)
            self._clear_errors()
            raise Exception(errors)

    def _clear_vars(self):
        if platform.python_version_tuple()[0] == "2":
            self.__validate_latter__["unique"] = []
            self.__validate_latter__["constraint"] = []
        else:
            self.__validate_latter__["unique"].clear()
            self.__validate_latter__["constraint"].clear()

    def _clear_globals(self):
        keys = list(self.__constraints__.keys())
        for k in keys:
            if k == "global":
                self.__constraints__["global"] = []
                continue
            del self.__constraints__[k]


class OpenApiObject(OpenApiBase, OpenApiValidator):
    """Base class for any /components/schemas object

    Every OpenApiObject is reuseable within the schema so it can
    exist in multiple locations within the hierarchy.
    That means it can exist in multiple locations as a
    leaf, parent/choice or parent.
    """

    __slots__ = ("__warnings__", "_properties", "_parent", "_choice")
    _DEFAULTS = {}
    _TYPES = {}
    _REQUIRED = []
    _STATUS = {}

    def __init__(self, parent=None, choice=None):
        super(OpenApiObject, self).__init__()
        self._parent = parent
        self._choice = choice
        self._properties = {}
        self.__warnings__ = []

    @property
    def parent(self):
        return self._parent

    def _set_choice(self, name):
        if self._has_choice(name):
            for enum in self._TYPES["choice"]["enum"]:
                if enum in self._properties and name != enum:
                    self._properties.pop(enum)
            self._properties["choice"] = name

    def _has_choice(self, name):
        if (
            "choice" in dir(self)
            and "_TYPES" in dir(self)
            and "choice" in self._TYPES
            and name in self._TYPES["choice"]["enum"]
        ):
            return True
        else:
            return False

    def _get_property(self, name, default_value=None, parent=None, choice=None):
        if name in self._properties and self._properties[name] is not None:
            return self._properties[name]
        if isinstance(default_value, type) is True:
            self._set_choice(name)
            if "_choice" in default_value.__slots__:
                self._properties[name] = default_value(parent=parent, choice=choice)
            else:
                self._properties[name] = default_value(parent=parent)
            if (
                "_DEFAULTS" in dir(self._properties[name])
                and "choice" in self._properties[name]._DEFAULTS
            ):
                choice_str = self._properties[name]._DEFAULTS["choice"]

                if choice_str in self._properties[name]._TYPES:
                    getattr(
                        self._properties[name],
                        self._properties[name]._DEFAULTS["choice"],
                    )
        else:
            if default_value is None and name in self._DEFAULTS:
                self._set_choice(name)
                self._properties[name] = self._DEFAULTS[name]
            else:
                self._properties[name] = default_value
        return self._properties[name]

    def _set_property(self, name, value, choice=None):
        if name == "choice":

            if (
                self.parent is None
                and value is not None
                and value not in self._TYPES["choice"]["enum"]
            ):
                raise Exception(
                    "%s is not a valid choice, valid choices are %s"
                    % (value, ", ".join(self._TYPES["choice"]["enum"]))
                )

            self._set_choice(value)
            if name in self._DEFAULTS and value is None:
                self._properties[name] = self._DEFAULTS[name]
        elif name in self._DEFAULTS and value is None:
            self._set_choice(name)
            self._properties[name] = self._DEFAULTS[name]
        else:
            self._set_choice(name)
            self._properties[name] = value
        # TODO: restore behavior
        # self._validate_unique_and_name(name, value)
        # self._validate_constraint(name, value)
        if self._parent is not None and self._choice is not None and value is not None:
            self._parent._set_property("choice", self._choice)

    def _encode(self):
        """Helper method for serialization"""
        output = {}
        self._raise_status_warnings(self, None)
        self._validate_required()
        for key, value in self._properties.items():
            self._validate_types(key, value)
            # TODO: restore behavior
            # self._validate_unique_and_name(key, value, True)
            # self._validate_constraint(key, value, True)
            if isinstance(value, (OpenApiObject, OpenApiIter)):
                output[key] = value._encode()
                if isinstance(value, OpenApiObject):
                    self._raise_status_warnings(key, value)
            elif value is not None:
                if (
                    self._TYPES.get(key, {}).get("format", "") == "int64"
                    or self._TYPES.get(key, {}).get("format", "") == "uint64"
                ):
                    value = str(value)
                elif (
                    self._TYPES.get(key, {}).get("itemformat", "") == "int64"
                    or self._TYPES.get(key, {}).get("itemformat", "") == "uint64"
                ):
                    value = [str(v) for v in value]
                output[key] = value
                self._raise_status_warnings(key, value)
        return output

    def _decode(self, obj):
        dtypes = [list, str, int, float, bool]
        self._raise_status_warnings(self, None)
        for property_name, property_value in obj.items():
            if property_name in self._TYPES:
                ignore_warnings = False
                if isinstance(property_value, dict):
                    child = self._get_child_class(property_name)
                    if "choice" in child[1]._TYPES and "_parent" in child[1].__slots__:
                        property_value = child[1](self, property_name)._decode(
                            property_value
                        )
                    elif "_parent" in child[1].__slots__:
                        property_value = child[1](self)._decode(property_value)
                    else:
                        property_value = child[1]()._decode(property_value)
                elif (
                    isinstance(property_value, list)
                    and property_name in self._TYPES
                    and self._TYPES[property_name]["type"] not in dtypes
                ):
                    child = self._get_child_class(property_name, True)
                    openapi_list = child[0]()
                    for item in property_value:
                        item = child[1]()._decode(item)
                        openapi_list._items.append(item)
                    property_value = openapi_list
                    ignore_warnings = True
                elif property_name in self._DEFAULTS and property_value is None:
                    if isinstance(self._DEFAULTS[property_name], tuple(dtypes)):
                        property_value = self._DEFAULTS[property_name]
                self._set_choice(property_name)
                # convert int64(will be string on wire) to to int
                if (
                    self._TYPES[property_name].get("format", "") == "int64"
                    or self._TYPES[property_name].get("format", "") == "uint64"
                ):
                    property_value = int(property_value)
                elif (
                    self._TYPES[property_name].get("itemformat", "") == "int64"
                    or self._TYPES[property_name].get("itemformat", "") == "uint64"
                ):
                    property_value = [int(v) for v in property_value]
                self._properties[property_name] = property_value
                # TODO: restore behavior
                # OpenApiStatus.warn(
                #     "{}.{}".format(type(self).__name__, property_name), self
                # )
                if not ignore_warnings:
                    self._raise_status_warnings(property_name, property_value)
            self._validate_types(property_name, property_value)
            # TODO: restore behavior
            # self._validate_unique_and_name(property_name, property_value, True)
            # self._validate_constraint(property_name, property_value, True)
        self._validate_required()
        return self

    def _get_child_class(self, property_name, is_property_list=False):
        list_class = None
        class_name = self._TYPES[property_name]["type"]
        module = globals().get(self.__module__)
        if module is None:
            module = importlib.import_module(self.__module__)
            globals()[self.__module__] = module
        object_class = getattr(module, class_name)
        if is_property_list is True:
            list_class = object_class
            object_class = getattr(module, class_name[0:-4])
        return (list_class, object_class)

    def __str__(self):
        return self.serialize(encoding=self.YAML)

    def __deepcopy__(self, memo):
        """Creates a deep copy of the current object"""
        return self.__class__().deserialize(self.serialize())

    def __copy__(self):
        """Creates a deep copy of the current object"""
        return self.__deepcopy__(None)

    def __eq__(self, other):
        return self.__str__() == other.__str__()

    def clone(self):
        """Creates a deep copy of the current object"""
        return self.__deepcopy__(None)

    def _validate_required(self):
        """Validates the required properties are set
        Use getattr as it will set any defaults prior to validating
        """
        if getattr(self, "_REQUIRED", None) is None:
            return
        for name in self._REQUIRED:
            if self._properties.get(name) is None:
                msg = (
                    "{} is a mandatory property of {}"
                    " and should not be set to None".format(
                        name,
                        self.__class__,
                    )
                )
                raise ValueError(msg)

    def _validate_types(self, property_name, property_value):
        common_data_types = [list, str, int, float, bool]
        if property_name not in self._TYPES:
            # raise ValueError("Invalid Property {}".format(property_name))
            return
        details = self._TYPES[property_name]
        if (
            property_value is None
            and property_name not in self._DEFAULTS
            and property_name not in self._REQUIRED
        ):
            return
        if "enum" in details and property_value not in details["enum"]:
            raise_error = False
            if isinstance(property_value, list):
                for value in property_value:
                    if value not in details["enum"]:
                        raise_error = True
                        break
            elif property_value not in details["enum"]:
                raise_error = True

            if raise_error is True:
                msg = "property {} shall be one of these" " {} enum, but got {} at {}"
                raise TypeError(
                    msg.format(
                        property_name,
                        details["enum"],
                        property_value,
                        self.__class__,
                    )
                )
        if details["type"] in common_data_types and "format" not in details:
            msg = "property {} shall be of type {} at {}".format(
                property_name, details["type"], self.__class__
            )

            itemtype = (
                details.get("itemformat")
                if "itemformat" in details
                else details.get("itemtype")
            )
            self.types_validation(
                property_value,
                details["type"],
                msg,
                itemtype,
                details.get("minimum"),
                details.get("maximum"),
                details.get("minLength"),
                details.get("maxLength"),
                details.get("pattern"),
            )

        if details["type"] not in common_data_types:
            class_name = details["type"]
            # TODO Need to revisit importlib
            module = importlib.import_module(self.__module__)
            object_class = getattr(module, class_name)
            if not isinstance(property_value, object_class):
                msg = "property {} shall be of type {}," " but got {} at {}"
                raise TypeError(
                    msg.format(
                        property_name,
                        class_name,
                        type(property_value),
                        self.__class__,
                    )
                )
        if "format" in details:
            msg = "Invalid {} format, expected {} at {}".format(
                property_value, details["format"], self.__class__
            )
            _type = details["type"] if details["type"] is list else details["format"]
            self.types_validation(
                property_value,
                _type,
                msg,
                details["format"],
                details.get("minimum"),
                details.get("maximum"),
                details.get("minLength"),
                details.get("maxLength"),
                details.get("pattern"),
            )

    def validate(self):
        self._validate_required()
        for key, value in self._properties.items():
            self._validate_types(key, value)
        # TODO: restore behavior
        # self._validate_coded()

    def get(self, name, with_default=False):
        """
        getattr for openapi object
        """
        if self._properties.get(name) is not None:
            return self._properties[name]
        elif with_default:
            # TODO need to find a way to avoid getattr
            choice = self._properties.get("choice") if "choice" in dir(self) else None
            getattr(self, name)
            if "choice" in dir(self):
                if choice is None and "choice" in self._properties:
                    self._properties.pop("choice")
                else:
                    self._properties["choice"] = choice
            return self._properties.pop(name)
        return None

    def _raise_status_warnings(self, property_name, property_value):
        if len(self._STATUS) > 0:

            if isinstance(property_name, OpenApiObject):
                if "self" in self._STATUS and property_value is None:
                    print("[WARNING]: %s" % self._STATUS["self"], file=sys.stderr)

                return

            enum_key = "%s.%s" % (property_name, property_value)
            if property_name in self._STATUS:
                print(
                    "[WARNING]: %s" % self._STATUS[property_name],
                    file=sys.stderr,
                )
            elif enum_key in self._STATUS:
                print("[WARNING]: %s" % self._STATUS[enum_key], file=sys.stderr)


class OpenApiIter(OpenApiBase):
    """Container class for OpenApiObject

    Inheriting classes contain 0..n instances of an OpenAPI components/schemas
    object.
    - config.flows.flow(name="1").flow(name="2").flow(name="3")

    The __getitem__ method allows getting an instance using ordinal.
    - config.flows[0]
    - config.flows[1:]
    - config.flows[0:1]
    - f1, f2, f3 = config.flows

    The __iter__ method allows for iterating across the encapsulated contents
    - for flow in config.flows:
    """

    __slots__ = ("_index", "_items")
    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self):
        super(OpenApiIter, self).__init__()
        self._index = -1
        self._items = []

    def __len__(self):
        return len(self._items)

    def _getitem(self, key):
        found = None
        if isinstance(key, int):
            found = self._items[key]
        elif isinstance(key, slice) is True:
            start, stop, step = key.indices(len(self))
            sliced = self.__class__()
            for i in range(start, stop, step):
                sliced._items.append(self._items[i])
            return sliced
        elif isinstance(key, str):
            for item in self._items:
                if item.name == key:
                    found = item
        if found is None:
            raise IndexError()
        if (
            self._GETITEM_RETURNS_CHOICE_OBJECT is True
            and found._properties.get("choice") is not None
            and found._properties.get(found._properties["choice"]) is not None
        ):
            return found._properties[found._properties["choice"]]
        return found

    def _iter(self):
        self._index = -1
        return self

    def _next(self):
        if self._index + 1 >= len(self._items):
            raise StopIteration
        else:
            self._index += 1
        return self.__getitem__(self._index)

    def __getitem__(self, key):
        raise NotImplementedError("This should be overridden by the generator")

    def _add(self, item):
        self._items.append(item)
        self._index = len(self._items) - 1

    def remove(self, index):
        del self._items[index]
        self._index = len(self._items) - 1

    def append(self, item):
        """Append an item to the end of OpenApiIter
        TBD: type check, raise error on mismatch
        """
        self._instanceOf(item)
        self._add(item)
        return self

    def clear(self):
        del self._items[:]
        self._index = -1

    def set(self, index, item):
        self._instanceOf(item)
        self._items[index] = item
        return self

    def _encode(self):
        return [item._encode() for item in self._items]

    def _decode(self, encoded_list):
        item_class_name = self.__class__.__name__.replace("Iter", "")
        module = importlib.import_module(self.__module__)
        object_class = getattr(module, item_class_name)
        self.clear()
        for item in encoded_list:
            self._add(object_class()._decode(item))

    def __copy__(self):
        raise NotImplementedError(
            "Shallow copy of OpenApiIter objects is not supported"
        )

    def __deepcopy__(self, memo):
        raise NotImplementedError("Deep copy of OpenApiIter objects is not supported")

    def __str__(self):
        return yaml.safe_dump(self._encode())

    def __eq__(self, other):
        return self.__str__() == other.__str__()

    def _instanceOf(self, item):
        raise NotImplementedError("validating an OpenApiIter object is not supported")


class Telemetry(object):
    def __init__(self, endpoint, transport):
        self.transport = transport
        self.endpoint = endpoint
        self.is_telemetry_enabled = False
        self._tracer = None
        self._trace_provider = None
        self._resource = None
        self._batch_span_processor = None
        self._trace = None
        self._http_exporter = None
        self._grpc_exporter = None
        self._http_instrumentor = None
        self._grpc_instrumentor = None
        self._spankind = None
        if self.endpoint is not None:
            self.is_telemetry_enabled = True
            self._initiate_tracer()

    def _initiate_tracer(self):
        import warnings

        warnings.filterwarnings("ignore", category=DeprecationWarning)
        self._trace = importlib.import_module("opentelemetry.trace")
        self._spankind = getattr(self._trace, "SpanKind")
        self._trace_provider = importlib.import_module("opentelemetry.sdk.trace")
        self._trace_provider = getattr(self._trace_provider, "TracerProvider")
        self._resource = importlib.import_module("opentelemetry.sdk.resources")
        self._resource = getattr(self._resource, "Resource")
        self._batch_span_processor = importlib.import_module(
            "opentelemetry.sdk.trace.export"
        )
        self._batch_span_processor = getattr(
            self._batch_span_processor, "BatchSpanProcessor"
        )
        self._grpc_exporter = importlib.import_module(
            "opentelemetry.exporter.otlp.proto.grpc.trace_exporter"
        )
        self._grpc_exporter = getattr(self._grpc_exporter, "OTLPSpanExporter")
        self._http_exporter = importlib.import_module(
            "opentelemetry.exporter.otlp.proto.http.trace_exporter"
        )
        self._http_exporter = getattr(self._http_exporter, "OTLPSpanExporter")

        provider = self._trace_provider(
            resource=self._resource.create({"service.name": "snappi"})
        )
        self._trace.set_tracer_provider(provider)
        if self.transport == "http":
            otlp_exporter = self._http_exporter(endpoint=self.endpoint)
        else:
            otlp_exporter = self._grpc_exporter(endpoint=self.endpoint, insecure=True)
        span_processor = self._batch_span_processor(otlp_exporter)
        provider.add_span_processor(span_processor)
        tracer = self._trace.get_tracer(__name__)
        self._tracer = tracer

    def initiate_http_instrumentation(self):
        if self.is_telemetry_enabled:
            from opentelemetry.instrumentation.requests import (
                RequestsInstrumentor,
            )

            RequestsInstrumentor().instrument()

    def initiate_grpc_instrumentation(self):
        if self.is_telemetry_enabled:
            from opentelemetry.instrumentation.grpc import (
                GrpcInstrumentorClient,
            )

            GrpcInstrumentorClient().instrument()

    def set_span_event(self, message):
        if self.is_telemetry_enabled:
            current_span = self._trace.get_current_span()
            current_span.add_event(message)

    @staticmethod
    def create_child_span(func):
        def tracing(self, *args, **kwargs):
            telemetry = self._telemetry
            if telemetry.is_telemetry_enabled:
                name = func.__name__
                with self.tracer().start_as_current_span(
                    name, kind=telemetry._spankind.CLIENT
                ):
                    return func(self, *args, **kwargs)
            else:
                return func(self, *args, **kwargs)

        return tracing


class ServerResponse(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "message": {"type": str},
        "warnings": {
            "type": list,
            "itemtype": str,
        },
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, message=None, warnings=None):
        super(ServerResponse, self).__init__()
        self._parent = parent
        self._set_property("message", message)
        self._set_property("warnings", warnings)

    def set(self, message=None, warnings=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def message(self):
        # type: () -> str
        """message getter

        Server Response Message

        Returns: str
        """
        return self._get_property("message")

    @message.setter
    def message(self, value):
        """message setter

        Server Response Message

        value: str
        """
        self._set_property("message", value)

    @property
    def warnings(self):
        # type: () -> List[str]
        """warnings getter

        A list of any system specific warnings that have occurred while executing the request.

        Returns: List[str]
        """
        return self._get_property("warnings")

    @warnings.setter
    def warnings(self, value):
        """warnings setter

        A list of any system specific warnings that have occurred while executing the request.

        value: List[str]
        """
        self._set_property("warnings", value)


class Error(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "code": {
            "type": int,
            "format": "int32",
        },
        "kind": {
            "type": str,
            "enum": [
                "validation",
                "internal",
            ],
        },
        "errors": {
            "type": list,
            "itemtype": str,
        },
    }  # type: Dict[str, str]

    _REQUIRED = ("code", "errors")  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    VALIDATION = "validation"  # type: str
    INTERNAL = "internal"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, code=None, kind=None, errors=None):
        super(Error, self).__init__()
        self._parent = parent
        self._set_property("code", code)
        self._set_property("kind", kind)
        self._set_property("errors", errors)

    def set(self, code=None, kind=None, errors=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def code(self):
        # type: () -> int
        """code getter

        Numeric status code based on the underlying transport being used.. The API server MUST set this code explicitly based on following references:. HTTP 4xx errors: https://datatracker.ietf.org/doc/html/rfc9110#section-15.5. HTTP 5xx errors: https://datatracker.ietf.org/doc/html/rfc9110#section-15.6. gRPC errors: https://grpc.github.io/grpc/core/md_doc_statuscodes.html

        Returns: int
        """
        return self._get_property("code")

    @code.setter
    def code(self, value):
        """code setter

        Numeric status code based on the underlying transport being used.. The API server MUST set this code explicitly based on following references:. HTTP 4xx errors: https://datatracker.ietf.org/doc/html/rfc9110#section-15.5. HTTP 5xx errors: https://datatracker.ietf.org/doc/html/rfc9110#section-15.6. gRPC errors: https://grpc.github.io/grpc/core/md_doc_statuscodes.html

        value: int
        """
        if value is None:
            raise TypeError("Cannot set required property code as None")
        self._set_property("code", value)

    @property
    def kind(self):
        # type: () -> Union[Literal["internal"], Literal["validation"]]
        """kind getter

        Classification of error originating from within API server that may not be mapped to the value in `code`.. Absence of this field may indicate that the error did not originate from within API server.

        Returns: Union[Literal["internal"], Literal["validation"]]
        """
        return self._get_property("kind")

    @kind.setter
    def kind(self, value):
        """kind setter

        Classification of error originating from within API server that may not be mapped to the value in `code`.. Absence of this field may indicate that the error did not originate from within API server.

        value: Union[Literal["internal"], Literal["validation"]]
        """
        self._set_property("kind", value)

    @property
    def errors(self):
        # type: () -> List[str]
        """errors getter

        List of error messages generated while executing the request.

        Returns: List[str]
        """
        return self._get_property("errors")

    @errors.setter
    def errors(self, value):
        """errors setter

        List of error messages generated while executing the request.

        value: List[str]
        """
        if value is None:
            raise TypeError("Cannot set required property errors as None")
        self._set_property("errors", value)


class Config(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "common_config": {"type": "CommonConfiguration"},
        "network_backend": {"type": "NetworkBackend"},
        "infragraph": {"type": "Infragraph"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(Config, self).__init__()
        self._parent = parent

    @property
    def common_config(self):
        # type: () -> CommonConfiguration
        """common_config getter

        Holds the schemas that define ASTRA-sim configurations common to all backends, including workload, system, communicator group, logging, remote memory, and command parameters.Holds the schemas that define ASTRA-sim configurations common to all backends, including workload, system, communicator group, logging, remote memory, and command parameters.Holds the schemas that define ASTRA-sim configurations common to all backends, including workload, system, communicator group, logging, remote memory, and command parameters.

        Returns: CommonConfiguration
        """
        return self._get_property("common_config", CommonConfiguration)

    @property
    def network_backend(self):
        # type: () -> NetworkBackend
        """network_backend getter

        A choice of network backends of ASTRA-sim which will run the simulation.A choice of network backends of ASTRA-sim which will run the simulation.A choice of network backends of ASTRA-sim which will run the simulation.

        Returns: NetworkBackend
        """
        return self._get_property("network_backend", NetworkBackend)

    @property
    def infragraph(self):
        # type: () -> Infragraph
        """infragraph getter

        InfraGraph or infrastructure graph defines model-driven, vendor-neutral, standard interface for capturing system of systems suitable for use in co-designing AI/HPC solutions.. This model allows for defining physical infrastructure as logical system of systems using graph like terminology. In addition to defining logical graph, an unlimited number of different physical characteristics can be associated with logical endpoints.. InfraGraph or infrastructure graph defines model-driven, vendor-neutral, standard interface for capturing system of systems suitable for use in co-designing AI/HPC solutions.. This model allows for defining physical infrastructure as logical system of systems using graph like terminology. In addition to defining logical graph, an unlimited number of different physical characteristics can be associated with logical endpoints.. InfraGraph or infrastructure graph defines model-driven, vendor-neutral, standard interface for capturing system of systems suitable for use in co-designing AI/HPC solutions.. This model allows for defining physical infrastructure as logical system of systems using graph like terminology. In addition to defining logical graph, an unlimited number of different physical characteristics can be associated with logical endpoints..

        Returns: Infragraph
        """
        return self._get_property("infragraph", Infragraph)


class CommonConfiguration(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "workload": {"type": str},
        "system": {"type": "SystemConfiguration"},
        "communicator_group": {"type": "CommunicatorGroupIter"},
        "remote_memory": {"type": "RemoteMemory"},
        "logging": {"type": "SpdlogConfig"},
        "cmd_parameters": {"type": "CommandArguments"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, workload=None):
        super(CommonConfiguration, self).__init__()
        self._parent = parent
        self._set_property("workload", workload)

    def set(self, workload=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def workload(self):
        # type: () -> str
        """workload getter

        Specifies the path containing workload configuration data as part of the uploaded .zip package. This field holds the folder/filename (excluding the `.rankid.et` suffix).

        Returns: str
        """
        return self._get_property("workload")

    @workload.setter
    def workload(self, value):
        """workload setter

        Specifies the path containing workload configuration data as part of the uploaded .zip package. This field holds the folder/filename (excluding the `.rankid.et` suffix).

        value: str
        """
        self._set_property("workload", value)

    @property
    def system(self):
        # type: () -> SystemConfiguration
        """system getter

        Defines ASTRA-sim core system configuration parameters used to control simulation behavior. This includes scheduling policies, collective communication algorithms, key performance metrics, and advanced features like roofline modeling and execution tracing. Users can specify these settings directly via structured schema for precise and flexible simulation setup.Defines ASTRA-sim core system configuration parameters used to control simulation behavior. This includes scheduling policies, collective communication algorithms, key performance metrics, and advanced features like roofline modeling and execution tracing. Users can specify these settings directly via structured schema for precise and flexible simulation setup.Defines ASTRA-sim core system configuration parameters used to control simulation behavior. This includes scheduling policies, collective communication algorithms, key performance metrics, and advanced features like roofline modeling and execution tracing. Users can specify these settings directly via structured schema for precise and flexible simulation setup.Holds the ASTRA-sim system configuration schema, allowing users to generate system configurations based on the schema.

        Returns: SystemConfiguration
        """
        return self._get_property("system", SystemConfiguration)

    @property
    def communicator_group(self):
        # type: () -> CommunicatorGroupIter
        """communicator_group getter

        Holds the ASTRA-sim communicator group configuration schema, allowing users to generate communicator group configurations based on the schema.

        Returns: CommunicatorGroupIter
        """
        return self._get_property(
            "communicator_group", CommunicatorGroupIter, self._parent, self._choice
        )

    @property
    def remote_memory(self):
        # type: () -> RemoteMemory
        """remote_memory getter

        Defines the remote memory configuration parameters for ASTRA-sim, enabling direct specification of memory subsystem settings via structured schema. This includes memory access patterns, latency, and bandwidth characteristics that influence how tensor loads, stores, and other memory operations are simulated. Users can utilize this schema to create detailed remote memory configurations for accurate and flexible workload modeling.Defines the remote memory configuration parameters for ASTRA-sim, enabling direct specification of memory subsystem settings via structured schema. This includes memory access patterns, latency, and bandwidth characteristics that influence how tensor loads, stores, and other memory operations are simulated. Users can utilize this schema to create detailed remote memory configurations for accurate and flexible workload modeling.Defines the remote memory configuration parameters for ASTRA-sim, enabling direct specification of memory subsystem settings via structured schema. This includes memory access patterns, latency, and bandwidth characteristics that influence how tensor loads, stores, and other memory operations are simulated. Users can utilize this schema to create detailed remote memory configurations for accurate and flexible workload modeling.Holds the ASTRA-sim remote memory configuration schema, allowing users to define and create remote memory configurations.

        Returns: RemoteMemory
        """
        return self._get_property("remote_memory", RemoteMemory)

    @property
    def logging(self):
        # type: () -> SpdlogConfig
        """logging getter

        Defines the overall logging configuration used to generate TOML-based spdlog configuration file. It specifies log sinks (output targets) and loggers (named logging instances with levels and patterns).Defines the overall logging configuration used to generate TOML-based spdlog configuration file. It specifies log sinks (output targets) and loggers (named logging instances with levels and patterns).Defines the overall logging configuration used to generate TOML-based spdlog configuration file. It specifies log sinks (output targets) and loggers (named logging instances with levels and patterns).Holds the logging configuration schema, allowing users to generate TOML-based spdlog configuration file.

        Returns: SpdlogConfig
        """
        return self._get_property("logging", SpdlogConfig)

    @property
    def cmd_parameters(self):
        # type: () -> CommandArguments
        """cmd_parameters getter

        Command Line Arguments that are common to the ASTRA-sim binary.Command Line Arguments that are common to the ASTRA-sim binary.Command Line Arguments that are common to the ASTRA-sim binary.Contains the command parameters schema, allowing users to define and set command line argument values.

        Returns: CommandArguments
        """
        return self._get_property("cmd_parameters", CommandArguments)


class SystemConfiguration(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "scheduling_policy": {
            "type": str,
            "enum": [
                "LIFO",
                "FIFO",
                "EXPLICIT",
            ],
        },
        "all_reduce_implementation": {
            "type": list,
            "enum": [
                "ring",
                "oneRing",
                "doubleBinaryTree",
                "direct",
                "oneDirect",
            ],
            "itemtype": str,
        },
        "reduce_scatter_implementation": {
            "type": list,
            "enum": [
                "ring",
                "oneRing",
                "direct",
                "oneDirect",
            ],
            "itemtype": str,
        },
        "all_gather_implementation": {
            "type": list,
            "enum": [
                "ring",
                "oneRing",
                "direct",
                "oneDirect",
            ],
            "itemtype": str,
        },
        "all_to_all_implementation": {
            "type": list,
            "enum": [
                "ring",
                "oneRing",
                "direct",
                "oneDirect",
            ],
            "itemtype": str,
        },
        "all_to_all_implementation_custom": {
            "type": list,
            "itemtype": str,
        },
        "all_gather_implementation_custom": {
            "type": list,
            "itemtype": str,
        },
        "all_reduce_implementation_custom": {
            "type": list,
            "itemtype": str,
        },
        "collective_optimization": {
            "type": str,
            "enum": [
                "baseline",
                "localBWAware",
            ],
        },
        "local_reduction_delay": {
            "type": int,
            "format": "int32",
        },
        "active_chunks_per_dimension": {
            "type": int,
            "format": "int32",
        },
        "latency": {
            "type": float,
            "format": "float",
        },
        "overhead": {
            "type": float,
            "format": "float",
        },
        "gap": {
            "type": float,
            "format": "float",
        },
        "global_memory": {
            "type": float,
            "format": "float",
        },
        "endpoint_delay": {
            "type": int,
            "format": "int32",
        },
        "model_shared_bus": {
            "type": int,
            "format": "int32",
        },
        "preferred_dataset_splits": {
            "type": int,
            "format": "int32",
            "minimum": 0,
        },
        "peak_perf": {
            "type": float,
            "format": "double",
            "minimum": 0,
        },
        "local_mem_bw": {
            "type": float,
            "format": "double",
            "minimum": 0,
        },
        "roofline_enabled": {
            "type": int,
            "format": "int32",
            "minimum": 0,
        },
        "trace_enabled": {
            "type": int,
            "format": "int32",
            "minimum": 0,
        },
        "replay_only": {
            "type": int,
            "format": "int32",
            "minimum": 0,
        },
        "track_local_mem": {
            "type": int,
            "format": "int32",
            "minimum": 0,
        },
        "local_mem_trace_filename": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {
        "scheduling_policy": "LIFO",
        "all_reduce_implementation": ["ring"],
        "reduce_scatter_implementation": ["ring"],
        "all_gather_implementation": ["ring"],
        "all_to_all_implementation": ["ring"],
        "collective_optimization": "localBWAware",
        "local_reduction_delay": 0,
        "active_chunks_per_dimension": 1,
        "endpoint_delay": 0,
        "preferred_dataset_splits": 1,
        "local_mem_bw": 50.0,
        "trace_enabled": 0,
    }  # type: Dict[str, Union(type)]

    LIFO = "LIFO"  # type: str
    FIFO = "FIFO"  # type: str
    EXPLICIT = "EXPLICIT"  # type: str

    RING = "ring"  # type: str
    ONERING = "oneRing"  # type: str
    DOUBLEBINARYTREE = "doubleBinaryTree"  # type: str
    DIRECT = "direct"  # type: str
    ONEDIRECT = "oneDirect"  # type: str

    RING = "ring"  # type: str
    ONERING = "oneRing"  # type: str
    DIRECT = "direct"  # type: str
    ONEDIRECT = "oneDirect"  # type: str

    RING = "ring"  # type: str
    ONERING = "oneRing"  # type: str
    DIRECT = "direct"  # type: str
    ONEDIRECT = "oneDirect"  # type: str

    RING = "ring"  # type: str
    ONERING = "oneRing"  # type: str
    DIRECT = "direct"  # type: str
    ONEDIRECT = "oneDirect"  # type: str

    BASELINE = "baseline"  # type: str
    LOCALBWAWARE = "localBWAware"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self,
        parent=None,
        scheduling_policy="LIFO",
        all_reduce_implementation=["ring"],
        reduce_scatter_implementation=["ring"],
        all_gather_implementation=["ring"],
        all_to_all_implementation=["ring"],
        all_to_all_implementation_custom=None,
        all_gather_implementation_custom=None,
        all_reduce_implementation_custom=None,
        collective_optimization="localBWAware",
        local_reduction_delay=0,
        active_chunks_per_dimension=1,
        latency=None,
        overhead=None,
        gap=None,
        global_memory=None,
        endpoint_delay=0,
        model_shared_bus=None,
        preferred_dataset_splits=1,
        peak_perf=None,
        local_mem_bw=50,
        roofline_enabled=None,
        trace_enabled=0,
        replay_only=None,
        track_local_mem=None,
        local_mem_trace_filename=None,
    ):
        super(SystemConfiguration, self).__init__()
        self._parent = parent
        self._set_property("scheduling_policy", scheduling_policy)
        self._set_property("all_reduce_implementation", all_reduce_implementation)
        self._set_property(
            "reduce_scatter_implementation", reduce_scatter_implementation
        )
        self._set_property("all_gather_implementation", all_gather_implementation)
        self._set_property("all_to_all_implementation", all_to_all_implementation)
        self._set_property(
            "all_to_all_implementation_custom", all_to_all_implementation_custom
        )
        self._set_property(
            "all_gather_implementation_custom", all_gather_implementation_custom
        )
        self._set_property(
            "all_reduce_implementation_custom", all_reduce_implementation_custom
        )
        self._set_property("collective_optimization", collective_optimization)
        self._set_property("local_reduction_delay", local_reduction_delay)
        self._set_property("active_chunks_per_dimension", active_chunks_per_dimension)
        self._set_property("latency", latency)
        self._set_property("overhead", overhead)
        self._set_property("gap", gap)
        self._set_property("global_memory", global_memory)
        self._set_property("endpoint_delay", endpoint_delay)
        self._set_property("model_shared_bus", model_shared_bus)
        self._set_property("preferred_dataset_splits", preferred_dataset_splits)
        self._set_property("peak_perf", peak_perf)
        self._set_property("local_mem_bw", local_mem_bw)
        self._set_property("roofline_enabled", roofline_enabled)
        self._set_property("trace_enabled", trace_enabled)
        self._set_property("replay_only", replay_only)
        self._set_property("track_local_mem", track_local_mem)
        self._set_property("local_mem_trace_filename", local_mem_trace_filename)

    def set(
        self,
        scheduling_policy=None,
        all_reduce_implementation=None,
        reduce_scatter_implementation=None,
        all_gather_implementation=None,
        all_to_all_implementation=None,
        all_to_all_implementation_custom=None,
        all_gather_implementation_custom=None,
        all_reduce_implementation_custom=None,
        collective_optimization=None,
        local_reduction_delay=None,
        active_chunks_per_dimension=None,
        latency=None,
        overhead=None,
        gap=None,
        global_memory=None,
        endpoint_delay=None,
        model_shared_bus=None,
        preferred_dataset_splits=None,
        peak_perf=None,
        local_mem_bw=None,
        roofline_enabled=None,
        trace_enabled=None,
        replay_only=None,
        track_local_mem=None,
        local_mem_trace_filename=None,
    ):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def scheduling_policy(self):
        # type: () -> Union[Literal["EXPLICIT"], Literal["FIFO"], Literal["LIFO"]]
        """scheduling_policy getter

        The order we proritize collectives according based on their time of arrival. LIFO means that most recently created collectives have higher priority. While FIFO is the reverse.

        Returns: Union[Literal["EXPLICIT"], Literal["FIFO"], Literal["LIFO"]]
        """
        return self._get_property("scheduling_policy")

    @scheduling_policy.setter
    def scheduling_policy(self, value):
        """scheduling_policy setter

        The order we proritize collectives according based on their time of arrival. LIFO means that most recently created collectives have higher priority. While FIFO is the reverse.

        value: Union[Literal["EXPLICIT"], Literal["FIFO"], Literal["LIFO"]]
        """
        self._set_property("scheduling_policy", value)

    @property
    def all_reduce_implementation(self):
        # type: () -> List[Union[Literal["direct"], Literal["doubleBinaryTree"], Literal["oneDirect"], Literal["oneRing"], Literal["ring"]]]
        """all_reduce_implementation getter

        (Dimension0Collective_Dimension1Collective_xxx_DimensionNCollective). Here we can create multiphase colective all-reduce algorithm and directly specify the collective algorithm type for each logical dimension. The available options (algorithms) are: ring, direct, doubleBinaryTree, oneRing, oneDirect.. For example, “ring_doubleBinaryTree” means we create logical topology with dimensions and we perform ring algorithm on the first dimension followed by double binary tree on the second dimension for the all-reduce pattern. Hence the number of physical dimension should be equal to the number of logical dimensions. The only exceptions are oneRing/oneDirect where we assume no matter how many physical dimensions we have, we create one big logical ring/direct(AllToAll) topology where all NPUs are connected and perfrom one phase ring/direct algorithm.

        Returns: List[Union[Literal["direct"], Literal["doubleBinaryTree"], Literal["oneDirect"], Literal["oneRing"], Literal["ring"]]]
        """
        return self._get_property("all_reduce_implementation")

    @all_reduce_implementation.setter
    def all_reduce_implementation(self, value):
        """all_reduce_implementation setter

        (Dimension0Collective_Dimension1Collective_xxx_DimensionNCollective). Here we can create multiphase colective all-reduce algorithm and directly specify the collective algorithm type for each logical dimension. The available options (algorithms) are: ring, direct, doubleBinaryTree, oneRing, oneDirect.. For example, “ring_doubleBinaryTree” means we create logical topology with dimensions and we perform ring algorithm on the first dimension followed by double binary tree on the second dimension for the all-reduce pattern. Hence the number of physical dimension should be equal to the number of logical dimensions. The only exceptions are oneRing/oneDirect where we assume no matter how many physical dimensions we have, we create one big logical ring/direct(AllToAll) topology where all NPUs are connected and perfrom one phase ring/direct algorithm.

        value: List[Union[Literal["direct"], Literal["doubleBinaryTree"], Literal["oneDirect"], Literal["oneRing"], Literal["ring"]]]
        """
        self._set_property("all_reduce_implementation", value)

    @property
    def reduce_scatter_implementation(self):
        # type: () -> List[Union[Literal["direct"], Literal["oneDirect"], Literal["oneRing"], Literal["ring"]]]
        """reduce_scatter_implementation getter

        (Dimension0CollectiveAlg_Dimension1CollectiveAlg_xxx_DimensionNCollectiveAlg). The same as all-reduce-implementation but for reduce-scatter collective. The available options are: ring, direct, oneRing, oneDirect.

        Returns: List[Union[Literal["direct"], Literal["oneDirect"], Literal["oneRing"], Literal["ring"]]]
        """
        return self._get_property("reduce_scatter_implementation")

    @reduce_scatter_implementation.setter
    def reduce_scatter_implementation(self, value):
        """reduce_scatter_implementation setter

        (Dimension0CollectiveAlg_Dimension1CollectiveAlg_xxx_DimensionNCollectiveAlg). The same as all-reduce-implementation but for reduce-scatter collective. The available options are: ring, direct, oneRing, oneDirect.

        value: List[Union[Literal["direct"], Literal["oneDirect"], Literal["oneRing"], Literal["ring"]]]
        """
        self._set_property("reduce_scatter_implementation", value)

    @property
    def all_gather_implementation(self):
        # type: () -> List[Union[Literal["direct"], Literal["oneDirect"], Literal["oneRing"], Literal["ring"]]]
        """all_gather_implementation getter

        (Dimension0CollectiveAlg_Dimension1CollectiveAlg_xxx_DimensionNCollectiveAlg). The same as all-reduce-implementation but for all-gather collective. The available options (algorithms) are: ring, direct, oneRing, oneDirect.

        Returns: List[Union[Literal["direct"], Literal["oneDirect"], Literal["oneRing"], Literal["ring"]]]
        """
        return self._get_property("all_gather_implementation")

    @all_gather_implementation.setter
    def all_gather_implementation(self, value):
        """all_gather_implementation setter

        (Dimension0CollectiveAlg_Dimension1CollectiveAlg_xxx_DimensionNCollectiveAlg). The same as all-reduce-implementation but for all-gather collective. The available options (algorithms) are: ring, direct, oneRing, oneDirect.

        value: List[Union[Literal["direct"], Literal["oneDirect"], Literal["oneRing"], Literal["ring"]]]
        """
        self._set_property("all_gather_implementation", value)

    @property
    def all_to_all_implementation(self):
        # type: () -> List[Union[Literal["direct"], Literal["oneDirect"], Literal["oneRing"], Literal["ring"]]]
        """all_to_all_implementation getter

        (Dimension0CollectiveAlg_Dimension1CollectiveAlg_xxx_DimensionNCollectiveAlg). The same as all-reduce-implementation but for all-to-all collective. The available options (algorithms) are: ring, direct, oneRing, oneDirect.

        Returns: List[Union[Literal["direct"], Literal["oneDirect"], Literal["oneRing"], Literal["ring"]]]
        """
        return self._get_property("all_to_all_implementation")

    @all_to_all_implementation.setter
    def all_to_all_implementation(self, value):
        """all_to_all_implementation setter

        (Dimension0CollectiveAlg_Dimension1CollectiveAlg_xxx_DimensionNCollectiveAlg). The same as all-reduce-implementation but for all-to-all collective. The available options (algorithms) are: ring, direct, oneRing, oneDirect.

        value: List[Union[Literal["direct"], Literal["oneDirect"], Literal["oneRing"], Literal["ring"]]]
        """
        self._set_property("all_to_all_implementation", value)

    @property
    def all_to_all_implementation_custom(self):
        # type: () -> List[str]
        """all_to_all_implementation_custom getter

        This parameter specifies Chakra Execution Trace (ET) file path for implementing AllToAll collective operations, requiring exactly one ET file that covers all dimensions in multi-dimensional collectives.

        Returns: List[str]
        """
        return self._get_property("all_to_all_implementation_custom")

    @all_to_all_implementation_custom.setter
    def all_to_all_implementation_custom(self, value):
        """all_to_all_implementation_custom setter

        This parameter specifies Chakra Execution Trace (ET) file path for implementing AllToAll collective operations, requiring exactly one ET file that covers all dimensions in multi-dimensional collectives.

        value: List[str]
        """
        self._set_property("all_to_all_implementation_custom", value)

    @property
    def all_gather_implementation_custom(self):
        # type: () -> List[str]
        """all_gather_implementation_custom getter

        This parameter defines Chakra ET file path for AllGather collective operations, following the same single-file requirement for multi-dimensional scenarios.

        Returns: List[str]
        """
        return self._get_property("all_gather_implementation_custom")

    @all_gather_implementation_custom.setter
    def all_gather_implementation_custom(self, value):
        """all_gather_implementation_custom setter

        This parameter defines Chakra ET file path for AllGather collective operations, following the same single-file requirement for multi-dimensional scenarios.

        value: List[str]
        """
        self._set_property("all_gather_implementation_custom", value)

    @property
    def all_reduce_implementation_custom(self):
        # type: () -> List[str]
        """all_reduce_implementation_custom getter

        This parameter specifies Chakra ET file for AllReduce operations, also requiring exactly one ET file to cover all dimensions in the collective implementation.

        Returns: List[str]
        """
        return self._get_property("all_reduce_implementation_custom")

    @all_reduce_implementation_custom.setter
    def all_reduce_implementation_custom(self, value):
        """all_reduce_implementation_custom setter

        This parameter specifies Chakra ET file for AllReduce operations, also requiring exactly one ET file to cover all dimensions in the collective implementation.

        value: List[str]
        """
        self._set_property("all_reduce_implementation_custom", value)

    @property
    def collective_optimization(self):
        # type: () -> Union[Literal["baseline"], Literal["localBWAware"]]
        """collective_optimization getter

        baseline issues allreduce across all dimensions to handle allreduce of single chunk. While for an N-dimensional network, localBWAware issues series of reduce-scatters on all dimensions from dim1 to dimN-1, followed by all-reduce on dimN, and then series of all-gathers starting from dimN-1 to dim1. This optimization is used to reduce the chunk size as it goes to the next network dimensions.

        Returns: Union[Literal["baseline"], Literal["localBWAware"]]
        """
        return self._get_property("collective_optimization")

    @collective_optimization.setter
    def collective_optimization(self, value):
        """collective_optimization setter

        baseline issues allreduce across all dimensions to handle allreduce of single chunk. While for an N-dimensional network, localBWAware issues series of reduce-scatters on all dimensions from dim1 to dimN-1, followed by all-reduce on dimN, and then series of all-gathers starting from dimN-1 to dim1. This optimization is used to reduce the chunk size as it goes to the next network dimensions.

        value: Union[Literal["baseline"], Literal["localBWAware"]]
        """
        self._set_property("collective_optimization", value)

    @property
    def local_reduction_delay(self):
        # type: () -> int
        """local_reduction_delay getter

        The local_reduction_delay parameter specifies the delay for local reduction operations during collective communications, with default value of 1.

        Returns: int
        """
        return self._get_property("local_reduction_delay")

    @local_reduction_delay.setter
    def local_reduction_delay(self, value):
        """local_reduction_delay setter

        The local_reduction_delay parameter specifies the delay for local reduction operations during collective communications, with default value of 1.

        value: int
        """
        self._set_property("local_reduction_delay", value)

    @property
    def active_chunks_per_dimension(self):
        # type: () -> int
        """active_chunks_per_dimension getter

        This corresponds to the Maximum number of chunks we like execute in parallel on each logical dimesnion of topology.

        Returns: int
        """
        return self._get_property("active_chunks_per_dimension")

    @active_chunks_per_dimension.setter
    def active_chunks_per_dimension(self, value):
        """active_chunks_per_dimension setter

        This corresponds to the Maximum number of chunks we like execute in parallel on each logical dimesnion of topology.

        value: int
        """
        self._set_property("active_chunks_per_dimension", value)

    @property
    def latency(self):
        # type: () -> float
        """latency getter

        Translates to - Latency parameter for memory operations.

        Returns: float
        """
        return self._get_property("latency")

    @latency.setter
    def latency(self, value):
        """latency setter

        Translates to - Latency parameter for memory operations.

        value: float
        """
        self._set_property("latency", value)

    @property
    def overhead(self):
        # type: () -> float
        """overhead getter

        Translates to - Overhead parameter for memory transactions.

        Returns: float
        """
        return self._get_property("overhead")

    @overhead.setter
    def overhead(self, value):
        """overhead setter

        Translates to - Overhead parameter for memory transactions.

        value: float
        """
        self._set_property("overhead", value)

    @property
    def gap(self):
        # type: () -> float
        """gap getter

        Translates to - Gap parameter between memory operations.

        Returns: float
        """
        return self._get_property("gap")

    @gap.setter
    def gap(self, value):
        """gap setter

        Translates to - Gap parameter between memory operations.

        value: float
        """
        self._set_property("gap", value)

    @property
    def global_memory(self):
        # type: () -> float
        """global_memory getter

        Translates to - Global memory parameter or bandwidth-related setting.

        Returns: float
        """
        return self._get_property("global_memory")

    @global_memory.setter
    def global_memory(self, value):
        """global_memory setter

        Translates to - Global memory parameter or bandwidth-related setting.

        value: float
        """
        self._set_property("global_memory", value)

    @property
    def endpoint_delay(self):
        # type: () -> int
        """endpoint_delay getter

        The time NPU spends processing message after receiving it in terms of cycles.

        Returns: int
        """
        return self._get_property("endpoint_delay")

    @endpoint_delay.setter
    def endpoint_delay(self, value):
        """endpoint_delay setter

        The time NPU spends processing message after receiving it in terms of cycles.

        value: int
        """
        self._set_property("endpoint_delay", value)

    @property
    def model_shared_bus(self):
        # type: () -> int
        """model_shared_bus getter

        The local_reduction_delay parameter specifies the delay for local reduction operations during collective communications, with default value of 1.

        Returns: int
        """
        return self._get_property("model_shared_bus")

    @model_shared_bus.setter
    def model_shared_bus(self, value):
        """model_shared_bus setter

        The local_reduction_delay parameter specifies the delay for local reduction operations during collective communications, with default value of 1.

        value: int
        """
        self._set_property("model_shared_bus", value)

    @property
    def preferred_dataset_splits(self):
        # type: () -> int
        """preferred_dataset_splits getter

        The preferred_dataset_splits parameter controls how datasets are divided for collective operations, with default value of 0.

        Returns: int
        """
        return self._get_property("preferred_dataset_splits")

    @preferred_dataset_splits.setter
    def preferred_dataset_splits(self, value):
        """preferred_dataset_splits setter

        The preferred_dataset_splits parameter controls how datasets are divided for collective operations, with default value of 0.

        value: int
        """
        self._set_property("preferred_dataset_splits", value)

    @property
    def peak_perf(self):
        # type: () -> float
        """peak_perf getter

        The peak_perf parameter specifies the peak computational performance in TFLOPS, with default value of 0.

        Returns: float
        """
        return self._get_property("peak_perf")

    @peak_perf.setter
    def peak_perf(self, value):
        """peak_perf setter

        The peak_perf parameter specifies the peak computational performance in TFLOPS, with default value of 0.

        value: float
        """
        self._set_property("peak_perf", value)

    @property
    def local_mem_bw(self):
        # type: () -> float
        """local_mem_bw getter

        The local_mem_bw parameter defines the local memory bandwidth in GB/sec, with default value of 0.

        Returns: float
        """
        return self._get_property("local_mem_bw")

    @local_mem_bw.setter
    def local_mem_bw(self, value):
        """local_mem_bw setter

        The local_mem_bw parameter defines the local memory bandwidth in GB/sec, with default value of 0.

        value: float
        """
        self._set_property("local_mem_bw", value)

    @property
    def roofline_enabled(self):
        # type: () -> int
        """roofline_enabled getter

        The roofline_enabled parameter is boolean flag that enables roofline performance modeling, defaulting to false. When enabled, it creates Roofline instance using the specified local_mem_bw and peak_perf parameters for realistic performance modeling.

        Returns: int
        """
        return self._get_property("roofline_enabled")

    @roofline_enabled.setter
    def roofline_enabled(self, value):
        """roofline_enabled setter

        The roofline_enabled parameter is boolean flag that enables roofline performance modeling, defaulting to false. When enabled, it creates Roofline instance using the specified local_mem_bw and peak_perf parameters for realistic performance modeling.

        value: int
        """
        self._set_property("roofline_enabled", value)

    @property
    def trace_enabled(self):
        # type: () -> int
        """trace_enabled getter

        The trace_enabled parameter controls whether execution tracing is enabled during simulation, defaulting to false. When enabled, it activates detailed logging throughout the workload execution for debugging and analysis purposes.

        Returns: int
        """
        return self._get_property("trace_enabled")

    @trace_enabled.setter
    def trace_enabled(self, value):
        """trace_enabled setter

        The trace_enabled parameter controls whether execution tracing is enabled during simulation, defaulting to false. When enabled, it activates detailed logging throughout the workload execution for debugging and analysis purposes.

        value: int
        """
        self._set_property("trace_enabled", value)

    @property
    def replay_only(self):
        # type: () -> int
        """replay_only getter

        The replay_only parameter is boolean flag that skips actual simulation and uses current duration values, defaulting to false. When enabled, it bypasses normal simulation execution and directly processes workload nodes without timing simulation.

        Returns: int
        """
        return self._get_property("replay_only")

    @replay_only.setter
    def replay_only(self, value):
        """replay_only setter

        The replay_only parameter is boolean flag that skips actual simulation and uses current duration values, defaulting to false. When enabled, it bypasses normal simulation execution and directly processes workload nodes without timing simulation.

        value: int
        """
        self._set_property("replay_only", value)

    @property
    def track_local_mem(self):
        # type: () -> int
        """track_local_mem getter

        TBD

        Returns: int
        """
        return self._get_property("track_local_mem")

    @track_local_mem.setter
    def track_local_mem(self, value):
        """track_local_mem setter

        TBD

        value: int
        """
        self._set_property("track_local_mem", value)

    @property
    def local_mem_trace_filename(self):
        # type: () -> str
        """local_mem_trace_filename getter

        TBD

        Returns: str
        """
        return self._get_property("local_mem_trace_filename")

    @local_mem_trace_filename.setter
    def local_mem_trace_filename(self, value):
        """local_mem_trace_filename setter

        TBD

        value: str
        """
        self._set_property("local_mem_trace_filename", value)


class CommunicatorGroup(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "identifier": {"type": str},
        "npu_list": {
            "type": list,
            "itemtype": int,
            "itemformat": "int32",
        },
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, identifier=None, npu_list=None):
        super(CommunicatorGroup, self).__init__()
        self._parent = parent
        self._set_property("identifier", identifier)
        self._set_property("npu_list", npu_list)

    def set(self, identifier=None, npu_list=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def identifier(self):
        # type: () -> str
        """identifier getter

        Represents unique identifier for communication group. This ID is used to distinguish different groups of NPUs that participate together in collective communication operations.

        Returns: str
        """
        return self._get_property("identifier")

    @identifier.setter
    def identifier(self, value):
        """identifier setter

        Represents unique identifier for communication group. This ID is used to distinguish different groups of NPUs that participate together in collective communication operations.

        value: str
        """
        self._set_property("identifier", value)

    @property
    def npu_list(self):
        # type: () -> List[int]
        """npu_list getter

        Contains the list of NPU IDs that belong to the communication group identified by the process ID. Each NPU listed is member of this group and will participate in collective operations such as AllReduce and AllGather with the other NPUs in the same group.

        Returns: List[int]
        """
        return self._get_property("npu_list")

    @npu_list.setter
    def npu_list(self, value):
        """npu_list setter

        Contains the list of NPU IDs that belong to the communication group identified by the process ID. Each NPU listed is member of this group and will participate in collective operations such as AllReduce and AllGather with the other NPUs in the same group.

        value: List[int]
        """
        self._set_property("npu_list", value)


class CommunicatorGroupIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(CommunicatorGroupIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[CommunicatorGroup]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> CommunicatorGroupIter
        return self._iter()

    def __next__(self):
        # type: () -> CommunicatorGroup
        return self._next()

    def next(self):
        # type: () -> CommunicatorGroup
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, CommunicatorGroup):
            raise Exception("Item is not an instance of CommunicatorGroup")

    def group(self, identifier=None, npu_list=None):
        # type: (str,List[int]) -> CommunicatorGroupIter
        """Factory method that creates an instance of the CommunicatorGroup class

        Defines the communication group configuration for ASTRA-sim, enabling users to specify process group memberships and related NPUs within structured schema.

        Returns: CommunicatorGroupIter
        """
        item = CommunicatorGroup(
            parent=self._parent, identifier=identifier, npu_list=npu_list
        )
        self._add(item)
        return self

    def add(self, identifier=None, npu_list=None):
        # type: (str,List[int]) -> CommunicatorGroup
        """Add method that creates and returns an instance of the CommunicatorGroup class

        Defines the communication group configuration for ASTRA-sim, enabling users to specify process group memberships and related NPUs within structured schema.

        Returns: CommunicatorGroup
        """
        item = CommunicatorGroup(
            parent=self._parent, identifier=identifier, npu_list=npu_list
        )
        self._add(item)
        return item


class RemoteMemory(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "memory_type": {
            "type": str,
            "enum": [
                "NO_MEMORY_EXPANSION",
                "PER_NODE_MEMORY_EXPANSION",
                "PER_NPU_MEMORY_EXPANSION",
                "MEMORY_POOL",
            ],
        },
        "remote_mem_latency": {
            "type": int,
            "format": "int32",
            "minimum": 0,
        },
        "remote_mem_bw": {
            "type": int,
            "format": "int32",
            "minimum": 0,
        },
        "num_nodes": {
            "type": int,
            "format": "int32",
            "minimum": 0,
        },
        "num_npus_per_node": {
            "type": int,
            "format": "int32",
            "minimum": 0,
        },
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {
        "memory_type": "NO_MEMORY_EXPANSION",
        "remote_mem_latency": 0,
        "remote_mem_bw": 0,
    }  # type: Dict[str, Union(type)]

    NO_MEMORY_EXPANSION = "NO_MEMORY_EXPANSION"  # type: str
    PER_NODE_MEMORY_EXPANSION = "PER_NODE_MEMORY_EXPANSION"  # type: str
    PER_NPU_MEMORY_EXPANSION = "PER_NPU_MEMORY_EXPANSION"  # type: str
    MEMORY_POOL = "MEMORY_POOL"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self,
        parent=None,
        memory_type="NO_MEMORY_EXPANSION",
        remote_mem_latency=0,
        remote_mem_bw=0,
        num_nodes=None,
        num_npus_per_node=None,
    ):
        super(RemoteMemory, self).__init__()
        self._parent = parent
        self._set_property("memory_type", memory_type)
        self._set_property("remote_mem_latency", remote_mem_latency)
        self._set_property("remote_mem_bw", remote_mem_bw)
        self._set_property("num_nodes", num_nodes)
        self._set_property("num_npus_per_node", num_npus_per_node)

    def set(
        self,
        memory_type=None,
        remote_mem_latency=None,
        remote_mem_bw=None,
        num_nodes=None,
        num_npus_per_node=None,
    ):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def memory_type(self):
        # type: () -> Union[Literal["MEMORY_POOL"], Literal["NO_MEMORY_EXPANSION"], Literal["PER_NODE_MEMORY_EXPANSION"], Literal["PER_NPU_MEMORY_EXPANSION"]]
        """memory_type getter

        the memory type.

        Returns: Union[Literal["MEMORY_POOL"], Literal["NO_MEMORY_EXPANSION"], Literal["PER_NODE_MEMORY_EXPANSION"], Literal["PER_NPU_MEMORY_EXPANSION"]]
        """
        return self._get_property("memory_type")

    @memory_type.setter
    def memory_type(self, value):
        """memory_type setter

        the memory type.

        value: Union[Literal["MEMORY_POOL"], Literal["NO_MEMORY_EXPANSION"], Literal["PER_NODE_MEMORY_EXPANSION"], Literal["PER_NPU_MEMORY_EXPANSION"]]
        """
        self._set_property("memory_type", value)

    @property
    def remote_mem_latency(self):
        # type: () -> int
        """remote_mem_latency getter

        remote memory latency (ns).

        Returns: int
        """
        return self._get_property("remote_mem_latency")

    @remote_mem_latency.setter
    def remote_mem_latency(self, value):
        """remote_mem_latency setter

        remote memory latency (ns).

        value: int
        """
        self._set_property("remote_mem_latency", value)

    @property
    def remote_mem_bw(self):
        # type: () -> int
        """remote_mem_bw getter

        remote memory bandwidth (GB/s or B/ns).

        Returns: int
        """
        return self._get_property("remote_mem_bw")

    @remote_mem_bw.setter
    def remote_mem_bw(self, value):
        """remote_mem_bw setter

        remote memory bandwidth (GB/s or B/ns).

        value: int
        """
        self._set_property("remote_mem_bw", value)

    @property
    def num_nodes(self):
        # type: () -> int
        """num_nodes getter

        number of nodes (only valid with “PER_NODE_MEMORY_EXPANSION”).

        Returns: int
        """
        return self._get_property("num_nodes")

    @num_nodes.setter
    def num_nodes(self, value):
        """num_nodes setter

        number of nodes (only valid with “PER_NODE_MEMORY_EXPANSION”).

        value: int
        """
        self._set_property("num_nodes", value)

    @property
    def num_npus_per_node(self):
        # type: () -> int
        """num_npus_per_node getter

        number of NPUs per node (only valid with “PER_NODE_MEMORY_EXPANSION”).

        Returns: int
        """
        return self._get_property("num_npus_per_node")

    @num_npus_per_node.setter
    def num_npus_per_node(self, value):
        """num_npus_per_node setter

        number of NPUs per node (only valid with “PER_NODE_MEMORY_EXPANSION”).

        value: int
        """
        self._set_property("num_npus_per_node", value)


class SpdlogConfig(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "sink": {"type": "SinkIter"},
        "logger": {"type": "LoggerIter"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(SpdlogConfig, self).__init__()
        self._parent = parent

    @property
    def sink(self):
        # type: () -> SinkIter
        """sink getter

        List of log sinks, defining where log messages are written (e.g., files, console).

        Returns: SinkIter
        """
        return self._get_property("sink", SinkIter, self._parent, self._choice)

    @property
    def logger(self):
        # type: () -> LoggerIter
        """logger getter

        List of logger configurations, each mapping to one or more sinks and defining log levels and formats.

        Returns: LoggerIter
        """
        return self._get_property("logger", LoggerIter, self._parent, self._choice)


class Sink(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "name": {"type": str},
        "type": {"type": str},
        "filename": {"type": str},
        "truncate": {"type": bool},
        "create_parent_dir": {"type": bool},
    }  # type: Dict[str, str]

    _REQUIRED = ("name", "type")  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self,
        parent=None,
        name=None,
        type=None,
        filename=None,
        truncate=None,
        create_parent_dir=None,
    ):
        super(Sink, self).__init__()
        self._parent = parent
        self._set_property("name", name)
        self._set_property("type", type)
        self._set_property("filename", filename)
        self._set_property("truncate", truncate)
        self._set_property("create_parent_dir", create_parent_dir)

    def set(
        self, name=None, type=None, filename=None, truncate=None, create_parent_dir=None
    ):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def name(self):
        # type: () -> str
        """name getter

        Unique identifier for the sink, used to reference it in logger definitions.

        Returns: str
        """
        return self._get_property("name")

    @name.setter
    def name(self, value):
        """name setter

        Unique identifier for the sink, used to reference it in logger definitions.

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property name as None")
        self._set_property("name", value)

    @property
    def type(self):
        # type: () -> str
        """type getter

        Sink type (e.g., stdout_sink_mt for console, basic_file_sink_mt for file output).

        Returns: str
        """
        return self._get_property("type")

    @type.setter
    def type(self, value):
        """type setter

        Sink type (e.g., stdout_sink_mt for console, basic_file_sink_mt for file output).

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property type as None")
        self._set_property("type", value)

    @property
    def filename(self):
        # type: () -> str
        """filename getter

        File path where log messages will be written. Required when using file-based sinks.

        Returns: str
        """
        return self._get_property("filename")

    @filename.setter
    def filename(self, value):
        """filename setter

        File path where log messages will be written. Required when using file-based sinks.

        value: str
        """
        self._set_property("filename", value)

    @property
    def truncate(self):
        # type: () -> bool
        """truncate getter

        Determines whether existing files should be truncated on startup (`true`) or logs should be appended (`false`).

        Returns: bool
        """
        return self._get_property("truncate")

    @truncate.setter
    def truncate(self, value):
        """truncate setter

        Determines whether existing files should be truncated on startup (`true`) or logs should be appended (`false`).

        value: bool
        """
        self._set_property("truncate", value)

    @property
    def create_parent_dir(self):
        # type: () -> bool
        """create_parent_dir getter

        Indicates whether parent directories should automatically be created if they do not exist.

        Returns: bool
        """
        return self._get_property("create_parent_dir")

    @create_parent_dir.setter
    def create_parent_dir(self, value):
        """create_parent_dir setter

        Indicates whether parent directories should automatically be created if they do not exist.

        value: bool
        """
        self._set_property("create_parent_dir", value)


class SinkIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(SinkIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[Sink]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> SinkIter
        return self._iter()

    def __next__(self):
        # type: () -> Sink
        return self._next()

    def next(self):
        # type: () -> Sink
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, Sink):
            raise Exception("Item is not an instance of Sink")

    def sink(
        self, name=None, type=None, filename=None, truncate=None, create_parent_dir=None
    ):
        # type: (str,str,str,bool,bool) -> SinkIter
        """Factory method that creates an instance of the Sink class

        Defines log sink, which represents an output destination (such as file or console) for log messages.

        Returns: SinkIter
        """
        item = Sink(
            parent=self._parent,
            name=name,
            type=type,
            filename=filename,
            truncate=truncate,
            create_parent_dir=create_parent_dir,
        )
        self._add(item)
        return self

    def add(
        self, name=None, type=None, filename=None, truncate=None, create_parent_dir=None
    ):
        # type: (str,str,str,bool,bool) -> Sink
        """Add method that creates and returns an instance of the Sink class

        Defines log sink, which represents an output destination (such as file or console) for log messages.

        Returns: Sink
        """
        item = Sink(
            parent=self._parent,
            name=name,
            type=type,
            filename=filename,
            truncate=truncate,
            create_parent_dir=create_parent_dir,
        )
        self._add(item)
        return item


class Logger(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "name": {"type": str},
        "sinks": {
            "type": list,
            "itemtype": str,
        },
        "level": {
            "type": str,
            "enum": [
                "trace",
                "debug",
                "info",
                "warn",
                "error",
                "critical",
            ],
        },
        "pattern": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    TRACE = "trace"  # type: str
    DEBUG = "debug"  # type: str
    INFO = "info"  # type: str
    WARN = "warn"  # type: str
    ERROR = "error"  # type: str
    CRITICAL = "critical"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, name=None, sinks=None, level=None, pattern=None):
        super(Logger, self).__init__()
        self._parent = parent
        self._set_property("name", name)
        self._set_property("sinks", sinks)
        self._set_property("level", level)
        self._set_property("pattern", pattern)

    def set(self, name=None, sinks=None, level=None, pattern=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def name(self):
        # type: () -> str
        """name getter

        Name of the logger, used to uniquely identify it.

        Returns: str
        """
        return self._get_property("name")

    @name.setter
    def name(self, value):
        """name setter

        Name of the logger, used to uniquely identify it.

        value: str
        """
        self._set_property("name", value)

    @property
    def sinks(self):
        # type: () -> List[str]
        """sinks getter

        List of sink names associated with this logger. Each log message is written to the defined sinks.

        Returns: List[str]
        """
        return self._get_property("sinks")

    @sinks.setter
    def sinks(self, value):
        """sinks setter

        List of sink names associated with this logger. Each log message is written to the defined sinks.

        value: List[str]
        """
        self._set_property("sinks", value)

    @property
    def level(self):
        # type: () -> Union[Literal["critical"], Literal["debug"], Literal["error"], Literal["info"], Literal["trace"], Literal["warn"]]
        """level getter

        Minimum severity level of messages the logger will output.

        Returns: Union[Literal["critical"], Literal["debug"], Literal["error"], Literal["info"], Literal["trace"], Literal["warn"]]
        """
        return self._get_property("level")

    @level.setter
    def level(self, value):
        """level setter

        Minimum severity level of messages the logger will output.

        value: Union[Literal["critical"], Literal["debug"], Literal["error"], Literal["info"], Literal["trace"], Literal["warn"]]
        """
        self._set_property("level", value)

    @property
    def pattern(self):
        # type: () -> str
        """pattern getter

        Optional message format pattern for log output (overrides the default spdlog pattern if specified).

        Returns: str
        """
        return self._get_property("pattern")

    @pattern.setter
    def pattern(self, value):
        """pattern setter

        Optional message format pattern for log output (overrides the default spdlog pattern if specified).

        value: str
        """
        self._set_property("pattern", value)


class LoggerIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(LoggerIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[Logger]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> LoggerIter
        return self._iter()

    def __next__(self):
        # type: () -> Logger
        return self._next()

    def next(self):
        # type: () -> Logger
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, Logger):
            raise Exception("Item is not an instance of Logger")

    def logger(self, name=None, sinks=None, level=None, pattern=None):
        # type: (str,List[str],Union[Literal["critical"], Literal["debug"], Literal["error"], Literal["info"], Literal["trace"], Literal["warn"]],str) -> LoggerIter
        """Factory method that creates an instance of the Logger class

        Defines logger configuration, which specifies the sinks it writes to, its log level, and optional message formatting.

        Returns: LoggerIter
        """
        item = Logger(
            parent=self._parent, name=name, sinks=sinks, level=level, pattern=pattern
        )
        self._add(item)
        return self

    def add(self, name=None, sinks=None, level=None, pattern=None):
        # type: (str,List[str],Union[Literal["critical"], Literal["debug"], Literal["error"], Literal["info"], Literal["trace"], Literal["warn"]],str) -> Logger
        """Add method that creates and returns an instance of the Logger class

        Defines logger configuration, which specifies the sinks it writes to, its log level, and optional message formatting.

        Returns: Logger
        """
        item = Logger(
            parent=self._parent, name=name, sinks=sinks, level=level, pattern=pattern
        )
        self._add(item)
        return item


class CommandArguments(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "num_queues_per_dim": {
            "type": int,
            "format": "uint32",
        },
        "comm_scale": {
            "type": float,
            "format": "double",
        },
        "injection_scale": {
            "type": float,
            "format": "double",
        },
        "rendezvous_protocol": {"type": bool},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {
        "num_queues_per_dim": 1,
        "comm_scale": 1.0,
        "injection_scale": 1.0,
        "rendezvous_protocol": False,
    }  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self,
        parent=None,
        num_queues_per_dim=1,
        comm_scale=1.0,
        injection_scale=1.0,
        rendezvous_protocol=False,
    ):
        super(CommandArguments, self).__init__()
        self._parent = parent
        self._set_property("num_queues_per_dim", num_queues_per_dim)
        self._set_property("comm_scale", comm_scale)
        self._set_property("injection_scale", injection_scale)
        self._set_property("rendezvous_protocol", rendezvous_protocol)

    def set(
        self,
        num_queues_per_dim=None,
        comm_scale=None,
        injection_scale=None,
        rendezvous_protocol=None,
    ):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def num_queues_per_dim(self):
        # type: () -> int
        """num_queues_per_dim getter

        The num-queues-per-dim parameter specifies the number of communication queues allocated per network dimension, with default value of 1.

        Returns: int
        """
        return self._get_property("num_queues_per_dim")

    @num_queues_per_dim.setter
    def num_queues_per_dim(self, value):
        """num_queues_per_dim setter

        The num-queues-per-dim parameter specifies the number of communication queues allocated per network dimension, with default value of 1.

        value: int
        """
        self._set_property("num_queues_per_dim", value)

    @property
    def comm_scale(self):
        # type: () -> float
        """comm_scale getter

        The comm-scale parameter is scaling factor applied to communication operations, with default value of 1.0.

        Returns: float
        """
        return self._get_property("comm_scale")

    @comm_scale.setter
    def comm_scale(self, value):
        """comm_scale setter

        The comm-scale parameter is scaling factor applied to communication operations, with default value of 1.0.

        value: float
        """
        self._set_property("comm_scale", value)

    @property
    def injection_scale(self):
        # type: () -> float
        """injection_scale getter

        The injection-scale parameter scales injection delays and endpoint communication delays, with default value of 1.0.

        Returns: float
        """
        return self._get_property("injection_scale")

    @injection_scale.setter
    def injection_scale(self, value):
        """injection_scale setter

        The injection-scale parameter scales injection delays and endpoint communication delays, with default value of 1.0.

        value: float
        """
        self._set_property("injection_scale", value)

    @property
    def rendezvous_protocol(self):
        # type: () -> bool
        """rendezvous_protocol getter

        The rendezvous-protocol parameter enables or disables the rendezvous communication protocol, with default value of false.

        Returns: bool
        """
        return self._get_property("rendezvous_protocol")

    @rendezvous_protocol.setter
    def rendezvous_protocol(self, value):
        """rendezvous_protocol setter

        The rendezvous-protocol parameter enables or disables the rendezvous communication protocol, with default value of false.

        value: bool
        """
        self._set_property("rendezvous_protocol", value)


class NetworkBackend(OpenApiObject):
    __slots__ = ("_parent", "_choice")

    _TYPES = {
        "choice": {
            "type": str,
            "enum": [
                "analytical_congestion_aware",
                "analytical_congestion_unaware",
                "ns3",
                "htsim",
            ],
        },
        "analytical_congestion_aware": {"type": "AnalyticalConfiguration"},
        "analytical_congestion_unaware": {"type": "AnalyticalConfiguration"},
        "ns3": {"type": "NS3Configuration"},
        "htsim": {"type": "HTSimConfiguration"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    ANALYTICAL_CONGESTION_AWARE = "analytical_congestion_aware"  # type: str
    ANALYTICAL_CONGESTION_UNAWARE = "analytical_congestion_unaware"  # type: str
    NS3 = "ns3"  # type: str
    HTSIM = "htsim"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, choice=None):
        super(NetworkBackend, self).__init__()
        self._parent = parent
        if (
            "choice" in self._DEFAULTS
            and choice is None
            and self._DEFAULTS["choice"] in self._TYPES
        ):
            getattr(self, self._DEFAULTS["choice"])
        else:
            self._set_property("choice", choice)

    @property
    def analytical_congestion_aware(self):
        # type: () -> AnalyticalConfiguration
        """Factory property that returns an instance of the AnalyticalConfiguration class

        This allows user to define the analytical configuration by allowing them to select between schema or infragraph which will be translated to schema by the server.

        Returns: AnalyticalConfiguration
        """
        return self._get_property(
            "analytical_congestion_aware",
            AnalyticalConfiguration,
            self,
            "analytical_congestion_aware",
        )

    @property
    def analytical_congestion_unaware(self):
        # type: () -> AnalyticalConfiguration
        """Factory property that returns an instance of the AnalyticalConfiguration class

        This allows user to define the analytical configuration by allowing them to select between schema or infragraph which will be translated to schema by the server.

        Returns: AnalyticalConfiguration
        """
        return self._get_property(
            "analytical_congestion_unaware",
            AnalyticalConfiguration,
            self,
            "analytical_congestion_unaware",
        )

    @property
    def ns3(self):
        # type: () -> NS3Configuration
        """Factory property that returns an instance of the NS3Configuration class

        The NS3 backend configuration enables users to define the NS3 backend settings using schema-based approach. The primary configuration schemas include network (representing network settings), topology (encompassing nc_topology, logical topology, and trace information), and trace itself, allowing users to specify properties via schemas. The topology schema supports choice between the infragraph and nc_topology schemas; when infragraph is selected, the server automatically converts the infragraph representation to the nc_topology format on the backend, streamlining the process for users.

        Returns: NS3Configuration
        """
        return self._get_property("ns3", NS3Configuration, self, "ns3")

    @property
    def htsim(self):
        # type: () -> HTSimConfiguration
        """Factory property that returns an instance of the HTSimConfiguration class

        Allows the end user to configure the HTSim backend. Users can select the HTSim protocol (e.g., TCP, RoCE) along with its schema-specific options, and define the network topology. For topology, users can either provide an infragraph from the global configuration or choose network configuration schema, which has analytical network config and predefined schemas for topologies such as fat-tree and others.

        Returns: HTSimConfiguration
        """
        return self._get_property("htsim", HTSimConfiguration, self, "htsim")

    @property
    def choice(self):
        # type: () -> Union[Literal["analytical_congestion_aware"], Literal["analytical_congestion_unaware"], Literal["htsim"], Literal["ns3"]]
        """choice getter

        Specifies the network backend to use for the simulation. Supported options include the analytical congestion-aware or congestion-unaware models, the NS3 discrete-event simulator, and the htsim high-performance simulator.

        Returns: Union[Literal["analytical_congestion_aware"], Literal["analytical_congestion_unaware"], Literal["htsim"], Literal["ns3"]]
        """
        return self._get_property("choice")

    @choice.setter
    def choice(self, value):
        """choice setter

        Specifies the network backend to use for the simulation. Supported options include the analytical congestion-aware or congestion-unaware models, the NS3 discrete-event simulator, and the htsim high-performance simulator.

        value: Union[Literal["analytical_congestion_aware"], Literal["analytical_congestion_unaware"], Literal["htsim"], Literal["ns3"]]
        """
        self._set_property("choice", value)


class AnalyticalConfiguration(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "topology": {"type": "AnalyticalTopology"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(AnalyticalConfiguration, self).__init__()
        self._parent = parent

    @property
    def topology(self):
        # type: () -> AnalyticalTopology
        """topology getter

        Provides choice between infragraph and analytical network configuration. If analytical is selected, schema is provided to specify analytical network values. If infragraph is selected, the user can reference the infragraph schema from the global configuration, which the server will convert into an analytical schema.Provides choice between infragraph and analytical network configuration. If analytical is selected, schema is provided to specify analytical network values. If infragraph is selected, the user can reference the infragraph schema from the global configuration, which the server will convert into an analytical schema.Provides choice between infragraph and analytical network configuration. If analytical is selected, schema is provided to specify analytical network values. If infragraph is selected, the user can reference the infragraph schema from the global configuration, which the server will convert into an analytical schema.Provides choice between infragraph and analytical network configuration. If analytical is selected, schema is provided to specify analytical network values. If infragraph is selected, the user can reference the infragraph schema from the global configuration, which the server will convert into an analytical schema.Provides choice between infragraph and analytical network configuration. If analytical is selected, schema is provided to specify analytical network values. If infragraph is selected, the user can reference the infragraph schema from the global configuration, which the server will convert into an analytical schema.

        Returns: AnalyticalTopology
        """
        return self._get_property("topology", AnalyticalTopology)


class AnalyticalTopology(OpenApiObject):
    __slots__ = ("_parent", "_choice")

    _TYPES = {
        "choice": {
            "type": str,
            "enum": [
                "network",
                "infragraph",
            ],
        },
        "network": {"type": "AnalyticalTopologyNetworkIter"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    NETWORK = "network"  # type: str
    INFRAGRAPH = "infragraph"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, choice=None):
        super(AnalyticalTopology, self).__init__()
        self._parent = parent
        if (
            "choice" in self._DEFAULTS
            and choice is None
            and self._DEFAULTS["choice"] in self._TYPES
        ):
            getattr(self, self._DEFAULTS["choice"])
        else:
            self._set_property("choice", choice)

    @property
    def choice(self):
        # type: () -> Union[Literal["infragraph"], Literal["network"]]
        """choice getter

        Specifies the choice between analytical network config or infragraph.

        Returns: Union[Literal["infragraph"], Literal["network"]]
        """
        return self._get_property("choice")

    @choice.setter
    def choice(self, value):
        """choice setter

        Specifies the choice between analytical network config or infragraph.

        value: Union[Literal["infragraph"], Literal["network"]]
        """
        self._set_property("choice", value)

    @property
    def network(self):
        # type: () -> AnalyticalTopologyNetworkIter
        """network getter

        An array of Analytical.Topology.Network which holds the topology, npus_count, bandwidth and latency. The minimum length of array is and maximum is 3.

        Returns: AnalyticalTopologyNetworkIter
        """
        return self._get_property(
            "network", AnalyticalTopologyNetworkIter, self._parent, self._choice
        )


class AnalyticalTopologyNetwork(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "topology": {
            "type": str,
            "enum": [
                "ring",
                "fullyconnected",
                "switch",
            ],
        },
        "npus_count": {
            "type": int,
            "format": "int32",
        },
        "bandwidth": {
            "type": float,
            "format": "float",
        },
        "latency": {
            "type": float,
            "format": "float",
        },
    }  # type: Dict[str, str]

    _REQUIRED = ("topology", "npus_count", "bandwidth", "latency")  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    RING = "ring"  # type: str
    FULLYCONNECTED = "fullyconnected"  # type: str
    SWITCH = "switch"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self, parent=None, topology=None, npus_count=None, bandwidth=None, latency=None
    ):
        super(AnalyticalTopologyNetwork, self).__init__()
        self._parent = parent
        self._set_property("topology", topology)
        self._set_property("npus_count", npus_count)
        self._set_property("bandwidth", bandwidth)
        self._set_property("latency", latency)

    def set(self, topology=None, npus_count=None, bandwidth=None, latency=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def topology(self):
        # type: () -> Union[Literal["fullyconnected"], Literal["ring"], Literal["switch"]]
        """topology getter

        List of topology types for each dimension (in order)..

        Returns: Union[Literal["fullyconnected"], Literal["ring"], Literal["switch"]]
        """
        return self._get_property("topology")

    @topology.setter
    def topology(self, value):
        """topology setter

        List of topology types for each dimension (in order)..

        value: Union[Literal["fullyconnected"], Literal["ring"], Literal["switch"]]
        """
        if value is None:
            raise TypeError("Cannot set required property topology as None")
        self._set_property("topology", value)

    @property
    def npus_count(self):
        # type: () -> int
        """npus_count getter

        Number of NPUs (neuronal processing units) along each topology dimension..

        Returns: int
        """
        return self._get_property("npus_count")

    @npus_count.setter
    def npus_count(self, value):
        """npus_count setter

        Number of NPUs (neuronal processing units) along each topology dimension..

        value: int
        """
        if value is None:
            raise TypeError("Cannot set required property npus_count as None")
        self._set_property("npus_count", value)

    @property
    def bandwidth(self):
        # type: () -> float
        """bandwidth getter

        Bandwidth per dimension in GB/s..

        Returns: float
        """
        return self._get_property("bandwidth")

    @bandwidth.setter
    def bandwidth(self, value):
        """bandwidth setter

        Bandwidth per dimension in GB/s..

        value: float
        """
        if value is None:
            raise TypeError("Cannot set required property bandwidth as None")
        self._set_property("bandwidth", value)

    @property
    def latency(self):
        # type: () -> float
        """latency getter

        Latency per dimension in nanoseconds (ns)..

        Returns: float
        """
        return self._get_property("latency")

    @latency.setter
    def latency(self, value):
        """latency setter

        Latency per dimension in nanoseconds (ns)..

        value: float
        """
        if value is None:
            raise TypeError("Cannot set required property latency as None")
        self._set_property("latency", value)


class AnalyticalTopologyNetworkIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(AnalyticalTopologyNetworkIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[AnalyticalTopologyNetwork]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> AnalyticalTopologyNetworkIter
        return self._iter()

    def __next__(self):
        # type: () -> AnalyticalTopologyNetwork
        return self._next()

    def next(self):
        # type: () -> AnalyticalTopologyNetwork
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, AnalyticalTopologyNetwork):
            raise Exception("Item is not an instance of AnalyticalTopologyNetwork")

    def network(self, topology=None, npus_count=None, bandwidth=None, latency=None):
        # type: (Union[Literal["fullyconnected"], Literal["ring"], Literal["switch"]],int,float,float) -> AnalyticalTopologyNetworkIter
        """Factory method that creates an instance of the AnalyticalTopologyNetwork class

        TBD

        Returns: AnalyticalTopologyNetworkIter
        """
        item = AnalyticalTopologyNetwork(
            parent=self._parent,
            topology=topology,
            npus_count=npus_count,
            bandwidth=bandwidth,
            latency=latency,
        )
        self._add(item)
        return self

    def add(self, topology=None, npus_count=None, bandwidth=None, latency=None):
        # type: (Union[Literal["fullyconnected"], Literal["ring"], Literal["switch"]],int,float,float) -> AnalyticalTopologyNetwork
        """Add method that creates and returns an instance of the AnalyticalTopologyNetwork class

        TBD

        Returns: AnalyticalTopologyNetwork
        """
        item = AnalyticalTopologyNetwork(
            parent=self._parent,
            topology=topology,
            npus_count=npus_count,
            bandwidth=bandwidth,
            latency=latency,
        )
        self._add(item)
        return item


class NS3Configuration(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "network": {"type": "NS3Network"},
        "topology": {"type": "NS3Topology"},
        "logical_topology": {"type": "NS3LogicalTopology"},
        "trace": {"type": "NS3Trace"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(NS3Configuration, self).__init__()
        self._parent = parent

    @property
    def network(self):
        # type: () -> NS3Network
        """network getter

        Defines the network topology and simulation parameters for NS3-based network simulations.Defines the network topology and simulation parameters for NS3-based network simulations.Defines the network topology and simulation parameters for NS3-based network simulations.Defines the network topology and simulation parameters for NS3-based network simulations.The NS3 network configuration file.

        Returns: NS3Network
        """
        return self._get_property("network", NS3Network)

    @property
    def topology(self):
        # type: () -> NS3Topology
        """topology getter

        A choice between infragraph and ns3 nc topology, where the user can choose either infragraph or nc_topology. On choosing nc_topology, the user gets schema which allows to fill in the nc_topology values, and on choosing infragraph, the user can create infragraph from the schema which will be translated to ns3 topology at the server.A choice between infragraph and ns3 nc topology, where the user can choose either infragraph or nc_topology. On choosing nc_topology, the user gets schema which allows to fill in the nc_topology values, and on choosing infragraph, the user can create infragraph from the schema which will be translated to ns3 topology at the server.A choice between infragraph and ns3 nc topology, where the user can choose either infragraph or nc_topology. On choosing nc_topology, the user gets schema which allows to fill in the nc_topology values, and on choosing infragraph, the user can create infragraph from the schema which will be translated to ns3 topology at the server.A choice between infragraph and ns3 nc topology, where the user can choose either infragraph or nc_topology. On choosing nc_topology, the user gets schema which allows to fill in the nc_topology values, and on choosing infragraph, the user can create infragraph from the schema which will be translated to ns3 topology at the server.A choice between infragraph and native nc_topology schema where the user can choose either of the one. On choosing infragraph, the infragraph gets converted to ns3 nc topology.

        Returns: NS3Topology
        """
        return self._get_property("topology", NS3Topology)

    @property
    def logical_topology(self):
        # type: () -> NS3LogicalTopology
        """logical_topology getter

        The logical topology in the NS-3 backend is defined through the network configuration file, specifically using the "logical-dims" field. This field specifies the dimensions of the network topology as an array of strings, where each string represents the number of NPUs in that dimension.The logical topology in the NS-3 backend is defined through the network configuration file, specifically using the "logical-dims" field. This field specifies the dimensions of the network topology as an array of strings, where each string represents the number of NPUs in that dimension.The logical topology in the NS-3 backend is defined through the network configuration file, specifically using the "logical-dims" field. This field specifies the dimensions of the network topology as an array of strings, where each string represents the number of NPUs in that dimension.The logical topology in the NS-3 backend is defined through the network configuration file, specifically using the "logical-dims" field. This field specifies the dimensions of the network topology as an array of strings, where each string represents the number of NPUs in that dimension.The logical topology schema enables users to define the logical structure or dimensions of the ns3 topology, specifying how nodes and links are organized and interact within the simulated network environment.

        Returns: NS3LogicalTopology
        """
        return self._get_property("logical_topology", NS3LogicalTopology)

    @property
    def trace(self):
        # type: () -> NS3Trace
        """trace getter

        The trace file includes the unique identifiers of devices specified in the nc_topology file and serves as an input to the network configuration. This enables NS3 to generate trace data specifically for the provided device identifiers.The trace file includes the unique identifiers of devices specified in the nc_topology file and serves as an input to the network configuration. This enables NS3 to generate trace data specifically for the provided device identifiers.The trace file includes the unique identifiers of devices specified in the nc_topology file and serves as an input to the network configuration. This enables NS3 to generate trace data specifically for the provided device identifiers.The trace file includes the unique identifiers of devices specified in the nc_topology file and serves as an input to the network configuration. This enables NS3 to generate trace data specifically for the provided device identifiers.A trace identifier schema enables users to specify the trace IDs of devices for which trace data should be generated, ensuring that only the desired device traces are collected during the simulation.

        Returns: NS3Trace
        """
        return self._get_property("trace", NS3Trace)


class NS3Network(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "enable_qcn": {
            "type": int,
            "format": "int32",
            "minimum": 0,
            "maximum": 1,
        },
        "use_dynamic_pfc_threshold": {
            "type": int,
            "format": "int32",
            "minimum": 0,
            "maximum": 1,
        },
        "packet_payload_size": {
            "type": int,
            "format": "uint32",
        },
        "topology_file": {"type": str},
        "flow_file": {"type": str},
        "trace_file": {"type": str},
        "trace_output_file": {"type": str},
        "fct_output_file": {"type": str},
        "pfc_output_file": {"type": str},
        "simulator_stop_time": {
            "type": float,
            "format": "float",
        },
        "cc_mode": {
            "type": int,
            "format": "int32",
        },
        "alpha_resume_interval": {
            "type": int,
            "format": "uint32",
        },
        "rate_decrease_interval": {
            "type": int,
            "format": "uint32",
        },
        "clamp_target_rate": {
            "type": int,
            "format": "uint32",
        },
        "rp_timer": {
            "type": int,
            "format": "uint32",
        },
        "ewma_gain": {
            "type": float,
            "format": "float",
        },
        "fast_recovery_times": {
            "type": int,
            "format": "uint32",
        },
        "rate_ai": {"type": str},
        "rate_hai": {"type": str},
        "min_rate": {"type": str},
        "dctcp_rate_ai": {"type": str},
        "error_rate_per_link": {
            "type": float,
            "format": "float",
        },
        "l2_chunk_size": {
            "type": int,
            "format": "uint32",
        },
        "l2_ack_interval": {
            "type": int,
            "format": "uint32",
        },
        "l2_back_to_zero": {
            "type": int,
            "format": "int32",
            "minimum": 0,
            "maximum": 1,
        },
        "has_win": {
            "type": int,
            "format": "int32",
            "minimum": 0,
            "maximum": 1,
        },
        "global_t": {
            "type": int,
            "format": "int32",
            "minimum": 0,
            "maximum": 1,
        },
        "var_win": {
            "type": int,
            "format": "int32",
            "minimum": 0,
            "maximum": 1,
        },
        "fast_react": {
            "type": int,
            "format": "int32",
            "minimum": 0,
            "maximum": 1,
        },
        "u_target": {
            "type": float,
            "format": "float",
        },
        "mi_thresh": {
            "type": int,
            "format": "uint32",
        },
        "int_multi": {
            "type": int,
            "format": "uint32",
        },
        "multi_rate": {
            "type": int,
            "format": "int32",
            "minimum": 0,
            "maximum": 1,
        },
        "sample_feedback": {
            "type": int,
            "format": "int32",
            "minimum": 0,
            "maximum": 1,
        },
        "pint_log_base": {
            "type": float,
            "format": "float",
        },
        "pint_prob": {
            "type": float,
            "format": "float",
        },
        "rate_bound": {
            "type": int,
            "format": "int32",
            "minimum": 0,
            "maximum": 1,
        },
        "ack_high_prio": {
            "type": int,
            "format": "int32",
            "minimum": 0,
            "maximum": 1,
        },
        "link_down": {
            "type": list,
            "itemtype": int,
            "itemformat": "uint32",
        },
        "enable_trace": {
            "type": int,
            "format": "int32",
            "minimum": 0,
            "maximum": 1,
        },
        "kmax_map": {"type": str},
        "kmin_map": {"type": str},
        "pmax_map": {"type": str},
        "buffer_size": {
            "type": int,
            "format": "uint32",
        },
        "qlen_mon_file": {"type": str},
        "qlen_mon_start": {
            "type": int,
            "format": "int64",
        },
        "qlen_mon_end": {
            "type": int,
            "format": "int64",
        },
        "nic_total_pause_time": {
            "type": int,
            "format": "int32",
        },
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {
        "enable_qcn": 1,
        "use_dynamic_pfc_threshold": 1,
        "packet_payload_size": 1024,
        "topology_file": "nc-topology.txt",
        "flow_file": "flow.txt",
        "trace_file": "trace.txt",
        "trace_output_file": "trace_out.tr",
        "fct_output_file": "fct.txt",
        "pfc_output_file": "pfc.txt",
        "simulator_stop_time": 40000000000000.0,
        "cc_mode": 12,
        "alpha_resume_interval": 1,
        "rate_decrease_interval": 4,
        "clamp_target_rate": 0,
        "rp_timer": 900,
        "ewma_gain": 0.00390625,
        "fast_recovery_times": 1,
        "rate_ai": "50Mb/s",
        "rate_hai": "100Mb/s",
        "min_rate": "100Mb/s",
        "dctcp_rate_ai": "1000Mb/s",
        "error_rate_per_link": 0.0,
        "l2_chunk_size": 4000,
        "l2_ack_interval": 1,
        "l2_back_to_zero": 0,
        "has_win": 1,
        "global_t": 0,
        "var_win": 1,
        "fast_react": 1,
        "u_target": 0.95,
        "mi_thresh": 0,
        "int_multi": 1,
        "multi_rate": 0,
        "sample_feedback": 0,
        "pint_log_base": 1.05,
        "pint_prob": 1.0,
        "rate_bound": 1,
        "ack_high_prio": 0,
        "link_down": [0, 0, 0],
        "enable_trace": 1,
        "kmax_map": "6 25000000000 400 40000000000 800 100000000000 1600 200000000000 2400 400000000000 3200 2400000000000 3200",
        "kmin_map": "6 25000000000 100 40000000000 200 100000000000 400 200000000000 600 400000000000 800 2400000000000 800",
        "pmax_map": "6 25000000000 0.2 40000000000 0.2 100000000000 0.2 200000000000 0.2 400000000000 0.2 2400000000000 0.2",
        "buffer_size": 32,
        "qlen_mon_file": "qlen.txt",
        "qlen_mon_start": 0,
        "qlen_mon_end": 20000,
        "nic_total_pause_time": 0,
    }  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self,
        parent=None,
        enable_qcn=1,
        use_dynamic_pfc_threshold=1,
        packet_payload_size=1024,
        topology_file="nc-topology.txt",
        flow_file="flow.txt",
        trace_file="trace.txt",
        trace_output_file="trace_out.tr",
        fct_output_file="fct.txt",
        pfc_output_file="pfc.txt",
        simulator_stop_time=40000000000000.0,
        cc_mode=12,
        alpha_resume_interval=1,
        rate_decrease_interval=4,
        clamp_target_rate=0,
        rp_timer=900,
        ewma_gain=0.00390625,
        fast_recovery_times=1,
        rate_ai="50Mb/s",
        rate_hai="100Mb/s",
        min_rate="100Mb/s",
        dctcp_rate_ai="1000Mb/s",
        error_rate_per_link=0.0,
        l2_chunk_size=4000,
        l2_ack_interval=1,
        l2_back_to_zero=0,
        has_win=1,
        global_t=0,
        var_win=1,
        fast_react=1,
        u_target=0.95,
        mi_thresh=0,
        int_multi=1,
        multi_rate=0,
        sample_feedback=0,
        pint_log_base=1.05,
        pint_prob=1.0,
        rate_bound=1,
        ack_high_prio=0,
        link_down=[0, 0, 0],
        enable_trace=1,
        kmax_map="6 25000000000 400 40000000000 800 100000000000 1600 200000000000 2400 400000000000 3200 2400000000000 3200",
        kmin_map="6 25000000000 100 40000000000 200 100000000000 400 200000000000 600 400000000000 800 2400000000000 800",
        pmax_map="6 25000000000 0.2 40000000000 0.2 100000000000 0.2 200000000000 0.2 400000000000 0.2 2400000000000 0.2",
        buffer_size=32,
        qlen_mon_file="qlen.txt",
        qlen_mon_start=0,
        qlen_mon_end=20000,
        nic_total_pause_time=0,
    ):
        super(NS3Network, self).__init__()
        self._parent = parent
        self._set_property("enable_qcn", enable_qcn)
        self._set_property("use_dynamic_pfc_threshold", use_dynamic_pfc_threshold)
        self._set_property("packet_payload_size", packet_payload_size)
        self._set_property("topology_file", topology_file)
        self._set_property("flow_file", flow_file)
        self._set_property("trace_file", trace_file)
        self._set_property("trace_output_file", trace_output_file)
        self._set_property("fct_output_file", fct_output_file)
        self._set_property("pfc_output_file", pfc_output_file)
        self._set_property("simulator_stop_time", simulator_stop_time)
        self._set_property("cc_mode", cc_mode)
        self._set_property("alpha_resume_interval", alpha_resume_interval)
        self._set_property("rate_decrease_interval", rate_decrease_interval)
        self._set_property("clamp_target_rate", clamp_target_rate)
        self._set_property("rp_timer", rp_timer)
        self._set_property("ewma_gain", ewma_gain)
        self._set_property("fast_recovery_times", fast_recovery_times)
        self._set_property("rate_ai", rate_ai)
        self._set_property("rate_hai", rate_hai)
        self._set_property("min_rate", min_rate)
        self._set_property("dctcp_rate_ai", dctcp_rate_ai)
        self._set_property("error_rate_per_link", error_rate_per_link)
        self._set_property("l2_chunk_size", l2_chunk_size)
        self._set_property("l2_ack_interval", l2_ack_interval)
        self._set_property("l2_back_to_zero", l2_back_to_zero)
        self._set_property("has_win", has_win)
        self._set_property("global_t", global_t)
        self._set_property("var_win", var_win)
        self._set_property("fast_react", fast_react)
        self._set_property("u_target", u_target)
        self._set_property("mi_thresh", mi_thresh)
        self._set_property("int_multi", int_multi)
        self._set_property("multi_rate", multi_rate)
        self._set_property("sample_feedback", sample_feedback)
        self._set_property("pint_log_base", pint_log_base)
        self._set_property("pint_prob", pint_prob)
        self._set_property("rate_bound", rate_bound)
        self._set_property("ack_high_prio", ack_high_prio)
        self._set_property("link_down", link_down)
        self._set_property("enable_trace", enable_trace)
        self._set_property("kmax_map", kmax_map)
        self._set_property("kmin_map", kmin_map)
        self._set_property("pmax_map", pmax_map)
        self._set_property("buffer_size", buffer_size)
        self._set_property("qlen_mon_file", qlen_mon_file)
        self._set_property("qlen_mon_start", qlen_mon_start)
        self._set_property("qlen_mon_end", qlen_mon_end)
        self._set_property("nic_total_pause_time", nic_total_pause_time)

    def set(
        self,
        enable_qcn=None,
        use_dynamic_pfc_threshold=None,
        packet_payload_size=None,
        topology_file=None,
        flow_file=None,
        trace_file=None,
        trace_output_file=None,
        fct_output_file=None,
        pfc_output_file=None,
        simulator_stop_time=None,
        cc_mode=None,
        alpha_resume_interval=None,
        rate_decrease_interval=None,
        clamp_target_rate=None,
        rp_timer=None,
        ewma_gain=None,
        fast_recovery_times=None,
        rate_ai=None,
        rate_hai=None,
        min_rate=None,
        dctcp_rate_ai=None,
        error_rate_per_link=None,
        l2_chunk_size=None,
        l2_ack_interval=None,
        l2_back_to_zero=None,
        has_win=None,
        global_t=None,
        var_win=None,
        fast_react=None,
        u_target=None,
        mi_thresh=None,
        int_multi=None,
        multi_rate=None,
        sample_feedback=None,
        pint_log_base=None,
        pint_prob=None,
        rate_bound=None,
        ack_high_prio=None,
        link_down=None,
        enable_trace=None,
        kmax_map=None,
        kmin_map=None,
        pmax_map=None,
        buffer_size=None,
        qlen_mon_file=None,
        qlen_mon_start=None,
        qlen_mon_end=None,
        nic_total_pause_time=None,
    ):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def enable_qcn(self):
        # type: () -> int
        """enable_qcn getter

        0: disable, 1: enable..

        Returns: int
        """
        return self._get_property("enable_qcn")

    @enable_qcn.setter
    def enable_qcn(self, value):
        """enable_qcn setter

        0: disable, 1: enable..

        value: int
        """
        self._set_property("enable_qcn", value)

    @property
    def use_dynamic_pfc_threshold(self):
        # type: () -> int
        """use_dynamic_pfc_threshold getter

        0: disable, 1: enable..

        Returns: int
        """
        return self._get_property("use_dynamic_pfc_threshold")

    @use_dynamic_pfc_threshold.setter
    def use_dynamic_pfc_threshold(self, value):
        """use_dynamic_pfc_threshold setter

        0: disable, 1: enable..

        value: int
        """
        self._set_property("use_dynamic_pfc_threshold", value)

    @property
    def packet_payload_size(self):
        # type: () -> int
        """packet_payload_size getter

        packet size (bytes)..

        Returns: int
        """
        return self._get_property("packet_payload_size")

    @packet_payload_size.setter
    def packet_payload_size(self, value):
        """packet_payload_size setter

        packet size (bytes)..

        value: int
        """
        self._set_property("packet_payload_size", value)

    @property
    def topology_file(self):
        # type: () -> str
        """topology_file getter

        input file: topoology..

        Returns: str
        """
        return self._get_property("topology_file")

    @topology_file.setter
    def topology_file(self, value):
        """topology_file setter

        input file: topoology..

        value: str
        """
        self._set_property("topology_file", value)

    @property
    def flow_file(self):
        # type: () -> str
        """flow_file getter

        input file: flow to generate..

        Returns: str
        """
        return self._get_property("flow_file")

    @flow_file.setter
    def flow_file(self, value):
        """flow_file setter

        input file: flow to generate..

        value: str
        """
        self._set_property("flow_file", value)

    @property
    def trace_file(self):
        # type: () -> str
        """trace_file getter

        input file: nodes to monitor packet-level events (enqu, dequ, pfc, etc.), will be dumped to TRACE_OUTPUT_FILE..

        Returns: str
        """
        return self._get_property("trace_file")

    @trace_file.setter
    def trace_file(self, value):
        """trace_file setter

        input file: nodes to monitor packet-level events (enqu, dequ, pfc, etc.), will be dumped to TRACE_OUTPUT_FILE..

        value: str
        """
        self._set_property("trace_file", value)

    @property
    def trace_output_file(self):
        # type: () -> str
        """trace_output_file getter

        output file: packet-level events (enqu, dequ, pfc, etc.)..

        Returns: str
        """
        return self._get_property("trace_output_file")

    @trace_output_file.setter
    def trace_output_file(self, value):
        """trace_output_file setter

        output file: packet-level events (enqu, dequ, pfc, etc.)..

        value: str
        """
        self._set_property("trace_output_file", value)

    @property
    def fct_output_file(self):
        # type: () -> str
        """fct_output_file getter

        output file: flow completion time of different flows..

        Returns: str
        """
        return self._get_property("fct_output_file")

    @fct_output_file.setter
    def fct_output_file(self, value):
        """fct_output_file setter

        output file: flow completion time of different flows..

        value: str
        """
        self._set_property("fct_output_file", value)

    @property
    def pfc_output_file(self):
        # type: () -> str
        """pfc_output_file getter

        output file: result of PFC..

        Returns: str
        """
        return self._get_property("pfc_output_file")

    @pfc_output_file.setter
    def pfc_output_file(self, value):
        """pfc_output_file setter

        output file: result of PFC..

        value: str
        """
        self._set_property("pfc_output_file", value)

    @property
    def simulator_stop_time(self):
        # type: () -> float
        """simulator_stop_time getter

        simulation stop time..

        Returns: float
        """
        return self._get_property("simulator_stop_time")

    @simulator_stop_time.setter
    def simulator_stop_time(self, value):
        """simulator_stop_time setter

        simulation stop time..

        value: float
        """
        self._set_property("simulator_stop_time", value)

    @property
    def cc_mode(self):
        # type: () -> int
        """cc_mode getter

        Specifying different CC. 1: DCQCN, 3: HPCC, 7: TIMELY, 8: DCTCP, 10: HPCC-PINT..

        Returns: int
        """
        return self._get_property("cc_mode")

    @cc_mode.setter
    def cc_mode(self, value):
        """cc_mode setter

        Specifying different CC. 1: DCQCN, 3: HPCC, 7: TIMELY, 8: DCTCP, 10: HPCC-PINT..

        value: int
        """
        self._set_property("cc_mode", value)

    @property
    def alpha_resume_interval(self):
        # type: () -> int
        """alpha_resume_interval getter

        for DCQCN: the interval of update alpha..

        Returns: int
        """
        return self._get_property("alpha_resume_interval")

    @alpha_resume_interval.setter
    def alpha_resume_interval(self, value):
        """alpha_resume_interval setter

        for DCQCN: the interval of update alpha..

        value: int
        """
        self._set_property("alpha_resume_interval", value)

    @property
    def rate_decrease_interval(self):
        # type: () -> int
        """rate_decrease_interval getter

        for DCQCN: the interval of rate decrease..

        Returns: int
        """
        return self._get_property("rate_decrease_interval")

    @rate_decrease_interval.setter
    def rate_decrease_interval(self, value):
        """rate_decrease_interval setter

        for DCQCN: the interval of rate decrease..

        value: int
        """
        self._set_property("rate_decrease_interval", value)

    @property
    def clamp_target_rate(self):
        # type: () -> int
        """clamp_target_rate getter

        for DCQCN: whether to reduce target rate upon consecutive rate decrease..

        Returns: int
        """
        return self._get_property("clamp_target_rate")

    @clamp_target_rate.setter
    def clamp_target_rate(self, value):
        """clamp_target_rate setter

        for DCQCN: whether to reduce target rate upon consecutive rate decrease..

        value: int
        """
        self._set_property("clamp_target_rate", value)

    @property
    def rp_timer(self):
        # type: () -> int
        """rp_timer getter

        for DCQCN: the interval of rate increase..

        Returns: int
        """
        return self._get_property("rp_timer")

    @rp_timer.setter
    def rp_timer(self, value):
        """rp_timer setter

        for DCQCN: the interval of rate increase..

        value: int
        """
        self._set_property("rp_timer", value)

    @property
    def ewma_gain(self):
        # type: () -> float
        """ewma_gain getter

        for DCQCN and DCTCP: the gain of EWMA..

        Returns: float
        """
        return self._get_property("ewma_gain")

    @ewma_gain.setter
    def ewma_gain(self, value):
        """ewma_gain setter

        for DCQCN and DCTCP: the gain of EWMA..

        value: float
        """
        self._set_property("ewma_gain", value)

    @property
    def fast_recovery_times(self):
        # type: () -> int
        """fast_recovery_times getter

        for DCQCN: number of times of increase for fast recovery..

        Returns: int
        """
        return self._get_property("fast_recovery_times")

    @fast_recovery_times.setter
    def fast_recovery_times(self, value):
        """fast_recovery_times setter

        for DCQCN: number of times of increase for fast recovery..

        value: int
        """
        self._set_property("fast_recovery_times", value)

    @property
    def rate_ai(self):
        # type: () -> str
        """rate_ai getter

        Additive increase (not for DCTCP)..

        Returns: str
        """
        return self._get_property("rate_ai")

    @rate_ai.setter
    def rate_ai(self, value):
        """rate_ai setter

        Additive increase (not for DCTCP)..

        value: str
        """
        self._set_property("rate_ai", value)

    @property
    def rate_hai(self):
        # type: () -> str
        """rate_hai getter

        Hyper additive increase..

        Returns: str
        """
        return self._get_property("rate_hai")

    @rate_hai.setter
    def rate_hai(self, value):
        """rate_hai setter

        Hyper additive increase..

        value: str
        """
        self._set_property("rate_hai", value)

    @property
    def min_rate(self):
        # type: () -> str
        """min_rate getter

        Minimum rate..

        Returns: str
        """
        return self._get_property("min_rate")

    @min_rate.setter
    def min_rate(self, value):
        """min_rate setter

        Minimum rate..

        value: str
        """
        self._set_property("min_rate", value)

    @property
    def dctcp_rate_ai(self):
        # type: () -> str
        """dctcp_rate_ai getter

        Additive increase for DCTCP..

        Returns: str
        """
        return self._get_property("dctcp_rate_ai")

    @dctcp_rate_ai.setter
    def dctcp_rate_ai(self, value):
        """dctcp_rate_ai setter

        Additive increase for DCTCP..

        value: str
        """
        self._set_property("dctcp_rate_ai", value)

    @property
    def error_rate_per_link(self):
        # type: () -> float
        """error_rate_per_link getter

        Error rate of each link..

        Returns: float
        """
        return self._get_property("error_rate_per_link")

    @error_rate_per_link.setter
    def error_rate_per_link(self, value):
        """error_rate_per_link setter

        Error rate of each link..

        value: float
        """
        self._set_property("error_rate_per_link", value)

    @property
    def l2_chunk_size(self):
        # type: () -> int
        """l2_chunk_size getter

        for DCQCN: chunk size..

        Returns: int
        """
        return self._get_property("l2_chunk_size")

    @l2_chunk_size.setter
    def l2_chunk_size(self, value):
        """l2_chunk_size setter

        for DCQCN: chunk size..

        value: int
        """
        self._set_property("l2_chunk_size", value)

    @property
    def l2_ack_interval(self):
        # type: () -> int
        """l2_ack_interval getter

        number of packets between ACK generation, means per packet..

        Returns: int
        """
        return self._get_property("l2_ack_interval")

    @l2_ack_interval.setter
    def l2_ack_interval(self, value):
        """l2_ack_interval setter

        number of packets between ACK generation, means per packet..

        value: int
        """
        self._set_property("l2_ack_interval", value)

    @property
    def l2_back_to_zero(self):
        # type: () -> int
        """l2_back_to_zero getter

        0: go-back-0, 1: go-back-N..

        Returns: int
        """
        return self._get_property("l2_back_to_zero")

    @l2_back_to_zero.setter
    def l2_back_to_zero(self, value):
        """l2_back_to_zero setter

        0: go-back-0, 1: go-back-N..

        value: int
        """
        self._set_property("l2_back_to_zero", value)

    @property
    def has_win(self):
        # type: () -> int
        """has_win getter

        0: no window, 1: has window..

        Returns: int
        """
        return self._get_property("has_win")

    @has_win.setter
    def has_win(self, value):
        """has_win setter

        0: no window, 1: has window..

        value: int
        """
        self._set_property("has_win", value)

    @property
    def global_t(self):
        # type: () -> int
        """global_t getter

        0: different server pairs use their own RTT as T, 1: use the max base RTT as the global T..

        Returns: int
        """
        return self._get_property("global_t")

    @global_t.setter
    def global_t(self, value):
        """global_t setter

        0: different server pairs use their own RTT as T, 1: use the max base RTT as the global T..

        value: int
        """
        self._set_property("global_t", value)

    @property
    def var_win(self):
        # type: () -> int
        """var_win getter

        0: fixed size of window (alwasy maximum), 1: variable window..

        Returns: int
        """
        return self._get_property("var_win")

    @var_win.setter
    def var_win(self, value):
        """var_win setter

        0: fixed size of window (alwasy maximum), 1: variable window..

        value: int
        """
        self._set_property("var_win", value)

    @property
    def fast_react(self):
        # type: () -> int
        """fast_react getter

        0: react once per RTT, 1: react per ACK..

        Returns: int
        """
        return self._get_property("fast_react")

    @fast_react.setter
    def fast_react(self, value):
        """fast_react setter

        0: react once per RTT, 1: react per ACK..

        value: int
        """
        self._set_property("fast_react", value)

    @property
    def u_target(self):
        # type: () -> float
        """u_target getter

        for HPCC: eta in paper..

        Returns: float
        """
        return self._get_property("u_target")

    @u_target.setter
    def u_target(self, value):
        """u_target setter

        for HPCC: eta in paper..

        value: float
        """
        self._set_property("u_target", value)

    @property
    def mi_thresh(self):
        # type: () -> int
        """mi_thresh getter

        for HPCC: eta in paper..

        Returns: int
        """
        return self._get_property("mi_thresh")

    @mi_thresh.setter
    def mi_thresh(self, value):
        """mi_thresh setter

        for HPCC: eta in paper..

        value: int
        """
        self._set_property("mi_thresh", value)

    @property
    def int_multi(self):
        # type: () -> int
        """int_multi getter

        for HPCC: multiply the unit of txBytes and qLen in INT header..

        Returns: int
        """
        return self._get_property("int_multi")

    @int_multi.setter
    def int_multi(self, value):
        """int_multi setter

        for HPCC: multiply the unit of txBytes and qLen in INT header..

        value: int
        """
        self._set_property("int_multi", value)

    @property
    def multi_rate(self):
        # type: () -> int
        """multi_rate getter

        for HPCC: 0: one rate for all hops, 1: one rate per hop..

        Returns: int
        """
        return self._get_property("multi_rate")

    @multi_rate.setter
    def multi_rate(self, value):
        """multi_rate setter

        for HPCC: 0: one rate for all hops, 1: one rate per hop..

        value: int
        """
        self._set_property("multi_rate", value)

    @property
    def sample_feedback(self):
        # type: () -> int
        """sample_feedback getter

        for HPCC: 0: get INT per packet, 1: get INT once per RTT or qlen>0..

        Returns: int
        """
        return self._get_property("sample_feedback")

    @sample_feedback.setter
    def sample_feedback(self, value):
        """sample_feedback setter

        for HPCC: 0: get INT per packet, 1: get INT once per RTT or qlen>0..

        value: int
        """
        self._set_property("sample_feedback", value)

    @property
    def pint_log_base(self):
        # type: () -> float
        """pint_log_base getter

        for HPCC-PINT: the base of the log encoding, equals to (1+epsilon)^2 where epsilon is the error bound. 1.05 corresponds to epsilon=0.025..

        Returns: float
        """
        return self._get_property("pint_log_base")

    @pint_log_base.setter
    def pint_log_base(self, value):
        """pint_log_base setter

        for HPCC-PINT: the base of the log encoding, equals to (1+epsilon)^2 where epsilon is the error bound. 1.05 corresponds to epsilon=0.025..

        value: float
        """
        self._set_property("pint_log_base", value)

    @property
    def pint_prob(self):
        # type: () -> float
        """pint_prob getter

        for HPCC-PINT: the base of the log encoding, equals to (1+epsilon)^2 where epsilon is the error bound. 1.05 corresponds to epsilon=0.025..

        Returns: float
        """
        return self._get_property("pint_prob")

    @pint_prob.setter
    def pint_prob(self, value):
        """pint_prob setter

        for HPCC-PINT: the base of the log encoding, equals to (1+epsilon)^2 where epsilon is the error bound. 1.05 corresponds to epsilon=0.025..

        value: float
        """
        self._set_property("pint_prob", value)

    @property
    def rate_bound(self):
        # type: () -> int
        """rate_bound getter

        0: no rate limitor, 1: use rate limitor..

        Returns: int
        """
        return self._get_property("rate_bound")

    @rate_bound.setter
    def rate_bound(self, value):
        """rate_bound setter

        0: no rate limitor, 1: use rate limitor..

        value: int
        """
        self._set_property("rate_bound", value)

    @property
    def ack_high_prio(self):
        # type: () -> int
        """ack_high_prio getter

        0: ACK has same priority with data packet, 1: prioritize ACK..

        Returns: int
        """
        return self._get_property("ack_high_prio")

    @ack_high_prio.setter
    def ack_high_prio(self, value):
        """ack_high_prio setter

        0: ACK has same priority with data packet, 1: prioritize ACK..

        value: int
        """
        self._set_property("ack_high_prio", value)

    @property
    def link_down(self):
        # type: () -> List[int]
        """link_down getter

        a c: take down link between and at time a. 0 mean no link down..

        Returns: List[int]
        """
        return self._get_property("link_down")

    @link_down.setter
    def link_down(self, value):
        """link_down setter

        a c: take down link between and at time a. 0 mean no link down..

        value: List[int]
        """
        self._set_property("link_down", value)

    @property
    def enable_trace(self):
        # type: () -> int
        """enable_trace getter

        dump packet-level events or not..

        Returns: int
        """
        return self._get_property("enable_trace")

    @enable_trace.setter
    def enable_trace(self, value):
        """enable_trace setter

        dump packet-level events or not..

        value: int
        """
        self._set_property("enable_trace", value)

    @property
    def kmax_map(self):
        # type: () -> str
        """kmax_map getter

        a map from link bandwidth to ECN threshold kmax..

        Returns: str
        """
        return self._get_property("kmax_map")

    @kmax_map.setter
    def kmax_map(self, value):
        """kmax_map setter

        a map from link bandwidth to ECN threshold kmax..

        value: str
        """
        self._set_property("kmax_map", value)

    @property
    def kmin_map(self):
        # type: () -> str
        """kmin_map getter

        a map from link bandwidth to ECN threshold kmin..

        Returns: str
        """
        return self._get_property("kmin_map")

    @kmin_map.setter
    def kmin_map(self, value):
        """kmin_map setter

        a map from link bandwidth to ECN threshold kmin..

        value: str
        """
        self._set_property("kmin_map", value)

    @property
    def pmax_map(self):
        # type: () -> str
        """pmax_map getter

        a map from link bandwidth to ECN threshold pmax..

        Returns: str
        """
        return self._get_property("pmax_map")

    @pmax_map.setter
    def pmax_map(self, value):
        """pmax_map setter

        a map from link bandwidth to ECN threshold pmax..

        value: str
        """
        self._set_property("pmax_map", value)

    @property
    def buffer_size(self):
        # type: () -> int
        """buffer_size getter

        buffer size per switch..

        Returns: int
        """
        return self._get_property("buffer_size")

    @buffer_size.setter
    def buffer_size(self, value):
        """buffer_size setter

        buffer size per switch..

        value: int
        """
        self._set_property("buffer_size", value)

    @property
    def qlen_mon_file(self):
        # type: () -> str
        """qlen_mon_file getter

        buffer size per switch..

        Returns: str
        """
        return self._get_property("qlen_mon_file")

    @qlen_mon_file.setter
    def qlen_mon_file(self, value):
        """qlen_mon_file setter

        buffer size per switch..

        value: str
        """
        self._set_property("qlen_mon_file", value)

    @property
    def qlen_mon_start(self):
        # type: () -> int
        """qlen_mon_start getter

        start time of dumping qlen..

        Returns: int
        """
        return self._get_property("qlen_mon_start")

    @qlen_mon_start.setter
    def qlen_mon_start(self, value):
        """qlen_mon_start setter

        start time of dumping qlen..

        value: int
        """
        self._set_property("qlen_mon_start", value)

    @property
    def qlen_mon_end(self):
        # type: () -> int
        """qlen_mon_end getter

        end time of dumping qlen..

        Returns: int
        """
        return self._get_property("qlen_mon_end")

    @qlen_mon_end.setter
    def qlen_mon_end(self, value):
        """qlen_mon_end setter

        end time of dumping qlen..

        value: int
        """
        self._set_property("qlen_mon_end", value)

    @property
    def nic_total_pause_time(self):
        # type: () -> int
        """nic_total_pause_time getter

        nic pause time..

        Returns: int
        """
        return self._get_property("nic_total_pause_time")

    @nic_total_pause_time.setter
    def nic_total_pause_time(self, value):
        """nic_total_pause_time setter

        nic pause time..

        value: int
        """
        self._set_property("nic_total_pause_time", value)


class NS3Topology(OpenApiObject):
    __slots__ = ("_parent", "_choice")

    _TYPES = {
        "choice": {
            "type": str,
            "enum": [
                "nc_topology",
                "infragraph",
            ],
        },
        "nc_topology": {"type": "NCTopology"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    NC_TOPOLOGY = "nc_topology"  # type: str
    INFRAGRAPH = "infragraph"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, choice=None):
        super(NS3Topology, self).__init__()
        self._parent = parent
        if (
            "choice" in self._DEFAULTS
            and choice is None
            and self._DEFAULTS["choice"] in self._TYPES
        ):
            getattr(self, self._DEFAULTS["choice"])
        else:
            self._set_property("choice", choice)

    @property
    def nc_topology(self):
        # type: () -> NCTopology
        """Factory property that returns an instance of the NCTopology class

        NC Topology Schema

        Returns: NCTopology
        """
        return self._get_property("nc_topology", NCTopology, self, "nc_topology")

    @property
    def choice(self):
        # type: () -> Union[Literal["infragraph"], Literal["nc_topology"]]
        """choice getter

        Specifies the choice between versions of infragraph.

        Returns: Union[Literal["infragraph"], Literal["nc_topology"]]
        """
        return self._get_property("choice")

    @choice.setter
    def choice(self, value):
        """choice setter

        Specifies the choice between versions of infragraph.

        value: Union[Literal["infragraph"], Literal["nc_topology"]]
        """
        self._set_property("choice", value)


class NCTopology(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "total_nodes": {
            "type": int,
            "format": "int32",
        },
        "total_switches": {
            "type": int,
            "format": "int32",
        },
        "total_links": {
            "type": int,
            "format": "int32",
        },
        "switch_ids": {
            "type": list,
            "itemtype": int,
            "itemformat": "int32",
            "minimum": 1,
        },
        "connections": {"type": "NCTopologyConnectionIter"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self,
        parent=None,
        total_nodes=None,
        total_switches=None,
        total_links=None,
        switch_ids=None,
    ):
        super(NCTopology, self).__init__()
        self._parent = parent
        self._set_property("total_nodes", total_nodes)
        self._set_property("total_switches", total_switches)
        self._set_property("total_links", total_links)
        self._set_property("switch_ids", switch_ids)

    def set(
        self, total_nodes=None, total_switches=None, total_links=None, switch_ids=None
    ):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def total_nodes(self):
        # type: () -> int
        """total_nodes getter

        The total number of nodes total gpus switches.

        Returns: int
        """
        return self._get_property("total_nodes")

    @total_nodes.setter
    def total_nodes(self, value):
        """total_nodes setter

        The total number of nodes total gpus switches.

        value: int
        """
        self._set_property("total_nodes", value)

    @property
    def total_switches(self):
        # type: () -> int
        """total_switches getter

        The total number of switches.

        Returns: int
        """
        return self._get_property("total_switches")

    @total_switches.setter
    def total_switches(self, value):
        """total_switches setter

        The total number of switches.

        value: int
        """
        self._set_property("total_switches", value)

    @property
    def total_links(self):
        # type: () -> int
        """total_links getter

        The total number of links.

        Returns: int
        """
        return self._get_property("total_links")

    @total_links.setter
    def total_links(self, value):
        """total_links setter

        The total number of links.

        value: int
        """
        self._set_property("total_links", value)

    @property
    def switch_ids(self):
        # type: () -> List[int]
        """switch_ids getter

        A list containing all unique switch identifiers.

        Returns: List[int]
        """
        return self._get_property("switch_ids")

    @switch_ids.setter
    def switch_ids(self, value):
        """switch_ids setter

        A list containing all unique switch identifiers.

        value: List[int]
        """
        self._set_property("switch_ids", value)

    @property
    def connections(self):
        # type: () -> NCTopologyConnectionIter
        """connections getter

        Holds collection of connection entries, representing multiple links between sources and destinations.

        Returns: NCTopologyConnectionIter
        """
        return self._get_property(
            "connections", NCTopologyConnectionIter, self._parent, self._choice
        )


class NCTopologyConnection(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "source_index": {
            "type": int,
            "format": "uint32",
        },
        "destination_index": {
            "type": int,
            "format": "uint32",
        },
        "bandwidth": {"type": str},
        "latency": {"type": str},
        "error_rate": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self,
        parent=None,
        source_index=None,
        destination_index=None,
        bandwidth=None,
        latency=None,
        error_rate=None,
    ):
        super(NCTopologyConnection, self).__init__()
        self._parent = parent
        self._set_property("source_index", source_index)
        self._set_property("destination_index", destination_index)
        self._set_property("bandwidth", bandwidth)
        self._set_property("latency", latency)
        self._set_property("error_rate", error_rate)

    def set(
        self,
        source_index=None,
        destination_index=None,
        bandwidth=None,
        latency=None,
        error_rate=None,
    ):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def source_index(self):
        # type: () -> int
        """source_index getter

        The index of the source node for this connection.

        Returns: int
        """
        return self._get_property("source_index")

    @source_index.setter
    def source_index(self, value):
        """source_index setter

        The index of the source node for this connection.

        value: int
        """
        self._set_property("source_index", value)

    @property
    def destination_index(self):
        # type: () -> int
        """destination_index getter

        The index of the destination node for this connection.

        Returns: int
        """
        return self._get_property("destination_index")

    @destination_index.setter
    def destination_index(self, value):
        """destination_index setter

        The index of the destination node for this connection.

        value: int
        """
        self._set_property("destination_index", value)

    @property
    def bandwidth(self):
        # type: () -> str
        """bandwidth getter

        The maximum data transfer capacity of the connection (e.g., in Gbps). Example 100Gbps.

        Returns: str
        """
        return self._get_property("bandwidth")

    @bandwidth.setter
    def bandwidth(self, value):
        """bandwidth setter

        The maximum data transfer capacity of the connection (e.g., in Gbps). Example 100Gbps.

        value: str
        """
        self._set_property("bandwidth", value)

    @property
    def latency(self):
        # type: () -> str
        """latency getter

        The communication delay associated with the connection, typically measured in milliseconds. Example 0.0005ms.

        Returns: str
        """
        return self._get_property("latency")

    @latency.setter
    def latency(self, value):
        """latency setter

        The communication delay associated with the connection, typically measured in milliseconds. Example 0.0005ms.

        value: str
        """
        self._set_property("latency", value)

    @property
    def error_rate(self):
        # type: () -> str
        """error_rate getter

        The probability of packet errors occurring over the connection.

        Returns: str
        """
        return self._get_property("error_rate")

    @error_rate.setter
    def error_rate(self, value):
        """error_rate setter

        The probability of packet errors occurring over the connection.

        value: str
        """
        self._set_property("error_rate", value)


class NCTopologyConnectionIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(NCTopologyConnectionIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[NCTopologyConnection]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> NCTopologyConnectionIter
        return self._iter()

    def __next__(self):
        # type: () -> NCTopologyConnection
        return self._next()

    def next(self):
        # type: () -> NCTopologyConnection
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, NCTopologyConnection):
            raise Exception("Item is not an instance of NCTopologyConnection")

    def connection(
        self,
        source_index=None,
        destination_index=None,
        bandwidth=None,
        latency=None,
        error_rate=None,
    ):
        # type: (int,int,str,str,str) -> NCTopologyConnectionIter
        """Factory method that creates an instance of the NCTopologyConnection class

        Represents connection entry, including source index, destination index, bandwidth, error rate, and latency.

        Returns: NCTopologyConnectionIter
        """
        item = NCTopologyConnection(
            parent=self._parent,
            source_index=source_index,
            destination_index=destination_index,
            bandwidth=bandwidth,
            latency=latency,
            error_rate=error_rate,
        )
        self._add(item)
        return self

    def add(
        self,
        source_index=None,
        destination_index=None,
        bandwidth=None,
        latency=None,
        error_rate=None,
    ):
        # type: (int,int,str,str,str) -> NCTopologyConnection
        """Add method that creates and returns an instance of the NCTopologyConnection class

        Represents connection entry, including source index, destination index, bandwidth, error rate, and latency.

        Returns: NCTopologyConnection
        """
        item = NCTopologyConnection(
            parent=self._parent,
            source_index=source_index,
            destination_index=destination_index,
            bandwidth=bandwidth,
            latency=latency,
            error_rate=error_rate,
        )
        self._add(item)
        return item


class NS3LogicalTopology(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "logical_dimensions": {
            "type": list,
            "itemtype": int,
            "itemformat": "uint32",
        },
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, logical_dimensions=None):
        super(NS3LogicalTopology, self).__init__()
        self._parent = parent
        self._set_property("logical_dimensions", logical_dimensions)

    def set(self, logical_dimensions=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def logical_dimensions(self):
        # type: () -> List[int]
        """logical_dimensions getter

        The NS-3 logical topology configuration file serves as blueprint for defining the high-level arrangement of network elements in an NS3 simulation. Provided as JSON file, it primarily features "logical-dims" field, which specifies the network’s dimensional structure by listing the number of NPUs (processing units) in each dimension as an array of strings.

        Returns: List[int]
        """
        return self._get_property("logical_dimensions")

    @logical_dimensions.setter
    def logical_dimensions(self, value):
        """logical_dimensions setter

        The NS-3 logical topology configuration file serves as blueprint for defining the high-level arrangement of network elements in an NS3 simulation. Provided as JSON file, it primarily features "logical-dims" field, which specifies the network’s dimensional structure by listing the number of NPUs (processing units) in each dimension as an array of strings.

        value: List[int]
        """
        self._set_property("logical_dimensions", value)


class NS3Trace(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "trace_ids": {
            "type": list,
            "itemtype": int,
            "itemformat": "uint32",
        },
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, trace_ids=None):
        super(NS3Trace, self).__init__()
        self._parent = parent
        self._set_property("trace_ids", trace_ids)

    def set(self, trace_ids=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def trace_ids(self):
        # type: () -> List[int]
        """trace_ids getter

        An array of all the device identifiers.

        Returns: List[int]
        """
        return self._get_property("trace_ids")

    @trace_ids.setter
    def trace_ids(self, value):
        """trace_ids setter

        An array of all the device identifiers.

        value: List[int]
        """
        self._set_property("trace_ids", value)


class HTSimConfiguration(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "htsim_protocol": {"type": "HTSimProtocol"},
        "topology": {"type": "HTSimTopologyOptions"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(HTSimConfiguration, self).__init__()
        self._parent = parent

    @property
    def htsim_protocol(self):
        # type: () -> HTSimProtocol
        """htsim_protocol getter

        The network protocol required to run simulation.

        Returns: HTSimProtocol
        """
        return self._get_property("htsim_protocol", HTSimProtocol)

    @property
    def topology(self):
        # type: () -> HTSimTopologyOptions
        """topology getter

        Provides choice between infragraph and HTSim network configuration with topology. If HTSim topology is selected, users can define analytical network configurations or choose HTSim-specific topologies such as fat-tree or dragonfly from the schema. If infragraph is selected, users can provide an infragraph from the global configuration, which the server will translate into an HTSim network configuration and topology.Provides choice between infragraph and HTSim network configuration with topology. If HTSim topology is selected, users can define analytical network configurations or choose HTSim-specific topologies such as fat-tree or dragonfly from the schema. If infragraph is selected, users can provide an infragraph from the global configuration, which the server will translate into an HTSim network configuration and topology.Provides choice between infragraph and HTSim network configuration with topology. If HTSim topology is selected, users can define analytical network configurations or choose HTSim-specific topologies such as fat-tree or dragonfly from the schema. If infragraph is selected, users can provide an infragraph from the global configuration, which the server will translate into an HTSim network configuration and topology.Provides choice between infragraph and HTSim network configuration with topology. If HTSim topology is selected, users can define analytical network configurations or choose HTSim-specific topologies such as fat-tree or dragonfly from the schema. If infragraph is selected, users can provide an infragraph from the global configuration, which the server will translate into an HTSim network configuration and topology.HTSim topology a choice between infragraph and HTSim network and topology configuration.

        Returns: HTSimTopologyOptions
        """
        return self._get_property("topology", HTSimTopologyOptions)


class HTSimProtocol(OpenApiObject):
    __slots__ = ("_parent", "_choice")

    _TYPES = {
        "choice": {
            "type": str,
            "enum": [
                "tcp",
            ],
        },
        "tcp": {"type": "HTSimProtocolTcp"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    TCP = "tcp"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, choice=None):
        super(HTSimProtocol, self).__init__()
        self._parent = parent
        if (
            "choice" in self._DEFAULTS
            and choice is None
            and self._DEFAULTS["choice"] in self._TYPES
        ):
            getattr(self, self._DEFAULTS["choice"])
        else:
            self._set_property("choice", choice)

    @property
    def tcp(self):
        # type: () -> HTSimProtocolTcp
        """Factory property that returns an instance of the HTSimProtocolTcp class

        Enables users to define configurable TCP schema for HTSim, allowing selection of the specific TCP protocol variant (such as UNCOUPLED, EPSILON, and others) to be simulated. The schema also lets users specify the associated network topology file that dictates the structure and path layout for the simulation. This flexible configuration supports in-depth experimentation with different TCP behaviors and network topologies within HTSim.

        Returns: HTSimProtocolTcp
        """
        return self._get_property("tcp", HTSimProtocolTcp, self, "tcp")

    @property
    def choice(self):
        # type: () -> Union[Literal["tcp"]]
        """choice getter

        The type of protocol backend: tcp, roce, etc.

        Returns: Union[Literal["tcp"]]
        """
        return self._get_property("choice")

    @choice.setter
    def choice(self, value):
        """choice setter

        The type of protocol backend: tcp, roce, etc.

        value: Union[Literal["tcp"]]
        """
        self._set_property("choice", value)


class HTSimProtocolTcp(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "o": {"type": str},
        "sub": {"type": str},
        "nodes": {"type": str},
        "tcp_protocol": {
            "type": str,
            "enum": [
                "COUPLED_EPSILON",
                "COUPLED_INC",
                "COUPLED_SCALABLE_TCP",
                "COUPLED_TCP",
                "UNCOUPLED",
            ],
        },
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    COUPLED_EPSILON = "COUPLED_EPSILON"  # type: str
    COUPLED_INC = "COUPLED_INC"  # type: str
    COUPLED_SCALABLE_TCP = "COUPLED_SCALABLE_TCP"  # type: str
    COUPLED_TCP = "COUPLED_TCP"  # type: str
    UNCOUPLED = "UNCOUPLED"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, o=None, sub=None, nodes=None, tcp_protocol=None):
        super(HTSimProtocolTcp, self).__init__()
        self._parent = parent
        self._set_property("o", o)
        self._set_property("sub", sub)
        self._set_property("nodes", nodes)
        self._set_property("tcp_protocol", tcp_protocol)

    def set(self, o=None, sub=None, nodes=None, tcp_protocol=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def o(self):
        # type: () -> str
        """o getter

        TBD

        Returns: str
        """
        return self._get_property("o")

    @o.setter
    def o(self, value):
        """o setter

        TBD

        value: str
        """
        self._set_property("o", value)

    @property
    def sub(self):
        # type: () -> str
        """sub getter

        TBD

        Returns: str
        """
        return self._get_property("sub")

    @sub.setter
    def sub(self, value):
        """sub setter

        TBD

        value: str
        """
        self._set_property("sub", value)

    @property
    def nodes(self):
        # type: () -> str
        """nodes getter

        TBD

        Returns: str
        """
        return self._get_property("nodes")

    @nodes.setter
    def nodes(self, value):
        """nodes setter

        TBD

        value: str
        """
        self._set_property("nodes", value)

    @property
    def tcp_protocol(self):
        # type: () -> Union[Literal["COUPLED_EPSILON"], Literal["COUPLED_INC"], Literal["COUPLED_SCALABLE_TCP"], Literal["COUPLED_TCP"], Literal["UNCOUPLED"]]
        """tcp_protocol getter

        Specifies the TCP protocol variant to use in the simulation. Supported values include UNCOUPLED, COUPLED_INC, COUPLED_TCP, COUPLED_SCALABLE_TCP, and COUPLED_EPSILON, each representing distinct congestion control or coupling approach within HTSim.

        Returns: Union[Literal["COUPLED_EPSILON"], Literal["COUPLED_INC"], Literal["COUPLED_SCALABLE_TCP"], Literal["COUPLED_TCP"], Literal["UNCOUPLED"]]
        """
        return self._get_property("tcp_protocol")

    @tcp_protocol.setter
    def tcp_protocol(self, value):
        """tcp_protocol setter

        Specifies the TCP protocol variant to use in the simulation. Supported values include UNCOUPLED, COUPLED_INC, COUPLED_TCP, COUPLED_SCALABLE_TCP, and COUPLED_EPSILON, each representing distinct congestion control or coupling approach within HTSim.

        value: Union[Literal["COUPLED_EPSILON"], Literal["COUPLED_INC"], Literal["COUPLED_SCALABLE_TCP"], Literal["COUPLED_TCP"], Literal["UNCOUPLED"]]
        """
        self._set_property("tcp_protocol", value)


class HTSimTopologyOptions(OpenApiObject):
    __slots__ = ("_parent", "_choice")

    _TYPES = {
        "choice": {
            "type": str,
            "enum": [
                "network_topology_configuration",
                "infragraph",
            ],
        },
        "network_topology_configuration": {"type": "HTSimNetworkConfiguration"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    NETWORK_TOPOLOGY_CONFIGURATION = "network_topology_configuration"  # type: str
    INFRAGRAPH = "infragraph"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, choice=None):
        super(HTSimTopologyOptions, self).__init__()
        self._parent = parent
        if (
            "choice" in self._DEFAULTS
            and choice is None
            and self._DEFAULTS["choice"] in self._TYPES
        ):
            getattr(self, self._DEFAULTS["choice"])
        else:
            self._set_property("choice", choice)

    @property
    def network_topology_configuration(self):
        # type: () -> HTSimNetworkConfiguration
        """Factory property that returns an instance of the HTSimNetworkConfiguration class

        TBD

        Returns: HTSimNetworkConfiguration
        """
        return self._get_property(
            "network_topology_configuration",
            HTSimNetworkConfiguration,
            self,
            "network_topology_configuration",
        )

    @property
    def choice(self):
        # type: () -> Union[Literal["infragraph"], Literal["network_topology_configuration"]]
        """choice getter

        Specifies the choice between HTSim network configuration and infragraph.

        Returns: Union[Literal["infragraph"], Literal["network_topology_configuration"]]
        """
        return self._get_property("choice")

    @choice.setter
    def choice(self, value):
        """choice setter

        Specifies the choice between HTSim network configuration and infragraph.

        value: Union[Literal["infragraph"], Literal["network_topology_configuration"]]
        """
        self._set_property("choice", value)


class HTSimNetworkConfiguration(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "network": {"type": "AnalyticalTopologyNetworkIter"},
        "htsim_topology": {"type": "HTSimTopology"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(HTSimNetworkConfiguration, self).__init__()
        self._parent = parent

    @property
    def network(self):
        # type: () -> AnalyticalTopologyNetworkIter
        """network getter

        TBD

        Returns: AnalyticalTopologyNetworkIter
        """
        return self._get_property(
            "network", AnalyticalTopologyNetworkIter, self._parent, self._choice
        )

    @property
    def htsim_topology(self):
        # type: () -> HTSimTopology
        """htsim_topology getter

        The HTSim network simulator provides rich collection of datacenter network topologies designed for evaluating transport protocols and congestion control algorithms.The HTSim network simulator provides rich collection of datacenter network topologies designed for evaluating transport protocols and congestion control algorithms.The HTSim network simulator provides rich collection of datacenter network topologies designed for evaluating transport protocols and congestion control algorithms.The HTSim network simulator provides rich collection of datacenter network topologies designed for evaluating transport protocols and congestion control algorithms.

        Returns: HTSimTopology
        """
        return self._get_property("htsim_topology", HTSimTopology)


class HTSimTopology(OpenApiObject):
    __slots__ = ("_parent", "_choice")

    _TYPES = {
        "choice": {
            "type": str,
            "enum": [
                "fat_tree",
            ],
        },
        "fat_tree": {"type": "HTSimTopologyFatTree"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    FAT_TREE = "fat_tree"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, choice=None):
        super(HTSimTopology, self).__init__()
        self._parent = parent
        if (
            "choice" in self._DEFAULTS
            and choice is None
            and self._DEFAULTS["choice"] in self._TYPES
        ):
            getattr(self, self._DEFAULTS["choice"])
        else:
            self._set_property("choice", choice)

    @property
    def fat_tree(self):
        # type: () -> HTSimTopologyFatTree
        """Factory property that returns an instance of the HTSimTopologyFatTree class

        TBD

        Returns: HTSimTopologyFatTree
        """
        return self._get_property("fat_tree", HTSimTopologyFatTree, self, "fat_tree")

    @property
    def choice(self):
        # type: () -> Union[Literal["fat_tree"]]
        """choice getter

        This setting allows users to select the topology definition. The users can choose from various predefined topologies such as fat tree, dragonfly, and others directly within the HTSim topology configuration.

        Returns: Union[Literal["fat_tree"]]
        """
        return self._get_property("choice")

    @choice.setter
    def choice(self, value):
        """choice setter

        This setting allows users to select the topology definition. The users can choose from various predefined topologies such as fat tree, dragonfly, and others directly within the HTSim topology configuration.

        value: Union[Literal["fat_tree"]]
        """
        self._set_property("choice", value)


class HTSimTopologyFatTree(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "nodes": {
            "type": int,
            "format": "int32",
        },
        "tiers": {
            "type": int,
            "format": "int32",
            "minimum": 2,
            "maximum": 3,
        },
        "podsize": {
            "type": int,
            "format": "int32",
        },
        "tier_0": {"type": "HTSimTopologyFatTreeTier"},
        "tier_1": {"type": "HTSimTopologyFatTreeTier"},
        "tier_2": {"type": "HTSimTopologyFatTreeTier2"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, nodes=None, tiers=None, podsize=None):
        super(HTSimTopologyFatTree, self).__init__()
        self._parent = parent
        self._set_property("nodes", nodes)
        self._set_property("tiers", tiers)
        self._set_property("podsize", podsize)

    def set(self, nodes=None, tiers=None, podsize=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def nodes(self):
        # type: () -> int
        """nodes getter

        The total number of nodes in topology.

        Returns: int
        """
        return self._get_property("nodes")

    @nodes.setter
    def nodes(self, value):
        """nodes setter

        The total number of nodes in topology.

        value: int
        """
        self._set_property("nodes", value)

    @property
    def tiers(self):
        # type: () -> int
        """tiers getter

        The total number of tiers in topology.

        Returns: int
        """
        return self._get_property("tiers")

    @tiers.setter
    def tiers(self, value):
        """tiers setter

        The total number of tiers in topology.

        value: int
        """
        self._set_property("tiers", value)

    @property
    def podsize(self):
        # type: () -> int
        """podsize getter

        The total podsize in topology.

        Returns: int
        """
        return self._get_property("podsize")

    @podsize.setter
    def podsize(self, value):
        """podsize setter

        The total podsize in topology.

        value: int
        """
        self._set_property("podsize", value)

    @property
    def tier_0(self):
        # type: () -> HTSimTopologyFatTreeTier
        """tier_0 getter



        Returns: HTSimTopologyFatTreeTier
        """
        return self._get_property("tier_0", HTSimTopologyFatTreeTier)

    @property
    def tier_1(self):
        # type: () -> HTSimTopologyFatTreeTier
        """tier_1 getter



        Returns: HTSimTopologyFatTreeTier
        """
        return self._get_property("tier_1", HTSimTopologyFatTreeTier)

    @property
    def tier_2(self):
        # type: () -> HTSimTopologyFatTreeTier2
        """tier_2 getter



        Returns: HTSimTopologyFatTreeTier2
        """
        return self._get_property("tier_2", HTSimTopologyFatTreeTier2)


class HTSimTopologyFatTreeTier(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "downlink_speed_gbps": {
            "type": int,
            "format": "int32",
        },
        "radix_up": {
            "type": int,
            "format": "int32",
        },
        "radix_down": {
            "type": int,
            "format": "int32",
        },
        "queue_up": {
            "type": int,
            "format": "int32",
        },
        "queue_down": {
            "type": int,
            "format": "int32",
        },
        "oversubscribed": {
            "type": int,
            "format": "int32",
        },
        "bundle": {
            "type": int,
            "format": "int32",
        },
        "switch_latency_ns": {
            "type": int,
            "format": "int32",
        },
        "downlink_latency_ns": {
            "type": int,
            "format": "int32",
        },
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self,
        parent=None,
        downlink_speed_gbps=None,
        radix_up=None,
        radix_down=None,
        queue_up=None,
        queue_down=None,
        oversubscribed=None,
        bundle=None,
        switch_latency_ns=None,
        downlink_latency_ns=None,
    ):
        super(HTSimTopologyFatTreeTier, self).__init__()
        self._parent = parent
        self._set_property("downlink_speed_gbps", downlink_speed_gbps)
        self._set_property("radix_up", radix_up)
        self._set_property("radix_down", radix_down)
        self._set_property("queue_up", queue_up)
        self._set_property("queue_down", queue_down)
        self._set_property("oversubscribed", oversubscribed)
        self._set_property("bundle", bundle)
        self._set_property("switch_latency_ns", switch_latency_ns)
        self._set_property("downlink_latency_ns", downlink_latency_ns)

    def set(
        self,
        downlink_speed_gbps=None,
        radix_up=None,
        radix_down=None,
        queue_up=None,
        queue_down=None,
        oversubscribed=None,
        bundle=None,
        switch_latency_ns=None,
        downlink_latency_ns=None,
    ):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def downlink_speed_gbps(self):
        # type: () -> int
        """downlink_speed_gbps getter

        The downlink speed of the tier, measured in gigabits per second (Gbps).

        Returns: int
        """
        return self._get_property("downlink_speed_gbps")

    @downlink_speed_gbps.setter
    def downlink_speed_gbps(self, value):
        """downlink_speed_gbps setter

        The downlink speed of the tier, measured in gigabits per second (Gbps).

        value: int
        """
        self._set_property("downlink_speed_gbps", value)

    @property
    def radix_up(self):
        # type: () -> int
        """radix_up getter

        The count of uplink ports available in the given tier.

        Returns: int
        """
        return self._get_property("radix_up")

    @radix_up.setter
    def radix_up(self, value):
        """radix_up setter

        The count of uplink ports available in the given tier.

        value: int
        """
        self._set_property("radix_up", value)

    @property
    def radix_down(self):
        # type: () -> int
        """radix_down getter

        The count of downlink ports available in the given tier.

        Returns: int
        """
        return self._get_property("radix_down")

    @radix_down.setter
    def radix_down(self, value):
        """radix_down setter

        The count of downlink ports available in the given tier.

        value: int
        """
        self._set_property("radix_down", value)

    @property
    def queue_up(self):
        # type: () -> int
        """queue_up getter

        The number of uplink queues assigned for this tier.

        Returns: int
        """
        return self._get_property("queue_up")

    @queue_up.setter
    def queue_up(self, value):
        """queue_up setter

        The number of uplink queues assigned for this tier.

        value: int
        """
        self._set_property("queue_up", value)

    @property
    def queue_down(self):
        # type: () -> int
        """queue_down getter

        The number of downlink queues assigned for this tier.

        Returns: int
        """
        return self._get_property("queue_down")

    @queue_down.setter
    def queue_down(self, value):
        """queue_down setter

        The number of downlink queues assigned for this tier.

        value: int
        """
        self._set_property("queue_down", value)

    @property
    def oversubscribed(self):
        # type: () -> int
        """oversubscribed getter

        The oversubscription ratio configured for this tier.

        Returns: int
        """
        return self._get_property("oversubscribed")

    @oversubscribed.setter
    def oversubscribed(self, value):
        """oversubscribed setter

        The oversubscription ratio configured for this tier.

        value: int
        """
        self._set_property("oversubscribed", value)

    @property
    def bundle(self):
        # type: () -> int
        """bundle getter

        The count of port bundles configured for this tier.

        Returns: int
        """
        return self._get_property("bundle")

    @bundle.setter
    def bundle(self, value):
        """bundle setter

        The count of port bundles configured for this tier.

        value: int
        """
        self._set_property("bundle", value)

    @property
    def switch_latency_ns(self):
        # type: () -> int
        """switch_latency_ns getter

        The switch latency within the tier, measured in nanoseconds.

        Returns: int
        """
        return self._get_property("switch_latency_ns")

    @switch_latency_ns.setter
    def switch_latency_ns(self, value):
        """switch_latency_ns setter

        The switch latency within the tier, measured in nanoseconds.

        value: int
        """
        self._set_property("switch_latency_ns", value)

    @property
    def downlink_latency_ns(self):
        # type: () -> int
        """downlink_latency_ns getter

        The latency on the downlink ports of the tier, measured in nanoseconds.

        Returns: int
        """
        return self._get_property("downlink_latency_ns")

    @downlink_latency_ns.setter
    def downlink_latency_ns(self, value):
        """downlink_latency_ns setter

        The latency on the downlink ports of the tier, measured in nanoseconds.

        value: int
        """
        self._set_property("downlink_latency_ns", value)


class HTSimTopologyFatTreeTier2(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "downlink_speed_gbps": {
            "type": int,
            "format": "int32",
        },
        "radix_down": {
            "type": int,
            "format": "int32",
        },
        "queue_down": {
            "type": int,
            "format": "int32",
        },
        "oversubscribed": {
            "type": int,
            "format": "int32",
        },
        "bundle": {
            "type": int,
            "format": "int32",
        },
        "switch_latency_ns": {
            "type": int,
            "format": "int32",
        },
        "downlink_latency_ns": {
            "type": int,
            "format": "int32",
        },
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self,
        parent=None,
        downlink_speed_gbps=None,
        radix_down=None,
        queue_down=None,
        oversubscribed=None,
        bundle=None,
        switch_latency_ns=None,
        downlink_latency_ns=None,
    ):
        super(HTSimTopologyFatTreeTier2, self).__init__()
        self._parent = parent
        self._set_property("downlink_speed_gbps", downlink_speed_gbps)
        self._set_property("radix_down", radix_down)
        self._set_property("queue_down", queue_down)
        self._set_property("oversubscribed", oversubscribed)
        self._set_property("bundle", bundle)
        self._set_property("switch_latency_ns", switch_latency_ns)
        self._set_property("downlink_latency_ns", downlink_latency_ns)

    def set(
        self,
        downlink_speed_gbps=None,
        radix_down=None,
        queue_down=None,
        oversubscribed=None,
        bundle=None,
        switch_latency_ns=None,
        downlink_latency_ns=None,
    ):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def downlink_speed_gbps(self):
        # type: () -> int
        """downlink_speed_gbps getter

        The downlink speed of the tier, measured in gigabits per second (Gbps).

        Returns: int
        """
        return self._get_property("downlink_speed_gbps")

    @downlink_speed_gbps.setter
    def downlink_speed_gbps(self, value):
        """downlink_speed_gbps setter

        The downlink speed of the tier, measured in gigabits per second (Gbps).

        value: int
        """
        self._set_property("downlink_speed_gbps", value)

    @property
    def radix_down(self):
        # type: () -> int
        """radix_down getter

        The count of downlink ports available in the given tier.

        Returns: int
        """
        return self._get_property("radix_down")

    @radix_down.setter
    def radix_down(self, value):
        """radix_down setter

        The count of downlink ports available in the given tier.

        value: int
        """
        self._set_property("radix_down", value)

    @property
    def queue_down(self):
        # type: () -> int
        """queue_down getter

        The number of downlink queues assigned for this tier.

        Returns: int
        """
        return self._get_property("queue_down")

    @queue_down.setter
    def queue_down(self, value):
        """queue_down setter

        The number of downlink queues assigned for this tier.

        value: int
        """
        self._set_property("queue_down", value)

    @property
    def oversubscribed(self):
        # type: () -> int
        """oversubscribed getter

        The oversubscription ratio configured for this tier.

        Returns: int
        """
        return self._get_property("oversubscribed")

    @oversubscribed.setter
    def oversubscribed(self, value):
        """oversubscribed setter

        The oversubscription ratio configured for this tier.

        value: int
        """
        self._set_property("oversubscribed", value)

    @property
    def bundle(self):
        # type: () -> int
        """bundle getter

        The count of port bundles configured for this tier.

        Returns: int
        """
        return self._get_property("bundle")

    @bundle.setter
    def bundle(self, value):
        """bundle setter

        The count of port bundles configured for this tier.

        value: int
        """
        self._set_property("bundle", value)

    @property
    def switch_latency_ns(self):
        # type: () -> int
        """switch_latency_ns getter

        The switch latency within the tier, measured in nanoseconds.

        Returns: int
        """
        return self._get_property("switch_latency_ns")

    @switch_latency_ns.setter
    def switch_latency_ns(self, value):
        """switch_latency_ns setter

        The switch latency within the tier, measured in nanoseconds.

        value: int
        """
        self._set_property("switch_latency_ns", value)

    @property
    def downlink_latency_ns(self):
        # type: () -> int
        """downlink_latency_ns getter

        The latency on the downlink ports of the tier, measured in nanoseconds.

        Returns: int
        """
        return self._get_property("downlink_latency_ns")

    @downlink_latency_ns.setter
    def downlink_latency_ns(self, value):
        """downlink_latency_ns setter

        The latency on the downlink ports of the tier, measured in nanoseconds.

        value: int
        """
        self._set_property("downlink_latency_ns", value)


class Infragraph(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "infrastructure": {"type": "Infrastructure"},
        "annotations": {"type": "Annotations"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(Infragraph, self).__init__()
        self._parent = parent

    @property
    def infrastructure(self):
        # type: () -> Infrastructure
        """infrastructure getter

        The infrastructure model representing the current version (v0.4.1) of InfraGraph schema

        Returns: Infrastructure
        """
        return self._get_property("infrastructure", Infrastructure)

    @property
    def annotations(self):
        # type: () -> Annotations
        """annotations getter

        Container for link and device specifications annotationsContainer for link and device specifications annotationsContainer for link and device specifications annotationsAdditional annotations to enrich infrastructure data, used by Astra Sim backend network topologies and other components

        Returns: Annotations
        """
        return self._get_property("annotations", Annotations)


class Infrastructure(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "name": {
            "type": str,
            "pattern": r"^[\sa-zA-Z0-9-_()><\[\]]+$",
        },
        "description": {"type": str},
        "devices": {"type": "DeviceIter"},
        "links": {"type": "LinkIter"},
        "instances": {"type": "InstanceIter"},
        "edges": {"type": "InfrastructureEdgeIter"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, name=None, description=None):
        super(Infrastructure, self).__init__()
        self._parent = parent
        self._set_property("name", name)
        self._set_property("description", description)

    def set(self, name=None, description=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def name(self):
        # type: () -> str
        """name getter

        The name of the infrastructure.. Globally unique name of an object. It also serves as the primary key for arrays of objects.

        Returns: str
        """
        return self._get_property("name")

    @name.setter
    def name(self, value):
        """name setter

        The name of the infrastructure.. Globally unique name of an object. It also serves as the primary key for arrays of objects.

        value: str
        """
        self._set_property("name", value)

    @property
    def description(self):
        # type: () -> str
        """description getter

        A detailed description of the infrastructure.

        Returns: str
        """
        return self._get_property("description")

    @description.setter
    def description(self, value):
        """description setter

        A detailed description of the infrastructure.

        value: str
        """
        self._set_property("description", value)

    @property
    def devices(self):
        # type: () -> DeviceIter
        """devices getter

        An inventory of devices and components.

        Returns: DeviceIter
        """
        return self._get_property("devices", DeviceIter, self._parent, self._choice)

    @property
    def links(self):
        # type: () -> LinkIter
        """links getter

        An inventory of the links present in the infrastructure edges.

        Returns: LinkIter
        """
        return self._get_property("links", LinkIter, self._parent, self._choice)

    @property
    def instances(self):
        # type: () -> InstanceIter
        """instances getter

        An inventory of the device instances present in the infrastructure edges.

        Returns: InstanceIter
        """
        return self._get_property("instances", InstanceIter, self._parent, self._choice)

    @property
    def edges(self):
        # type: () -> InfrastructureEdgeIter
        """edges getter

        An array of edge objects used to connect instance devices and components to other instance. devices and components. These edge objects are used to form fully qualified qualified graph.

        Returns: InfrastructureEdgeIter
        """
        return self._get_property(
            "edges", InfrastructureEdgeIter, self._parent, self._choice
        )


class Device(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "name": {
            "type": str,
            "pattern": r"^[\sa-zA-Z0-9-_()><\[\]]+$",
        },
        "description": {"type": str},
        "components": {"type": "ComponentIter"},
        "links": {"type": "LinkIter"},
        "edges": {"type": "DeviceEdgeIter"},
    }  # type: Dict[str, str]

    _REQUIRED = ("name", "components", "links", "edges")  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, name=None, description=None):
        super(Device, self).__init__()
        self._parent = parent
        self._set_property("name", name)
        self._set_property("description", description)

    def set(self, name=None, description=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def name(self):
        # type: () -> str
        """name getter

        The name of the device being described.. Globally unique name of an object. It also serves as the primary key for arrays of objects.

        Returns: str
        """
        return self._get_property("name")

    @name.setter
    def name(self, value):
        """name setter

        The name of the device being described.. Globally unique name of an object. It also serves as the primary key for arrays of objects.

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property name as None")
        self._set_property("name", value)

    @property
    def description(self):
        # type: () -> str
        """description getter

        A description of the device.. This will not be used in Infrastructure.connections.

        Returns: str
        """
        return self._get_property("description")

    @description.setter
    def description(self, value):
        """description setter

        A description of the device.. This will not be used in Infrastructure.connections.

        value: str
        """
        self._set_property("description", value)

    @property
    def components(self):
        # type: () -> ComponentIter
        """components getter

        TBD

        Returns: ComponentIter
        """
        return self._get_property(
            "components", ComponentIter, self._parent, self._choice
        )

    @property
    def links(self):
        # type: () -> LinkIter
        """links getter

        All the links that make up this device.

        Returns: LinkIter
        """
        return self._get_property("links", LinkIter, self._parent, self._choice)

    @property
    def edges(self):
        # type: () -> DeviceEdgeIter
        """edges getter

        An array of edges that are used to produce device graph.. These are used to connect components to each other or components. to other device components (composability).. The generated graph edges will be fully qualified using the count property. of the device and component and slice notation of each endpoint in the edge object.

        Returns: DeviceEdgeIter
        """
        return self._get_property("edges", DeviceEdgeIter, self._parent, self._choice)


class Component(OpenApiObject):
    __slots__ = ("_parent", "_choice")

    _TYPES = {
        "name": {
            "type": str,
            "pattern": r"^[\sa-zA-Z0-9-_()><\[\]]+$",
        },
        "description": {"type": str},
        "count": {
            "type": int,
            "format": "int32",
        },
        "choice": {
            "type": str,
            "enum": [
                "custom",
                "device",
                "cpu",
                "npu",
                "nic",
                "memory",
                "port",
                "switch",
            ],
        },
        "custom": {"type": "ComponentCustom"},
        "device": {"type": "ComponentDevice"},
        "cpu": {"type": "ComponentCpu"},
        "npu": {"type": "ComponentNpu"},
        "nic": {"type": "ComponentNic"},
        "memory": {"type": "ComponentMemory"},
        "port": {"type": "ComponentPort"},
        "switch": {"type": "ComponentSwitch"},
    }  # type: Dict[str, str]

    _REQUIRED = ("name", "count", "choice")  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    CUSTOM = "custom"  # type: str
    DEVICE = "device"  # type: str
    CPU = "cpu"  # type: str
    NPU = "npu"  # type: str
    NIC = "nic"  # type: str
    MEMORY = "memory"  # type: str
    PORT = "port"  # type: str
    SWITCH = "switch"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self, parent=None, choice=None, name=None, description=None, count=None
    ):
        super(Component, self).__init__()
        self._parent = parent
        self._set_property("name", name)
        self._set_property("description", description)
        self._set_property("count", count)
        if (
            "choice" in self._DEFAULTS
            and choice is None
            and self._DEFAULTS["choice"] in self._TYPES
        ):
            getattr(self, self._DEFAULTS["choice"])
        else:
            self._set_property("choice", choice)

    def set(self, name=None, description=None, count=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def custom(self):
        # type: () -> ComponentCustom
        """Factory property that returns an instance of the ComponentCustom class

        Placeholder for component that can be extended.

        Returns: ComponentCustom
        """
        return self._get_property("custom", ComponentCustom, self, "custom")

    @property
    def device(self):
        # type: () -> ComponentDevice
        """Factory property that returns an instance of the ComponentDevice class

        Placeholder for component that can be extended.

        Returns: ComponentDevice
        """
        return self._get_property("device", ComponentDevice, self, "device")

    @property
    def cpu(self):
        # type: () -> ComponentCpu
        """Factory property that returns an instance of the ComponentCpu class

        Placeholder for component that can be extended.

        Returns: ComponentCpu
        """
        return self._get_property("cpu", ComponentCpu, self, "cpu")

    @property
    def npu(self):
        # type: () -> ComponentNpu
        """Factory property that returns an instance of the ComponentNpu class

        Placeholder for component that can be extended.

        Returns: ComponentNpu
        """
        return self._get_property("npu", ComponentNpu, self, "npu")

    @property
    def nic(self):
        # type: () -> ComponentNic
        """Factory property that returns an instance of the ComponentNic class

        Placeholder for component that can be extended.

        Returns: ComponentNic
        """
        return self._get_property("nic", ComponentNic, self, "nic")

    @property
    def memory(self):
        # type: () -> ComponentMemory
        """Factory property that returns an instance of the ComponentMemory class

        Placeholder for component that can be extended.

        Returns: ComponentMemory
        """
        return self._get_property("memory", ComponentMemory, self, "memory")

    @property
    def port(self):
        # type: () -> ComponentPort
        """Factory property that returns an instance of the ComponentPort class

        Placeholder for component that can be extended.

        Returns: ComponentPort
        """
        return self._get_property("port", ComponentPort, self, "port")

    @property
    def switch(self):
        # type: () -> ComponentSwitch
        """Factory property that returns an instance of the ComponentSwitch class

        Placeholder for component that can be extended.

        Returns: ComponentSwitch
        """
        return self._get_property("switch", ComponentSwitch, self, "switch")

    @property
    def name(self):
        # type: () -> str
        """name getter

        Globally unique name of an object. It also serves as the primary key for arrays of objects.

        Returns: str
        """
        return self._get_property("name")

    @name.setter
    def name(self, value):
        """name setter

        Globally unique name of an object. It also serves as the primary key for arrays of objects.

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property name as None")
        self._set_property("name", value)

    @property
    def description(self):
        # type: () -> str
        """description getter

        A description of the component.

        Returns: str
        """
        return self._get_property("description")

    @description.setter
    def description(self, value):
        """description setter

        A description of the component.

        value: str
        """
        self._set_property("description", value)

    @property
    def count(self):
        # type: () -> int
        """count getter

        The maxiumim number of this component that will be contained by single device instance.. This property is used by the infragraph service in edge generation.

        Returns: int
        """
        return self._get_property("count")

    @count.setter
    def count(self, value):
        """count setter

        The maxiumim number of this component that will be contained by single device instance.. This property is used by the infragraph service in edge generation.

        value: int
        """
        if value is None:
            raise TypeError("Cannot set required property count as None")
        self._set_property("count", value)

    @property
    def choice(self):
        # type: () -> Union[Literal["cpu"], Literal["custom"], Literal["device"], Literal["memory"], Literal["nic"], Literal["npu"], Literal["port"], Literal["switch"]]
        """choice getter

        The type of component.. The `choice` value will be added to the graph node in the form of `type value` attribute.. - `custom` If the type of component is not listed as choice it can be defined using the custom object which includes type property that allows for custom type attribute on the graph node.. `device` This enum allows device to be composed of other devices. When this enum is selected the name of the component MUST be the name of device that exists in the Infrastructure.devices array.. `cpu` high level definition for cpu. `npu` high level definition for neural processing unit. `nic` high level definition for network interface card, for more detailed breakdowns create device representing specific type network interface card. `memory` high level definition for memory. `port` high level definitiion for an IO port. `switch` high level definition for an internal switch connecting components

        Returns: Union[Literal["cpu"], Literal["custom"], Literal["device"], Literal["memory"], Literal["nic"], Literal["npu"], Literal["port"], Literal["switch"]]
        """
        return self._get_property("choice")

    @choice.setter
    def choice(self, value):
        """choice setter

        The type of component.. The `choice` value will be added to the graph node in the form of `type value` attribute.. - `custom` If the type of component is not listed as choice it can be defined using the custom object which includes type property that allows for custom type attribute on the graph node.. `device` This enum allows device to be composed of other devices. When this enum is selected the name of the component MUST be the name of device that exists in the Infrastructure.devices array.. `cpu` high level definition for cpu. `npu` high level definition for neural processing unit. `nic` high level definition for network interface card, for more detailed breakdowns create device representing specific type network interface card. `memory` high level definition for memory. `port` high level definitiion for an IO port. `switch` high level definition for an internal switch connecting components

        value: Union[Literal["cpu"], Literal["custom"], Literal["device"], Literal["memory"], Literal["nic"], Literal["npu"], Literal["port"], Literal["switch"]]
        """
        if value is None:
            raise TypeError("Cannot set required property choice as None")
        self._set_property("choice", value)


class ComponentCustom(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "type": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ("type",)  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, type=None):
        super(ComponentCustom, self).__init__()
        self._parent = parent
        self._set_property("type", type)

    def set(self, type=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def type(self):
        # type: () -> str
        """type getter

        This property will be added to the graph node in the form of `type value` attribute.

        Returns: str
        """
        return self._get_property("type")

    @type.setter
    def type(self, value):
        """type setter

        This property will be added to the graph node in the form of `type value` attribute.

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property type as None")
        self._set_property("type", value)


class ComponentDevice(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {}  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(ComponentDevice, self).__init__()
        self._parent = parent


class ComponentCpu(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {}  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(ComponentCpu, self).__init__()
        self._parent = parent


class ComponentNpu(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {}  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(ComponentNpu, self).__init__()
        self._parent = parent


class ComponentNic(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {}  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(ComponentNic, self).__init__()
        self._parent = parent


class ComponentMemory(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {}  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(ComponentMemory, self).__init__()
        self._parent = parent


class ComponentPort(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {}  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(ComponentPort, self).__init__()
        self._parent = parent


class ComponentSwitch(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {}  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(ComponentSwitch, self).__init__()
        self._parent = parent


class ComponentIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(ComponentIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[Component, ComponentCpu, ComponentCustom, ComponentDevice, ComponentMemory, ComponentNic, ComponentNpu, ComponentPort, ComponentSwitch]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> ComponentIter
        return self._iter()

    def __next__(self):
        # type: () -> Component
        return self._next()

    def next(self):
        # type: () -> Component
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, Component):
            raise Exception("Item is not an instance of Component")

    def component(self, name=None, description=None, count=None):
        # type: (str,str,int) -> ComponentIter
        """Factory method that creates an instance of the Component class

        A container for describing component.. Component is contained in Device.

        Returns: ComponentIter
        """
        item = Component(
            parent=self._parent,
            choice=self._choice,
            name=name,
            description=description,
            count=count,
        )
        self._add(item)
        return self

    def add(self, name=None, description=None, count=None):
        # type: (str,str,int) -> Component
        """Add method that creates and returns an instance of the Component class

        A container for describing component.. Component is contained in Device.

        Returns: Component
        """
        item = Component(
            parent=self._parent,
            choice=self._choice,
            name=name,
            description=description,
            count=count,
        )
        self._add(item)
        return item


class Link(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "name": {
            "type": str,
            "pattern": r"^[\sa-zA-Z0-9-_()><\[\]]+$",
        },
        "description": {"type": str},
        "physical": {"type": "LinkPhysical"},
    }  # type: Dict[str, str]

    _REQUIRED = ("name",)  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, name=None, description=None):
        super(Link, self).__init__()
        self._parent = parent
        self._set_property("name", name)
        self._set_property("description", description)

    def set(self, name=None, description=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def name(self):
        # type: () -> str
        """name getter

        Globally unique name of an object. It also serves as the primary key for arrays of objects.

        Returns: str
        """
        return self._get_property("name")

    @name.setter
    def name(self, value):
        """name setter

        Globally unique name of an object. It also serves as the primary key for arrays of objects.

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property name as None")
        self._set_property("name", value)

    @property
    def description(self):
        # type: () -> str
        """description getter

        A description of the type of link.

        Returns: str
        """
        return self._get_property("description")

    @description.setter
    def description(self, value):
        """description setter

        A description of the type of link.

        value: str
        """
        self._set_property("description", value)

    @property
    def physical(self):
        # type: () -> LinkPhysical
        """physical getter

        A container for physical properties.

        Returns: LinkPhysical
        """
        return self._get_property("physical", LinkPhysical)


class LinkPhysical(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "bandwidth": {"type": "LinkPhysicalBandwidth"},
        "latency": {"type": "LinkPhysicalLatency"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(LinkPhysical, self).__init__()
        self._parent = parent

    @property
    def bandwidth(self):
        # type: () -> LinkPhysicalBandwidth
        """bandwidth getter

        A container for specific Link physical Properties.A container for specific Link physical Properties.A container for specific Link physical Properties.

        Returns: LinkPhysicalBandwidth
        """
        return self._get_property("bandwidth", LinkPhysicalBandwidth)

    @property
    def latency(self):
        # type: () -> LinkPhysicalLatency
        """latency getter

        A container for specific Link latency properties.A container for specific Link latency properties.A container for specific Link latency properties.

        Returns: LinkPhysicalLatency
        """
        return self._get_property("latency", LinkPhysicalLatency)


class LinkPhysicalBandwidth(OpenApiObject):
    __slots__ = ("_parent", "_choice")

    _TYPES = {
        "choice": {
            "type": str,
            "enum": [
                "gigabits_per_second",
                "gigabytes_per_second",
                "gigatransfers_per_second",
            ],
        },
        "gigabits_per_second": {"type": float},
        "gigabytes_per_second": {"type": float},
        "gigatransfers_per_second": {"type": float},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    GIGABITS_PER_SECOND = "gigabits_per_second"  # type: str
    GIGABYTES_PER_SECOND = "gigabytes_per_second"  # type: str
    GIGATRANSFERS_PER_SECOND = "gigatransfers_per_second"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self,
        parent=None,
        choice=None,
        gigabits_per_second=None,
        gigabytes_per_second=None,
        gigatransfers_per_second=None,
    ):
        super(LinkPhysicalBandwidth, self).__init__()
        self._parent = parent
        self._set_property("gigabits_per_second", gigabits_per_second)
        self._set_property("gigabytes_per_second", gigabytes_per_second)
        self._set_property("gigatransfers_per_second", gigatransfers_per_second)
        if (
            "choice" in self._DEFAULTS
            and choice is None
            and self._DEFAULTS["choice"] in self._TYPES
        ):
            getattr(self, self._DEFAULTS["choice"])
        else:
            self._set_property("choice", choice)

    def set(
        self,
        gigabits_per_second=None,
        gigabytes_per_second=None,
        gigatransfers_per_second=None,
    ):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def choice(self):
        # type: () -> Union[Literal["gigabits_per_second"], Literal["gigabytes_per_second"], Literal["gigatransfers_per_second"]]
        """choice getter

        TBD

        Returns: Union[Literal["gigabits_per_second"], Literal["gigabytes_per_second"], Literal["gigatransfers_per_second"]]
        """
        return self._get_property("choice")

    @choice.setter
    def choice(self, value):
        """choice setter

        TBD

        value: Union[Literal["gigabits_per_second"], Literal["gigabytes_per_second"], Literal["gigatransfers_per_second"]]
        """
        self._set_property("choice", value)

    @property
    def gigabits_per_second(self):
        # type: () -> float
        """gigabits_per_second getter

        Gigabits per second.

        Returns: float
        """
        return self._get_property("gigabits_per_second")

    @gigabits_per_second.setter
    def gigabits_per_second(self, value):
        """gigabits_per_second setter

        Gigabits per second.

        value: float
        """
        self._set_property("gigabits_per_second", value, "gigabits_per_second")

    @property
    def gigabytes_per_second(self):
        # type: () -> float
        """gigabytes_per_second getter

        Gigabytes per second.

        Returns: float
        """
        return self._get_property("gigabytes_per_second")

    @gigabytes_per_second.setter
    def gigabytes_per_second(self, value):
        """gigabytes_per_second setter

        Gigabytes per second.

        value: float
        """
        self._set_property("gigabytes_per_second", value, "gigabytes_per_second")

    @property
    def gigatransfers_per_second(self):
        # type: () -> float
        """gigatransfers_per_second getter

        Gigatrasfers per second.

        Returns: float
        """
        return self._get_property("gigatransfers_per_second")

    @gigatransfers_per_second.setter
    def gigatransfers_per_second(self, value):
        """gigatransfers_per_second setter

        Gigatrasfers per second.

        value: float
        """
        self._set_property(
            "gigatransfers_per_second", value, "gigatransfers_per_second"
        )


class LinkPhysicalLatency(OpenApiObject):
    __slots__ = ("_parent", "_choice")

    _TYPES = {
        "choice": {
            "type": str,
            "enum": [
                "ms",
                "us",
                "ns",
            ],
        },
        "ms": {"type": float},
        "us": {"type": float},
        "ns": {"type": float},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    MS = "ms"  # type: str
    US = "us"  # type: str
    NS = "ns"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, choice=None, ms=None, us=None, ns=None):
        super(LinkPhysicalLatency, self).__init__()
        self._parent = parent
        self._set_property("ms", ms)
        self._set_property("us", us)
        self._set_property("ns", ns)
        if (
            "choice" in self._DEFAULTS
            and choice is None
            and self._DEFAULTS["choice"] in self._TYPES
        ):
            getattr(self, self._DEFAULTS["choice"])
        else:
            self._set_property("choice", choice)

    def set(self, ms=None, us=None, ns=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def choice(self):
        # type: () -> Union[Literal["ms"], Literal["ns"], Literal["us"]]
        """choice getter

        TBD

        Returns: Union[Literal["ms"], Literal["ns"], Literal["us"]]
        """
        return self._get_property("choice")

    @choice.setter
    def choice(self, value):
        """choice setter

        TBD

        value: Union[Literal["ms"], Literal["ns"], Literal["us"]]
        """
        self._set_property("choice", value)

    @property
    def ms(self):
        # type: () -> float
        """ms getter

        Latency in milliseconds

        Returns: float
        """
        return self._get_property("ms")

    @ms.setter
    def ms(self, value):
        """ms setter

        Latency in milliseconds

        value: float
        """
        self._set_property("ms", value, "ms")

    @property
    def us(self):
        # type: () -> float
        """us getter

        Latency in microseconds.

        Returns: float
        """
        return self._get_property("us")

    @us.setter
    def us(self, value):
        """us setter

        Latency in microseconds.

        value: float
        """
        self._set_property("us", value, "us")

    @property
    def ns(self):
        # type: () -> float
        """ns getter

        Latency in nanoseconds.

        Returns: float
        """
        return self._get_property("ns")

    @ns.setter
    def ns(self, value):
        """ns setter

        Latency in nanoseconds.

        value: float
        """
        self._set_property("ns", value, "ns")


class LinkIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(LinkIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[Link]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> LinkIter
        return self._iter()

    def __next__(self):
        # type: () -> Link
        return self._next()

    def next(self):
        # type: () -> Link
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, Link):
            raise Exception("Item is not an instance of Link")

    def link(self, name=None, description=None):
        # type: (str,str) -> LinkIter
        """Factory method that creates an instance of the Link class

        A container for describing link used between components.

        Returns: LinkIter
        """
        item = Link(parent=self._parent, name=name, description=description)
        self._add(item)
        return self

    def add(self, name=None, description=None):
        # type: (str,str) -> Link
        """Add method that creates and returns an instance of the Link class

        A container for describing link used between components.

        Returns: Link
        """
        item = Link(parent=self._parent, name=name, description=description)
        self._add(item)
        return item


class DeviceEdge(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "ep1": {"type": "DeviceEndpoint"},
        "ep2": {"type": "DeviceEndpoint"},
        "scheme": {
            "type": str,
            "enum": [
                "one2one",
                "many2many",
                "ring",
            ],
        },
        "link": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ("ep1", "ep2", "link")  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    ONE2ONE = "one2one"  # type: str
    MANY2MANY = "many2many"  # type: str
    RING = "ring"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, scheme=None, link=None):
        super(DeviceEdge, self).__init__()
        self._parent = parent
        self._set_property("scheme", scheme)
        self._set_property("link", link)

    def set(self, scheme=None, link=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def ep1(self):
        # type: () -> DeviceEndpoint
        """ep1 getter

        An optional device and component that is the other endpoint of the edge

        Returns: DeviceEndpoint
        """
        return self._get_property("ep1", DeviceEndpoint)

    @property
    def ep2(self):
        # type: () -> DeviceEndpoint
        """ep2 getter

        An optional device and component that is the other endpoint of the edge

        Returns: DeviceEndpoint
        """
        return self._get_property("ep2", DeviceEndpoint)

    @property
    def scheme(self):
        # type: () -> Union[Literal["many2many"], Literal["one2one"], Literal["ring"]]
        """scheme getter

        The scheme that will be used to create edges between the endpoints ep1 and ep2.

        Returns: Union[Literal["many2many"], Literal["one2one"], Literal["ring"]]
        """
        return self._get_property("scheme")

    @scheme.setter
    def scheme(self, value):
        """scheme setter

        The scheme that will be used to create edges between the endpoints ep1 and ep2.

        value: Union[Literal["many2many"], Literal["one2one"], Literal["ring"]]
        """
        self._set_property("scheme", value)

    @property
    def link(self):
        # type: () -> str
        """link getter

        The name of link that defines additional characteristics of the edge.. The name MUST exist in the links array of the containing device.

        Returns: str
        """
        return self._get_property("link")

    @link.setter
    def link(self, value):
        """link setter

        The name of link that defines additional characteristics of the edge.. The name MUST exist in the links array of the containing device.

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property link as None")
        self._set_property("link", value)


class DeviceEndpoint(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "device": {"type": str},
        "component": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ("component",)  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, device=None, component=None):
        super(DeviceEndpoint, self).__init__()
        self._parent = parent
        self._set_property("device", device)
        self._set_property("component", component)

    def set(self, device=None, component=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def device(self):
        # type: () -> str
        """device getter

        An optional name of device that contains the component.. If the property is empty the name of the device is the parent of the edge object.. An endpoint will be generated for every device based on the count.

        Returns: str
        """
        return self._get_property("device")

    @device.setter
    def device(self, value):
        """device setter

        An optional name of device that contains the component.. If the property is empty the name of the device is the parent of the edge object.. An endpoint will be generated for every device based on the count.

        value: str
        """
        self._set_property("device", value)

    @property
    def component(self):
        # type: () -> str
        """component getter

        The name of component that exists in the containing device. and the indexes of the component.. The indexes MUST be specified using python slice notation.. example: cx5[0:2]

        Returns: str
        """
        return self._get_property("component")

    @component.setter
    def component(self, value):
        """component setter

        The name of component that exists in the containing device. and the indexes of the component.. The indexes MUST be specified using python slice notation.. example: cx5[0:2]

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property component as None")
        self._set_property("component", value)


class DeviceEdgeIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(DeviceEdgeIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[DeviceEdge]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> DeviceEdgeIter
        return self._iter()

    def __next__(self):
        # type: () -> DeviceEdge
        return self._next()

    def next(self):
        # type: () -> DeviceEdge
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, DeviceEdge):
            raise Exception("Item is not an instance of DeviceEdge")

    def edge(self, scheme=None, link=None):
        # type: (Union[Literal["many2many"], Literal["one2one"], Literal["ring"]],str) -> DeviceEdgeIter
        """Factory method that creates an instance of the DeviceEdge class

        TBD

        Returns: DeviceEdgeIter
        """
        item = DeviceEdge(parent=self._parent, scheme=scheme, link=link)
        self._add(item)
        return self

    def add(self, scheme=None, link=None):
        # type: (Union[Literal["many2many"], Literal["one2one"], Literal["ring"]],str) -> DeviceEdge
        """Add method that creates and returns an instance of the DeviceEdge class

        TBD

        Returns: DeviceEdge
        """
        item = DeviceEdge(parent=self._parent, scheme=scheme, link=link)
        self._add(item)
        return item


class DeviceIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(DeviceIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[Device]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> DeviceIter
        return self._iter()

    def __next__(self):
        # type: () -> Device
        return self._next()

    def next(self):
        # type: () -> Device
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, Device):
            raise Exception("Item is not an instance of Device")

    def device(self, name=None, description=None):
        # type: (str,str) -> DeviceIter
        """Factory method that creates an instance of the Device class

        A subgraph container for device and its components, links and edges.. The edges form subgraph of the device.

        Returns: DeviceIter
        """
        item = Device(parent=self._parent, name=name, description=description)
        self._add(item)
        return self

    def add(self, name=None, description=None):
        # type: (str,str) -> Device
        """Add method that creates and returns an instance of the Device class

        A subgraph container for device and its components, links and edges.. The edges form subgraph of the device.

        Returns: Device
        """
        item = Device(parent=self._parent, name=name, description=description)
        self._add(item)
        return item


class Instance(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "name": {
            "type": str,
            "pattern": r"^[\sa-zA-Z0-9-_()><\[\]]+$",
        },
        "description": {"type": str},
        "device": {"type": str},
        "count": {
            "type": int,
            "format": "int32",
        },
    }  # type: Dict[str, str]

    _REQUIRED = ("name", "device", "count")  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self, parent=None, name=None, description=None, device=None, count=None
    ):
        super(Instance, self).__init__()
        self._parent = parent
        self._set_property("name", name)
        self._set_property("description", description)
        self._set_property("device", device)
        self._set_property("count", count)

    def set(self, name=None, description=None, device=None, count=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def name(self):
        # type: () -> str
        """name getter

        An alias for the device that MUST be used in the Infrastructure edge object.. Globally unique name of an object. It also serves as the primary key for arrays of objects.

        Returns: str
        """
        return self._get_property("name")

    @name.setter
    def name(self, value):
        """name setter

        An alias for the device that MUST be used in the Infrastructure edge object.. Globally unique name of an object. It also serves as the primary key for arrays of objects.

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property name as None")
        self._set_property("name", value)

    @property
    def description(self):
        # type: () -> str
        """description getter

        A description of the instance.

        Returns: str
        """
        return self._get_property("description")

    @description.setter
    def description(self, value):
        """description setter

        A description of the instance.

        value: str
        """
        self._set_property("description", value)

    @property
    def device(self):
        # type: () -> str
        """device getter

        The name of device that MUST exist in the array of Infrastructure devices.

        Returns: str
        """
        return self._get_property("device")

    @device.setter
    def device(self, value):
        """device setter

        The name of device that MUST exist in the array of Infrastructure devices.

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property device as None")
        self._set_property("device", value)

    @property
    def count(self):
        # type: () -> int
        """count getter

        The maximum number of instances that will be created as nodes in the graph.. Not all the instances need to be used in the graph edges.

        Returns: int
        """
        return self._get_property("count")

    @count.setter
    def count(self, value):
        """count setter

        The maximum number of instances that will be created as nodes in the graph.. Not all the instances need to be used in the graph edges.

        value: int
        """
        if value is None:
            raise TypeError("Cannot set required property count as None")
        self._set_property("count", value)


class InstanceIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(InstanceIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[Instance]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> InstanceIter
        return self._iter()

    def __next__(self):
        # type: () -> Instance
        return self._next()

    def next(self):
        # type: () -> Instance
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, Instance):
            raise Exception("Item is not an instance of Instance")

    def instance(self, name=None, description=None, device=None, count=None):
        # type: (str,str,str,int) -> InstanceIter
        """Factory method that creates an instance of the Instance class

        TBD

        Returns: InstanceIter
        """
        item = Instance(
            parent=self._parent,
            name=name,
            description=description,
            device=device,
            count=count,
        )
        self._add(item)
        return self

    def add(self, name=None, description=None, device=None, count=None):
        # type: (str,str,str,int) -> Instance
        """Add method that creates and returns an instance of the Instance class

        TBD

        Returns: Instance
        """
        item = Instance(
            parent=self._parent,
            name=name,
            description=description,
            device=device,
            count=count,
        )
        self._add(item)
        return item


class InfrastructureEdge(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "ep1": {"type": "InfrastructureEndpoint"},
        "ep2": {"type": "InfrastructureEndpoint"},
        "scheme": {
            "type": str,
            "enum": [
                "one2one",
                "many2many",
                "ring",
            ],
        },
        "link": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ("ep1", "ep2", "link")  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    ONE2ONE = "one2one"  # type: str
    MANY2MANY = "many2many"  # type: str
    RING = "ring"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, scheme=None, link=None):
        super(InfrastructureEdge, self).__init__()
        self._parent = parent
        self._set_property("scheme", scheme)
        self._set_property("link", link)

    def set(self, scheme=None, link=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def ep1(self):
        # type: () -> InfrastructureEndpoint
        """ep1 getter

        A device and component that is one endpoint of the edge

        Returns: InfrastructureEndpoint
        """
        return self._get_property("ep1", InfrastructureEndpoint)

    @property
    def ep2(self):
        # type: () -> InfrastructureEndpoint
        """ep2 getter

        A device and component that is the other endpoint of the edge

        Returns: InfrastructureEndpoint
        """
        return self._get_property("ep2", InfrastructureEndpoint)

    @property
    def scheme(self):
        # type: () -> Union[Literal["many2many"], Literal["one2one"], Literal["ring"]]
        """scheme getter

        The scheme that will be used to create edges between the endpoints ep1 and ep2.

        Returns: Union[Literal["many2many"], Literal["one2one"], Literal["ring"]]
        """
        return self._get_property("scheme")

    @scheme.setter
    def scheme(self, value):
        """scheme setter

        The scheme that will be used to create edges between the endpoints ep1 and ep2.

        value: Union[Literal["many2many"], Literal["one2one"], Literal["ring"]]
        """
        self._set_property("scheme", value)

    @property
    def link(self):
        # type: () -> str
        """link getter

        The name of link that defines additional characteristics of the edge.. The name MUST exist in the links array of the infrastructure.

        Returns: str
        """
        return self._get_property("link")

    @link.setter
    def link(self, value):
        """link setter

        The name of link that defines additional characteristics of the edge.. The name MUST exist in the links array of the infrastructure.

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property link as None")
        self._set_property("link", value)


class InfrastructureEndpoint(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "instance": {"type": str},
        "component": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ("instance", "component")  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, instance=None, component=None):
        super(InfrastructureEndpoint, self).__init__()
        self._parent = parent
        self._set_property("instance", instance)
        self._set_property("component", component)

    def set(self, instance=None, component=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def instance(self):
        # type: () -> str
        """instance getter

        A name that matches the Instance.name property of an instance object that MUST exist in the infrastructure instances array.. The instance object yields:. a device name that contains the component and MUST exist in the infrastructure devices. a count that is the maximum to be used in the slice notation. The indexes MUST be specified using python slice notation.. example: host[0:2]

        Returns: str
        """
        return self._get_property("instance")

    @instance.setter
    def instance(self, value):
        """instance setter

        A name that matches the Instance.name property of an instance object that MUST exist in the infrastructure instances array.. The instance object yields:. a device name that contains the component and MUST exist in the infrastructure devices. a count that is the maximum to be used in the slice notation. The indexes MUST be specified using python slice notation.. example: host[0:2]

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property instance as None")
        self._set_property("instance", value)

    @property
    def component(self):
        # type: () -> str
        """component getter

        The name of component that MUST exist in the Instance.device specified by the instance object in the Infrastructure.instances array.. The indexes MUST be specified using python slice notation.. example: npu[0:2]

        Returns: str
        """
        return self._get_property("component")

    @component.setter
    def component(self, value):
        """component setter

        The name of component that MUST exist in the Instance.device specified by the instance object in the Infrastructure.instances array.. The indexes MUST be specified using python slice notation.. example: npu[0:2]

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property component as None")
        self._set_property("component", value)


class InfrastructureEdgeIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(InfrastructureEdgeIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[InfrastructureEdge]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> InfrastructureEdgeIter
        return self._iter()

    def __next__(self):
        # type: () -> InfrastructureEdge
        return self._next()

    def next(self):
        # type: () -> InfrastructureEdge
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, InfrastructureEdge):
            raise Exception("Item is not an instance of InfrastructureEdge")

    def edge(self, scheme=None, link=None):
        # type: (Union[Literal["many2many"], Literal["one2one"], Literal["ring"]],str) -> InfrastructureEdgeIter
        """Factory method that creates an instance of the InfrastructureEdge class

        TBD

        Returns: InfrastructureEdgeIter
        """
        item = InfrastructureEdge(parent=self._parent, scheme=scheme, link=link)
        self._add(item)
        return self

    def add(self, scheme=None, link=None):
        # type: (Union[Literal["many2many"], Literal["one2one"], Literal["ring"]],str) -> InfrastructureEdge
        """Add method that creates and returns an instance of the InfrastructureEdge class

        TBD

        Returns: InfrastructureEdge
        """
        item = InfrastructureEdge(parent=self._parent, scheme=scheme, link=link)
        self._add(item)
        return item


class Annotations(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "link_specifications": {"type": "AnnotationLinkSpecificationsIter"},
        "device_specifications": {"type": "AnnotationDeviceSpecificationsIter"},
        "rank_assignment": {"type": "AnnotationRankAssignmentIter"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(Annotations, self).__init__()
        self._parent = parent

    @property
    def link_specifications(self):
        # type: () -> AnnotationLinkSpecificationsIter
        """link_specifications getter

        TBD

        Returns: AnnotationLinkSpecificationsIter
        """
        return self._get_property(
            "link_specifications",
            AnnotationLinkSpecificationsIter,
            self._parent,
            self._choice,
        )

    @property
    def device_specifications(self):
        # type: () -> AnnotationDeviceSpecificationsIter
        """device_specifications getter

        TBD

        Returns: AnnotationDeviceSpecificationsIter
        """
        return self._get_property(
            "device_specifications",
            AnnotationDeviceSpecificationsIter,
            self._parent,
            self._choice,
        )

    @property
    def rank_assignment(self):
        # type: () -> AnnotationRankAssignmentIter
        """rank_assignment getter

        TBD

        Returns: AnnotationRankAssignmentIter
        """
        return self._get_property(
            "rank_assignment", AnnotationRankAssignmentIter, self._parent, self._choice
        )


class AnnotationLinkSpecifications(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "link_name": {"type": str},
        "packet_loss_rate": {
            "type": float,
            "format": "float",
        },
        "link_error_rate": {
            "type": float,
            "format": "float",
        },
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self, parent=None, link_name=None, packet_loss_rate=None, link_error_rate=None
    ):
        super(AnnotationLinkSpecifications, self).__init__()
        self._parent = parent
        self._set_property("link_name", link_name)
        self._set_property("packet_loss_rate", packet_loss_rate)
        self._set_property("link_error_rate", link_error_rate)

    def set(self, link_name=None, packet_loss_rate=None, link_error_rate=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def link_name(self):
        # type: () -> str
        """link_name getter

        The name of the device defined in infragraph

        Returns: str
        """
        return self._get_property("link_name")

    @link_name.setter
    def link_name(self, value):
        """link_name setter

        The name of the device defined in infragraph

        value: str
        """
        self._set_property("link_name", value)

    @property
    def packet_loss_rate(self):
        # type: () -> float
        """packet_loss_rate getter

        The packet loss rate on the link as percentage

        Returns: float
        """
        return self._get_property("packet_loss_rate")

    @packet_loss_rate.setter
    def packet_loss_rate(self, value):
        """packet_loss_rate setter

        The packet loss rate on the link as percentage

        value: float
        """
        self._set_property("packet_loss_rate", value)

    @property
    def link_error_rate(self):
        # type: () -> float
        """link_error_rate getter

        The link error rate indicating transmission errors

        Returns: float
        """
        return self._get_property("link_error_rate")

    @link_error_rate.setter
    def link_error_rate(self, value):
        """link_error_rate setter

        The link error rate indicating transmission errors

        value: float
        """
        self._set_property("link_error_rate", value)


class AnnotationLinkSpecificationsIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(AnnotationLinkSpecificationsIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[AnnotationLinkSpecifications]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> AnnotationLinkSpecificationsIter
        return self._iter()

    def __next__(self):
        # type: () -> AnnotationLinkSpecifications
        return self._next()

    def next(self):
        # type: () -> AnnotationLinkSpecifications
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, AnnotationLinkSpecifications):
            raise Exception("Item is not an instance of AnnotationLinkSpecifications")

    def specifications(
        self, link_name=None, packet_loss_rate=None, link_error_rate=None
    ):
        # type: (str,float,float) -> AnnotationLinkSpecificationsIter
        """Factory method that creates an instance of the AnnotationLinkSpecifications class

        The link specifications including name, packet loss, and error rates

        Returns: AnnotationLinkSpecificationsIter
        """
        item = AnnotationLinkSpecifications(
            parent=self._parent,
            link_name=link_name,
            packet_loss_rate=packet_loss_rate,
            link_error_rate=link_error_rate,
        )
        self._add(item)
        return self

    def add(self, link_name=None, packet_loss_rate=None, link_error_rate=None):
        # type: (str,float,float) -> AnnotationLinkSpecifications
        """Add method that creates and returns an instance of the AnnotationLinkSpecifications class

        The link specifications including name, packet loss, and error rates

        Returns: AnnotationLinkSpecifications
        """
        item = AnnotationLinkSpecifications(
            parent=self._parent,
            link_name=link_name,
            packet_loss_rate=packet_loss_rate,
            link_error_rate=link_error_rate,
        )
        self._add(item)
        return item


class AnnotationDeviceSpecifications(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "device_name": {"type": str},
        "device_type": {
            "type": str,
            "enum": [
                "host",
                "switch",
            ],
        },
        "device_latency_ms": {
            "type": float,
            "format": "float",
        },
        "device_bandwidth_gbps": {
            "type": float,
            "format": "float",
        },
        "radix_up": {
            "type": float,
            "format": "int32",
        },
        "radix_down": {
            "type": float,
            "format": "int32",
        },
        "queue_up": {
            "type": float,
            "format": "int32",
        },
        "queue_down": {
            "type": float,
            "format": "int32",
        },
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    HOST = "host"  # type: str
    SWITCH = "switch"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self,
        parent=None,
        device_name=None,
        device_type=None,
        device_latency_ms=None,
        device_bandwidth_gbps=None,
        radix_up=None,
        radix_down=None,
        queue_up=None,
        queue_down=None,
    ):
        super(AnnotationDeviceSpecifications, self).__init__()
        self._parent = parent
        self._set_property("device_name", device_name)
        self._set_property("device_type", device_type)
        self._set_property("device_latency_ms", device_latency_ms)
        self._set_property("device_bandwidth_gbps", device_bandwidth_gbps)
        self._set_property("radix_up", radix_up)
        self._set_property("radix_down", radix_down)
        self._set_property("queue_up", queue_up)
        self._set_property("queue_down", queue_down)

    def set(
        self,
        device_name=None,
        device_type=None,
        device_latency_ms=None,
        device_bandwidth_gbps=None,
        radix_up=None,
        radix_down=None,
        queue_up=None,
        queue_down=None,
    ):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def device_name(self):
        # type: () -> str
        """device_name getter

        The name of the device defined in infragraph

        Returns: str
        """
        return self._get_property("device_name")

    @device_name.setter
    def device_name(self, value):
        """device_name setter

        The name of the device defined in infragraph

        value: str
        """
        self._set_property("device_name", value)

    @property
    def device_type(self):
        # type: () -> Union[Literal["host"], Literal["switch"]]
        """device_type getter

        The type of device host or switch

        Returns: Union[Literal["host"], Literal["switch"]]
        """
        return self._get_property("device_type")

    @device_type.setter
    def device_type(self, value):
        """device_type setter

        The type of device host or switch

        value: Union[Literal["host"], Literal["switch"]]
        """
        self._set_property("device_type", value)

    @property
    def device_latency_ms(self):
        # type: () -> float
        """device_latency_ms getter

        The latency of the device in milliseconds

        Returns: float
        """
        return self._get_property("device_latency_ms")

    @device_latency_ms.setter
    def device_latency_ms(self, value):
        """device_latency_ms setter

        The latency of the device in milliseconds

        value: float
        """
        self._set_property("device_latency_ms", value)

    @property
    def device_bandwidth_gbps(self):
        # type: () -> float
        """device_bandwidth_gbps getter

        The bandwidth capacity of the device in Gbps

        Returns: float
        """
        return self._get_property("device_bandwidth_gbps")

    @device_bandwidth_gbps.setter
    def device_bandwidth_gbps(self, value):
        """device_bandwidth_gbps setter

        The bandwidth capacity of the device in Gbps

        value: float
        """
        self._set_property("device_bandwidth_gbps", value)

    @property
    def radix_up(self):
        # type: () -> float
        """radix_up getter

        Number of upward radix connections

        Returns: float
        """
        return self._get_property("radix_up")

    @radix_up.setter
    def radix_up(self, value):
        """radix_up setter

        Number of upward radix connections

        value: float
        """
        self._set_property("radix_up", value)

    @property
    def radix_down(self):
        # type: () -> float
        """radix_down getter

        Number of downward radix connections

        Returns: float
        """
        return self._get_property("radix_down")

    @radix_down.setter
    def radix_down(self, value):
        """radix_down setter

        Number of downward radix connections

        value: float
        """
        self._set_property("radix_down", value)

    @property
    def queue_up(self):
        # type: () -> float
        """queue_up getter

        Number of packets in the upward queue

        Returns: float
        """
        return self._get_property("queue_up")

    @queue_up.setter
    def queue_up(self, value):
        """queue_up setter

        Number of packets in the upward queue

        value: float
        """
        self._set_property("queue_up", value)

    @property
    def queue_down(self):
        # type: () -> float
        """queue_down getter

        Number of packets in the downward queue

        Returns: float
        """
        return self._get_property("queue_down")

    @queue_down.setter
    def queue_down(self, value):
        """queue_down setter

        Number of packets in the downward queue

        value: float
        """
        self._set_property("queue_down", value)


class AnnotationDeviceSpecificationsIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(AnnotationDeviceSpecificationsIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[AnnotationDeviceSpecifications]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> AnnotationDeviceSpecificationsIter
        return self._iter()

    def __next__(self):
        # type: () -> AnnotationDeviceSpecifications
        return self._next()

    def next(self):
        # type: () -> AnnotationDeviceSpecifications
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, AnnotationDeviceSpecifications):
            raise Exception("Item is not an instance of AnnotationDeviceSpecifications")

    def specifications(
        self,
        device_name=None,
        device_type=None,
        device_latency_ms=None,
        device_bandwidth_gbps=None,
        radix_up=None,
        radix_down=None,
        queue_up=None,
        queue_down=None,
    ):
        # type: (str,Union[Literal["host"], Literal["switch"]],float,float,float,float,float,float) -> AnnotationDeviceSpecificationsIter
        """Factory method that creates an instance of the AnnotationDeviceSpecifications class

        Specifications of device including its name, type, latency, bandwidth, and queue details

        Returns: AnnotationDeviceSpecificationsIter
        """
        item = AnnotationDeviceSpecifications(
            parent=self._parent,
            device_name=device_name,
            device_type=device_type,
            device_latency_ms=device_latency_ms,
            device_bandwidth_gbps=device_bandwidth_gbps,
            radix_up=radix_up,
            radix_down=radix_down,
            queue_up=queue_up,
            queue_down=queue_down,
        )
        self._add(item)
        return self

    def add(
        self,
        device_name=None,
        device_type=None,
        device_latency_ms=None,
        device_bandwidth_gbps=None,
        radix_up=None,
        radix_down=None,
        queue_up=None,
        queue_down=None,
    ):
        # type: (str,Union[Literal["host"], Literal["switch"]],float,float,float,float,float,float) -> AnnotationDeviceSpecifications
        """Add method that creates and returns an instance of the AnnotationDeviceSpecifications class

        Specifications of device including its name, type, latency, bandwidth, and queue details

        Returns: AnnotationDeviceSpecifications
        """
        item = AnnotationDeviceSpecifications(
            parent=self._parent,
            device_name=device_name,
            device_type=device_type,
            device_latency_ms=device_latency_ms,
            device_bandwidth_gbps=device_bandwidth_gbps,
            radix_up=radix_up,
            radix_down=radix_down,
            queue_up=queue_up,
            queue_down=queue_down,
        )
        self._add(item)
        return item


class AnnotationRankAssignment(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "rank_identifier": {
            "type": float,
            "format": "int32",
        },
        "npu_identifier": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, rank_identifier=None, npu_identifier=None):
        super(AnnotationRankAssignment, self).__init__()
        self._parent = parent
        self._set_property("rank_identifier", rank_identifier)
        self._set_property("npu_identifier", npu_identifier)

    def set(self, rank_identifier=None, npu_identifier=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def rank_identifier(self):
        # type: () -> float
        """rank_identifier getter

        The rank identifier of an NPU component

        Returns: float
        """
        return self._get_property("rank_identifier")

    @rank_identifier.setter
    def rank_identifier(self, value):
        """rank_identifier setter

        The rank identifier of an NPU component

        value: float
        """
        self._set_property("rank_identifier", value)

    @property
    def npu_identifier(self):
        # type: () -> str
        """npu_identifier getter

        The npu identifier given as device_instance.index.npu_component.index

        Returns: str
        """
        return self._get_property("npu_identifier")

    @npu_identifier.setter
    def npu_identifier(self, value):
        """npu_identifier setter

        The npu identifier given as device_instance.index.npu_component.index

        value: str
        """
        self._set_property("npu_identifier", value)


class AnnotationRankAssignmentIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(AnnotationRankAssignmentIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[AnnotationRankAssignment]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> AnnotationRankAssignmentIter
        return self._iter()

    def __next__(self):
        # type: () -> AnnotationRankAssignment
        return self._next()

    def next(self):
        # type: () -> AnnotationRankAssignment
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, AnnotationRankAssignment):
            raise Exception("Item is not an instance of AnnotationRankAssignment")

    def assignment(self, rank_identifier=None, npu_identifier=None):
        # type: (float,str) -> AnnotationRankAssignmentIter
        """Factory method that creates an instance of the AnnotationRankAssignment class

        Specifications of rank assignment with the rank identifier and the npu identifier as device_instance.index.npu_component.index

        Returns: AnnotationRankAssignmentIter
        """
        item = AnnotationRankAssignment(
            parent=self._parent,
            rank_identifier=rank_identifier,
            npu_identifier=npu_identifier,
        )
        self._add(item)
        return self

    def add(self, rank_identifier=None, npu_identifier=None):
        # type: (float,str) -> AnnotationRankAssignment
        """Add method that creates and returns an instance of the AnnotationRankAssignment class

        Specifications of rank assignment with the rank identifier and the npu identifier as device_instance.index.npu_component.index

        Returns: AnnotationRankAssignment
        """
        item = AnnotationRankAssignment(
            parent=self._parent,
            rank_identifier=rank_identifier,
            npu_identifier=npu_identifier,
        )
        self._add(item)
        return item


class ControlStatus(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "status": {
            "type": str,
            "enum": [
                "running",
                "completed",
                "failed",
                "terminated",
                "inactive",
            ],
        },
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    RUNNING = "running"  # type: str
    COMPLETED = "completed"  # type: str
    FAILED = "failed"  # type: str
    TERMINATED = "terminated"  # type: str
    INACTIVE = "inactive"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, status=None):
        super(ControlStatus, self).__init__()
        self._parent = parent
        self._set_property("status", status)

    def set(self, status=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def status(self):
        # type: () -> Union[Literal["completed"], Literal["failed"], Literal["inactive"], Literal["running"], Literal["terminated"]]
        """status getter

        TBD

        Returns: Union[Literal["completed"], Literal["failed"], Literal["inactive"], Literal["running"], Literal["terminated"]]
        """
        return self._get_property("status")

    @status.setter
    def status(self, value):
        """status setter

        TBD

        value: Union[Literal["completed"], Literal["failed"], Literal["inactive"], Literal["running"], Literal["terminated"]]
        """
        self._set_property("status", value)


class Control(OpenApiObject):
    __slots__ = ("_parent", "_choice")

    _TYPES = {
        "choice": {
            "type": str,
            "enum": [
                "start",
                "stop",
            ],
        },
        "start": {"type": "ControlStart"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    START = "start"  # type: str
    STOP = "stop"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, choice=None):
        super(Control, self).__init__()
        self._parent = parent
        if (
            "choice" in self._DEFAULTS
            and choice is None
            and self._DEFAULTS["choice"] in self._TYPES
        ):
            getattr(self, self._DEFAULTS["choice"])
        else:
            self._set_property("choice", choice)

    @property
    def start(self):
        # type: () -> ControlStart
        """Factory property that returns an instance of the ControlStart class

        Specifies the operation to set control to specific network backend, allowing the user to initiate an action on the selected backend.

        Returns: ControlStart
        """
        return self._get_property("start", ControlStart, self, "start")

    @property
    def choice(self):
        # type: () -> Union[Literal["start"], Literal["stop"]]
        """choice getter

        Represents control interface that allows users to choose between starting or stopping ASTRA-sim simulation. Only one action start or stop— can be performed at time. Users must specify either the configuration to start backend or the command to stop it, ensuring that these actions are mutually exclusive within single operation.

        Returns: Union[Literal["start"], Literal["stop"]]
        """
        return self._get_property("choice")

    @choice.setter
    def choice(self, value):
        """choice setter

        Represents control interface that allows users to choose between starting or stopping ASTRA-sim simulation. Only one action start or stop— can be performed at time. Users must specify either the configuration to start backend or the command to stop it, ensuring that these actions are mutually exclusive within single operation.

        value: Union[Literal["start"], Literal["stop"]]
        """
        self._set_property("choice", value)


class ControlStart(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "backend": {
            "type": str,
            "enum": [
                "analytical_congestion_aware",
                "analytical_congestion_unaware",
                "custom",
                "htsim",
                "ns3",
            ],
        },
    }  # type: Dict[str, str]

    _REQUIRED = ("backend",)  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    ANALYTICAL_CONGESTION_AWARE = "analytical_congestion_aware"  # type: str
    ANALYTICAL_CONGESTION_UNAWARE = "analytical_congestion_unaware"  # type: str
    CUSTOM = "custom"  # type: str
    HTSIM = "htsim"  # type: str
    NS3 = "ns3"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, backend=None):
        super(ControlStart, self).__init__()
        self._parent = parent
        self._set_property("backend", backend)

    def set(self, backend=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def backend(self):
        # type: () -> Union[Literal["analytical_congestion_aware"], Literal["analytical_congestion_unaware"], Literal["custom"], Literal["htsim"], Literal["ns3"]]
        """backend getter

        The name of the backend to control. This string must match one of the allowed backend names (as defined in the enumerated list), specifying which backend to activate or interact with.

        Returns: Union[Literal["analytical_congestion_aware"], Literal["analytical_congestion_unaware"], Literal["custom"], Literal["htsim"], Literal["ns3"]]
        """
        return self._get_property("backend")

    @backend.setter
    def backend(self, value):
        """backend setter

        The name of the backend to control. This string must match one of the allowed backend names (as defined in the enumerated list), specifying which backend to activate or interact with.

        value: Union[Literal["analytical_congestion_aware"], Literal["analytical_congestion_unaware"], Literal["custom"], Literal["htsim"], Literal["ns3"]]
        """
        if value is None:
            raise TypeError("Cannot set required property backend as None")
        self._set_property("backend", value)


class Result(OpenApiObject):
    __slots__ = ("_parent", "_choice")

    _TYPES = {
        "choice": {
            "type": str,
            "enum": [
                "metadata",
                "filename",
            ],
        },
        "filename": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    METADATA = "metadata"  # type: str
    FILENAME = "filename"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, choice=None, filename=None):
        super(Result, self).__init__()
        self._parent = parent
        self._set_property("filename", filename)
        if (
            "choice" in self._DEFAULTS
            and choice is None
            and self._DEFAULTS["choice"] in self._TYPES
        ):
            getattr(self, self._DEFAULTS["choice"])
        else:
            self._set_property("choice", choice)

    def set(self, filename=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def choice(self):
        # type: () -> Union[Literal["filename"], Literal["metadata"]]
        """choice getter

        The type of result required: metadata or file.

        Returns: Union[Literal["filename"], Literal["metadata"]]
        """
        return self._get_property("choice")

    @choice.setter
    def choice(self, value):
        """choice setter

        The type of result required: metadata or file.

        value: Union[Literal["filename"], Literal["metadata"]]
        """
        self._set_property("choice", value)

    @property
    def filename(self):
        # type: () -> str
        """filename getter

        A single file metadata object describing filename which is associated with the result.

        Returns: str
        """
        return self._get_property("filename")

    @filename.setter
    def filename(self, value):
        """filename setter

        A single file metadata object describing filename which is associated with the result.

        value: str
        """
        self._set_property("filename", value, "filename")


class Version(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "api_spec_version": {"type": str},
        "sdk_version": {"type": str},
        "app_version": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {
        "api_spec_version": "",
        "sdk_version": "",
        "app_version": "",
    }  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self, parent=None, api_spec_version="", sdk_version="", app_version=""
    ):
        super(Version, self).__init__()
        self._parent = parent
        self._set_property("api_spec_version", api_spec_version)
        self._set_property("sdk_version", sdk_version)
        self._set_property("app_version", app_version)

    def set(self, api_spec_version=None, sdk_version=None, app_version=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def api_spec_version(self):
        # type: () -> str
        """api_spec_version getter

        Version of API specification

        Returns: str
        """
        return self._get_property("api_spec_version")

    @api_spec_version.setter
    def api_spec_version(self, value):
        """api_spec_version setter

        Version of API specification

        value: str
        """
        self._set_property("api_spec_version", value)

    @property
    def sdk_version(self):
        # type: () -> str
        """sdk_version getter

        Version of SDK generated from API specification

        Returns: str
        """
        return self._get_property("sdk_version")

    @sdk_version.setter
    def sdk_version(self, value):
        """sdk_version setter

        Version of SDK generated from API specification

        value: str
        """
        self._set_property("sdk_version", value)

    @property
    def app_version(self):
        # type: () -> str
        """app_version getter

        Version of application consuming or serving the API

        Returns: str
        """
        return self._get_property("app_version")

    @app_version.setter
    def app_version(self, value):
        """app_version setter

        Version of application consuming or serving the API

        value: str
        """
        self._set_property("app_version", value)


class Api(object):
    """OpenApi Abstract API"""

    __warnings__ = []

    def __init__(self, **kwargs):
        self._version_meta = self.version()
        self._version_meta.api_spec_version = "1.0.0"
        self._version_meta.sdk_version = "1.0.0"
        self._version_check = kwargs.get("version_check")
        if self._version_check is None:
            self._version_check = False
        self._version_check_err = None
        self._client_name = None
        self._client_ver = None
        self._server_name = None
        endpoint = kwargs.get("otel_collector")
        transport = kwargs.get("otel_collector_transport")
        self._telemetry = Telemetry(endpoint, transport)

    def tracer(self):
        return self._telemetry._tracer

    def add_warnings(self, msg):
        print("[WARNING]: %s" % msg, file=sys.stderr)
        self.__warnings__.append(msg)

    def _deserialize_error(self, err_string):
        # type: (str) -> Union[Error, None]
        err = self.error()
        try:
            err.deserialize(err_string)
        except Exception:
            err = None
        return err

    def from_exception(self, error):
        # type: (Exception) -> Union[Error, None]
        if isinstance(error, Error):
            return error
        elif isinstance(error, grpc.RpcError):
            err = self._deserialize_error(error.details())
            if err is not None:
                return err
            err = self.error()
            err.code = error.code().value[0]
            err.errors = [error.details()]
            return err
        elif isinstance(error, Exception):
            if len(error.args) != 1:
                return None
            if isinstance(error.args[0], Error):
                return error.args[0]
            elif isinstance(error.args[0], str):
                return self._deserialize_error(error.args[0])

    def upload_config(self, payload):
        """POST /upload_config

        TBD

        Return: serverresponse
        """
        raise NotImplementedError("upload_config")

    def set_config(self, payload):
        """POST /set_config

        TBD

        Return: serverresponse
        """
        raise NotImplementedError("set_config")

    def get_config(self):
        """POST /get_config

        TBD

        Return: None
        """
        raise NotImplementedError("get_config")

    def get_status(self):
        """POST /get_status

        TBD

        Return: control_status
        """
        raise NotImplementedError("get_status")

    def set_control_action(self, payload):
        """POST /set_control_action

        TBD

        Return: serverresponse
        """
        raise NotImplementedError("set_control_action")

    def get_result(self, payload):
        """POST /result

        TBD

        Return: None
        """
        raise NotImplementedError("get_result")

    def get_version(self):
        """GET /capabilities/version

        TBD

        Return: version
        """
        raise NotImplementedError("get_version")

    def serverresponse(self):
        """Factory method that creates an instance of ServerResponse

        Return: ServerResponse
        """
        return ServerResponse()

    def error(self):
        """Factory method that creates an instance of Error

        Return: Error
        """
        return Error()

    def config(self):
        """Factory method that creates an instance of Config

        Return: Config
        """
        return Config()

    def control_status(self):
        """Factory method that creates an instance of ControlStatus

        Return: ControlStatus
        """
        return ControlStatus()

    def control(self):
        """Factory method that creates an instance of Control

        Return: Control
        """
        return Control()

    def result(self):
        """Factory method that creates an instance of Result

        Return: Result
        """
        return Result()

    def version(self):
        """Factory method that creates an instance of Version

        Return: Version
        """
        return Version()

    def close(self):
        pass

    def set_component_info(self, client_name, client_version, server_name):
        self._client_name = client_name
        self._client_app_ver = client_version
        self._server_name = server_name

    def _check_client_server_version_compatibility(
        self, client_ver, server_ver, component_name
    ):
        try:
            c = semantic_version.Version(client_ver)
        except Exception as e:
            raise AssertionError(
                "Client {} version '{}' is not a valid semver: {}".format(
                    component_name, client_ver, e
                )
            )

        try:
            s = semantic_version.SimpleSpec(server_ver)
        except Exception as e:
            raise AssertionError(
                "Server {} version '{}' is not a valid semver: {}".format(
                    component_name, server_ver, e
                )
            )

        err = "Client {} version '{}' is not semver compatible with Server {} version '{}'".format(
            component_name, client_ver, component_name, server_ver
        )

        if not s.match(c):
            raise Exception(err)

    def get_local_version(self):
        log.info("Local Version is " + str(self._version_meta))
        return self._version_meta

    def get_remote_version(self):
        log.info("Remote Version is " + str(self.get_version()))
        return self.get_version()

    def check_version_compatibility(self):
        comp_err, api_err = self._do_version_check()
        if comp_err is not None:
            raise comp_err
        if api_err is not None:
            raise api_err

    def _do_version_check(self):
        local = self.get_local_version()
        try:
            remote = self.get_remote_version()
        except Exception as e:
            return None, e

        try:
            self._check_client_server_version_compatibility(
                local.api_spec_version, remote.api_spec_version, "API spec"
            )
        except Exception as e:
            if self._client_name is not None:
                msg = "{} {} is not compatible with {} {}".format(
                    self._client_name,
                    self._client_app_ver,
                    self._server_name,
                    remote.app_version,
                )
                return Exception(msg), None
            else:
                msg = "client SDK version '{}' is not compatible with server SDK version '{}'".format(
                    local.sdk_version, remote.sdk_version
                )
                return Exception("{}: {}".format(msg, str(e))), None

        return None, None

    def _do_version_check_once(self):
        if not self._version_check:
            return

        if self._version_check_err is not None:
            raise self._version_check_err

        comp_err, api_err = self._do_version_check()
        if comp_err is not None:
            self._version_check_err = comp_err
            raise comp_err
        if api_err is not None:
            self._version_check_err = None
            raise api_err

        self._version_check = False
        self._version_check_err = None


class HttpApi(Api):
    """OpenAPI HTTP Api"""

    def __init__(self, **kwargs):
        super(HttpApi, self).__init__(**kwargs)
        self._transport = HttpTransport(**kwargs)
        self._telemetry.initiate_http_instrumentation()

    @property
    def verify(self):
        return self._transport.verify

    @verify.setter
    def verify(self, value):
        self._transport.set_verify(value)

    @Telemetry.create_child_span
    def upload_config(self, payload):
        """POST /upload_config

        TBD

        Return: serverresponse
        """
        log.info("Executing upload_config")
        self._do_version_check_once()
        return self._transport.send_recv(
            "post",
            "/upload_config",
            payload=payload,
            return_object=self.serverresponse(),
        )

    @Telemetry.create_child_span
    def set_config(self, payload):
        """POST /set_config

        TBD

        Return: serverresponse
        """
        log.info("Executing set_config")
        self._do_version_check_once()
        return self._transport.send_recv(
            "post",
            "/set_config",
            payload=payload,
            return_object=self.serverresponse(),
            request_class=Config,
        )

    @Telemetry.create_child_span
    def get_config(self):
        """POST /get_config

        TBD

        Return: None
        """
        log.info("Executing get_config")
        self._do_version_check_once()
        return self._transport.send_recv(
            "post",
            "/get_config",
            payload=None,
            return_object=None,
        )

    @Telemetry.create_child_span
    def get_status(self):
        """POST /get_status

        TBD

        Return: control_status
        """
        log.info("Executing get_status")
        self._do_version_check_once()
        return self._transport.send_recv(
            "post",
            "/get_status",
            payload=None,
            return_object=self.control_status(),
        )

    @Telemetry.create_child_span
    def set_control_action(self, payload):
        """POST /set_control_action

        TBD

        Return: serverresponse
        """
        log.info("Executing set_control_action")
        self._do_version_check_once()
        return self._transport.send_recv(
            "post",
            "/set_control_action",
            payload=payload,
            return_object=self.serverresponse(),
            request_class=Control,
        )

    @Telemetry.create_child_span
    def get_result(self, payload):
        """POST /result

        TBD

        Return: None
        """
        log.info("Executing get_result")
        self._do_version_check_once()
        return self._transport.send_recv(
            "post",
            "/result",
            payload=payload,
            return_object=None,
            request_class=Result,
        )

    @Telemetry.create_child_span
    def get_version(self):
        """GET /capabilities/version

        TBD

        Return: version
        """
        log.info("Executing get_version")
        return self._transport.send_recv(
            "get",
            "/capabilities/version",
            payload=None,
            return_object=self.version(),
        )


class GrpcApi(Api):
    # OpenAPI gRPC Api
    def __init__(self, **kwargs):
        super(GrpcApi, self).__init__(**kwargs)
        self._stub = None
        self._channel = None
        self._cert = None
        self._cert_domain = None
        self._request_timeout = 10
        self._keep_alive_timeout = 10 * 1000
        self._maximum_receive_buffer_size = 4 * 1024 * 1024
        self.enable_grpc_streaming = False
        self._chunk_size = 4 * 1024 * 1024
        self._location = (
            kwargs["location"]
            if "location" in kwargs and kwargs["location"] is not None
            else "localhost:50051"
        )
        self._transport = kwargs["transport"] if "transport" in kwargs else None
        log.debug(
            "gRPCTransport args: {}".format(
                ", ".join(["{}={!r}".format(k, v) for k, v in kwargs.items()])
            )
        )
        self._telemetry.initiate_grpc_instrumentation()

    def _use_secure_connection(self, cert_path, cert_domain=None):
        """Accepts certificate and host_name for SSL Connection."""
        if cert_path is None:
            raise Exception("path to certificate cannot be None")
        self._cert = cert_path
        self._cert_domain = cert_domain

    def _get_stub(self):
        if self._stub is None:
            CHANNEL_OPTIONS = [
                ("grpc.enable_retries", 0),
                ("grpc.keepalive_timeout_ms", self._keep_alive_timeout),
                ("grpc.max_receive_message_length", self._maximum_receive_buffer_size),
            ]
            if self._cert is None:
                self._channel = grpc.insecure_channel(
                    self._location, options=CHANNEL_OPTIONS
                )
            else:
                crt = open(self._cert, "rb").read()
                creds = grpc.ssl_channel_credentials(crt)
                if self._cert_domain is not None:
                    CHANNEL_OPTIONS.append(
                        ("grpc.ssl_target_name_override", self._cert_domain)
                    )
                self._channel = grpc.secure_channel(
                    self._location, credentials=creds, options=CHANNEL_OPTIONS
                )
            self._stub = pb2_grpc.OpenapiStub(self._channel)
        return self._stub

    def _serialize_payload(self, payload):
        if not isinstance(payload, (str, dict, OpenApiBase)):
            raise Exception("We are supporting [str, dict, OpenApiBase] object")
        if isinstance(payload, OpenApiBase):
            payload = payload.serialize()
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        elif isinstance(payload, (str, unicode)):
            payload = json.dumps(yaml.safe_load(payload))
        return payload

    def _raise_exception(self, grpc_error):
        err = self.error()
        try:
            err.deserialize(grpc_error.details())
        except Exception as _:
            err.code = grpc_error.code().value[0]
            err.errors = [grpc_error.details()]
        raise Exception(err)

    def _client_stream(self, stub, data):
        data_chunks = []
        for i in range(0, len(data), self._chunk_size):
            if i + self._chunk_size > len(data):
                chunk = data[i : len(data)]
            else:
                chunk = data[i : i + self._chunk_size]
            data_chunks.append(pb2.Data(datum=chunk, chunk_size=self._chunk_size))
        # print(chunk_list, len(chunk_list))
        reqs = iter(data_chunks)
        return reqs

    def _server_stream(self, stub, responses):
        data = b""
        for response in responses:
            data += response.datum
        return data

    @property
    def request_timeout(self):
        """duration of time in seconds to allow for the RPC."""
        return self._request_timeout

    @request_timeout.setter
    def request_timeout(self, timeout):
        self._request_timeout = timeout

    @property
    def keep_alive_timeout(self):
        return self._keep_alive_timeout

    @keep_alive_timeout.setter
    def keep_alive_timeout(self, timeout):
        self._keep_alive_timeout = timeout * 1000

    @property
    def chunk_size(self):
        return self._chunk_size

    @chunk_size.setter
    def chunk_size(self, size):
        self._chunk_size = size * 1024 * 1024

    @property
    def maximum_receive_buffer_size(self):
        return self._maximum_receive_buffer_size

    @maximum_receive_buffer_size.setter
    def maximum_receive_buffer_size(self, size):
        self._maximum_receive_buffer_size = size * 1024 * 1024

    def close(self):
        if self._channel is not None:
            self._channel.close()
            self._channel = None
            self._stub = None

    @Telemetry.create_child_span
    def upload_config(self, payload):
        log.info("Executing upload_config")
        self._do_version_check_once()
        req_obj = pb2.UploadConfigRequest(request_bytes=payload)
        pb_str = payload
        stub = self._get_stub()
        try:
            if self.enable_grpc_streaming and len(pb_str) > self._chunk_size:
                stream_req = self._client_stream(stub, pb_str)
                res_obj = stub.streamUploadConfig(
                    stream_req, timeout=self._request_timeout
                )
            else:
                res_obj = stub.UploadConfig(req_obj, timeout=self._request_timeout)
        except grpc.RpcError as grpc_error:
            self._raise_exception(grpc_error)
        response = json_format.MessageToDict(res_obj, preserving_proto_field_name=True)
        log.debug("Response - " + str(response))
        self._telemetry.set_span_event("RESPONSE: %s" % str(response))
        result = response.get("server_response")
        if result is not None:
            if len(result) == 0:
                result = json_format.MessageToDict(
                    res_obj.server_response,
                    preserving_proto_field_name=True,
                    including_default_value_fields=True,
                )
            return self.serverresponse().deserialize(result)

    @Telemetry.create_child_span
    def set_config(self, payload):
        log.info("Executing set_config")
        log.debug("Request payload - " + str(payload))
        self._telemetry.set_span_event("REQUEST: %s" % str(payload))
        pb_obj = json_format.Parse(self._serialize_payload(payload), pb2.Config())
        self._do_version_check_once()
        req_obj = pb2.SetConfigRequest(config=pb_obj)
        pb_str = pb_obj.SerializeToString()
        stub = self._get_stub()
        try:
            if self.enable_grpc_streaming and len(pb_str) > self._chunk_size:
                stream_req = self._client_stream(stub, pb_str)
                res_obj = stub.streamSetConfig(
                    stream_req, timeout=self._request_timeout
                )
            else:
                res_obj = stub.SetConfig(req_obj, timeout=self._request_timeout)
        except grpc.RpcError as grpc_error:
            self._raise_exception(grpc_error)
        response = json_format.MessageToDict(res_obj, preserving_proto_field_name=True)
        log.debug("Response - " + str(response))
        self._telemetry.set_span_event("RESPONSE: %s" % str(response))
        result = response.get("server_response")
        if result is not None:
            if len(result) == 0:
                result = json_format.MessageToDict(
                    res_obj.server_response,
                    preserving_proto_field_name=True,
                    including_default_value_fields=True,
                )
            return self.serverresponse().deserialize(result)

    @Telemetry.create_child_span
    def get_config(self):
        log.info("Executing get_config")
        stub = self._get_stub()
        empty = pb2_grpc.google_dot_protobuf_dot_empty__pb2.Empty()
        if self.enable_grpc_streaming:
            res = stub.streamGetConfig(empty, timeout=self._request_timeout)
            data = self._server_stream(stub, res)
            return io.BytesIO(data)
        else:
            res_obj = stub.GetConfig(empty, timeout=self._request_timeout)
        response = json_format.MessageToDict(res_obj, preserving_proto_field_name=True)
        log.debug("Response - " + str(response))
        self._telemetry.set_span_event("RESPONSE: %s" % str(response))
        bytes = response.get("response_bytes")
        if bytes is not None:
            return io.BytesIO(res_obj.response_bytes)

    @Telemetry.create_child_span
    def get_status(self):
        log.info("Executing get_status")
        stub = self._get_stub()
        empty = pb2_grpc.google_dot_protobuf_dot_empty__pb2.Empty()
        res_obj = stub.GetStatus(empty, timeout=self._request_timeout)
        response = json_format.MessageToDict(res_obj, preserving_proto_field_name=True)
        log.debug("Response - " + str(response))
        self._telemetry.set_span_event("RESPONSE: %s" % str(response))
        result = response.get("control_status")
        if result is not None:
            return self.control_status().deserialize(result)

    @Telemetry.create_child_span
    def set_control_action(self, payload):
        log.info("Executing set_control_action")
        log.debug("Request payload - " + str(payload))
        self._telemetry.set_span_event("REQUEST: %s" % str(payload))
        pb_obj = json_format.Parse(self._serialize_payload(payload), pb2.Control())
        self._do_version_check_once()
        req_obj = pb2.SetControlActionRequest(control=pb_obj)
        stub = self._get_stub()
        try:
            res_obj = stub.SetControlAction(req_obj, timeout=self._request_timeout)
        except grpc.RpcError as grpc_error:
            self._raise_exception(grpc_error)
        response = json_format.MessageToDict(res_obj, preserving_proto_field_name=True)
        log.debug("Response - " + str(response))
        self._telemetry.set_span_event("RESPONSE: %s" % str(response))
        result = response.get("server_response")
        if result is not None:
            if len(result) == 0:
                result = json_format.MessageToDict(
                    res_obj.server_response,
                    preserving_proto_field_name=True,
                    including_default_value_fields=True,
                )
            return self.serverresponse().deserialize(result)

    @Telemetry.create_child_span
    def get_result(self, payload):
        log.info("Executing get_result")
        log.debug("Request payload - " + str(payload))
        self._telemetry.set_span_event("REQUEST: %s" % str(payload))
        pb_obj = json_format.Parse(self._serialize_payload(payload), pb2.Result())
        self._do_version_check_once()
        req_obj = pb2.GetResultRequest(result=pb_obj)
        stub = self._get_stub()
        try:
            if self.enable_grpc_streaming:
                res = stub.streamGetResult(req_obj, timeout=self._request_timeout)
                data = self._server_stream(stub, res)
                return io.BytesIO(data)
            else:
                res_obj = stub.GetResult(req_obj, timeout=self._request_timeout)
        except grpc.RpcError as grpc_error:
            self._raise_exception(grpc_error)
        response = json_format.MessageToDict(res_obj, preserving_proto_field_name=True)
        log.debug("Response - " + str(response))
        self._telemetry.set_span_event("RESPONSE: %s" % str(response))
        bytes = response.get("response_bytes")
        if bytes is not None:
            return io.BytesIO(res_obj.response_bytes)

    @Telemetry.create_child_span
    def get_version(self):
        log.info("Executing get_version")
        stub = self._get_stub()
        empty = pb2_grpc.google_dot_protobuf_dot_empty__pb2.Empty()
        res_obj = stub.GetVersion(empty, timeout=self._request_timeout)
        response = json_format.MessageToDict(res_obj, preserving_proto_field_name=True)
        log.debug("Response - " + str(response))
        self._telemetry.set_span_event("RESPONSE: %s" % str(response))
        result = response.get("version")
        if result is not None:
            return self.version().deserialize(result)
