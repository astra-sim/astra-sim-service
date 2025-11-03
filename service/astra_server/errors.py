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


class ServerError(Exception):
    """The base error class for all IxNetwork REST API errors"""

    def __init__(self, message, grpc_code=None, http_code=None):
        self._message = message
        self._grpc_code = grpc_code
        self._http_code = http_code

    @property
    def message(self):
        return self._message

    @property
    def grpc_code(self):
        return self._grpc_code

    @property
    def http_code(self):
        return self._http_code

    def __str__(self):
        return self._message

    def __repr__(self):
        return self._message


class ConfigurationError(ServerError):
    """Configuration Error"""

    def __init__(self, message, grpc_error=None, http_error=None):
        super(ConfigurationError, self).__init__(message, grpc_error, http_error)


class SimulationAlreadyRunningError(ServerError):
    """Simulation Already Running Error"""

    def __init__(self, message, grpc_error=None, http_error=None):
        super(SimulationAlreadyRunningError, self).__init__(
            message, grpc_error, http_error
        )


class SimulationError(ServerError):
    """Simulation Already Running Error"""

    def __init__(self, message, grpc_error=None, http_error=None):
        super(SimulationError, self).__init__(message, grpc_error, http_error)


class ResultError(ServerError):
    """Simulation Already Running Error"""

    def __init__(self, message, grpc_error=None, http_error=None):
        super(ResultError, self).__init__(message, grpc_error, http_error)


class InfragraphError(ServerError):
    """Simulation Already Running Error"""

    def __init__(self, message, grpc_error=None, http_error=None):
        super(InfragraphError, self).__init__(message, grpc_error, http_error)
