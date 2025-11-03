FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3.11 \
    python3-pip \
    python3.11-dev \
    coreutils \
    wget \
    vim \
    git \
    gcc-11 \
    g++-11 \
    make \
    cmake \
    clang-format \
    libboost-dev \
    libboost-program-options-dev \
    libprotobuf-dev \
    protobuf-compiler \
    openmpi-bin \
    openmpi-common \
    openmpi-doc \
    libopenmpi-dev \
    graphviz \
    curl \
    dos2unix


RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1
RUN python3 -m pip config set global.break-system-packages true

RUN pip3 install --upgrade pip && \
    pip3 install protobuf graphviz pydot

ARG GIT_COMMIT_SHA
ENV GIT_COMMIT_SHA=$GIT_COMMIT_SHA

WORKDIR /app

# Copy the commit SHA file into the image
COPY .ASTRA_SIM_GIT_COMMIT_SHA /tmp/.ASTRA_SIM_GIT_COMMIT_SHA

# Clone the repo and checkout the commit from the file
RUN REPO=https://github.com/astra-sim/astra-sim.git && \
    COMMIT_SHA=$(cat /tmp/.ASTRA_SIM_GIT_COMMIT_SHA) && \
    git clone $REPO /app/astra-sim && \
    cd /app/astra-sim && \
    git checkout $COMMIT_SHA && \
    git submodule update --init --recursive

COPY build_script/build_backend.sh /app/build_script/build_backend.sh

COPY astra_server /app/astra_server
COPY requirements.txt /app/requirements.txt
COPY *.whl /app/
RUN chmod +x build_script/build_backend.sh
RUN ./build_script/build_backend.sh
# Install infragraph from GitHub release
RUN wget https://github.com/Keysight/infragraph/releases/download/v0.4.4/infragraph-0.4.4-py3-none-any.whl && \
    pip install infragraph-0.4.4-py3-none-any.whl && \
    rm -f infragraph-0.4.4-py3-none-any.whl
RUN pip install *.whl
RUN pip install --no-cache-dir -r /app/requirements.txt

WORKDIR /app/astra_server
ENV PYTHONPATH=/app

ENTRYPOINT ["python3", "__main__.py"]
# CMD ["/bin/bash"]

