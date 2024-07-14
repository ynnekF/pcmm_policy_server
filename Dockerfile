FROM        --platform=linux/amd64 ubuntu:22.04 as base

RUN         apt clean

# Install all core and developer-specific libraries
RUN         apt-get update && apt-get -y --no-install-recommends install \
                build-essential valgrind gdb gcc make libulfius-dev libjansson-dev\
                libevent-dev tcpdump

WORKDIR     /app

# Create the logs, data and config directories
# /logs     Is where thread-specific log files are created and updated.
# /data     Is where orphan entries and the connection RC file lives.
# /config   Is where startup configuration files are stored before use.
RUN         mkdir -p ./logs && \
            mkdir -p ./data && \
            mkdir -p ./config

# Copy over the Makefile and all non-test source/header files
COPY        src        ./src
COPY        include    ./include
COPY        Makefile   ./Makefile


###############################################################################
# Developers image
###############################################################################                      

FROM        base as dev
WORKDIR     /app

# Test specific aliases
RUN         echo "alias vg='make COMPILE_TEST=1; make valgrind'" >>~/.bashrc &&\
            echo "alias gd='make clean && make BUILD_OPTIMIZATIONS=1 && gdb bin/pserver -ex \"run server log_level=1\"'" >> ~/.bashrc &&\

# Valgrind error/warning suppresion file
COPY        tests/linux_sdl_gl.sup       ./

# Startup config files
COPY        docs/examples/ex_server.json ./config

EXPOSE      8000
CMD         ["make", "BUILD_OPTIMIZATIONS=1", "run", "args='server log_level=0'"]
# CMD ["sleep", "1000"]


###############################################################################
# Release image
###############################################################################   

FROM        base as release
WORKDIR     /app

# Remove uncessary libraries TODO
RUN         apt-get remove valgrind gdb

EXPOSE      8000

# This path must match the k8s volume mount
CMD         ["make", "run", "BUILD_OPTIMIZATIONS=1", "args='config=/app/config/ex_server.json'"]