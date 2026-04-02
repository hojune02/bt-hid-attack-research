FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Core system packages
RUN apt-get update && apt-get install -y \
    bluez \
    bluetooth \
    bluez-tools \
    bluez-hcidump \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    libglib2.0-dev \
    libdbus-1-dev \
    libudev-dev \
    net-tools \
    iproute2 \
    git \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python BT libraries (PyBluez dropped — attack scripts use Scapy + raw HCI sockets)
RUN pip3 install --no-cache-dir \
    scapy \
    pydbus \
    dbus-python \
    pyserial

# InternalBlue (Broadcom KNOB Mode B — optional; install anyway for completeness)
RUN pip3 install --no-cache-dir internalblue || true

# Python uhid bindings for presenting attacker as HID device to the PC
RUN pip3 install --no-cache-dir uhid

# BlueZ userspace utilities need dbus running; provide wrapper
RUN mkdir -p /run/dbus

# Ensure hci socket permissions inside container work with --privileged
RUN echo 'net.core.rmem_max = 4194304' >> /etc/sysctl.conf

WORKDIR /attack

CMD ["/bin/bash"]
