FROM python:3.10-slim

# Install system utilities (tcpdump for local PCAP, iproute2/iputils-ping for network troubleshooting)
RUN apt-get update && apt-get install -y \
    tcpdump \
    iproute2 \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Install pymodbus for our ICS simulation
RUN pip install --no-cache-dir pymodbus==3.6.4

# Set the working directory
WORKDIR /app

ARG SCRIPT_NAME
ENV SCRIPT_NAME=${SCRIPT_NAME}

COPY ./scripts/${SCRIPT_NAME} /app/scripts/${SCRIPT_NAME}
CMD python /app/scripts/${SCRIPT_NAME}
