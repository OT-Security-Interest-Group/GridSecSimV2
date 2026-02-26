FROM python:3.11-slim

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

# Copy your Python simulation scripts into the container
COPY ./scripts /app/scripts

# Keep the container running infinitely so you can execute scripts manually 
# or override this CMD in docker-compose.yml
CMD ["tail", "-f", "/dev/null"]
