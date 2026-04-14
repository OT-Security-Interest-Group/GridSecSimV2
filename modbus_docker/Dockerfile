FROM python:3.10-slim

RUN pip install --no-cache-dir pymodbus==3.6.4

WORKDIR /app

# Single image with all simulation scripts (SCADA, historians, attacks, orchestrator)
COPY ./scripts/ /app/scripts/

ENTRYPOINT ["python"]
