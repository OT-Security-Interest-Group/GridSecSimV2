import asyncio
import logging
from pymodbus.server import StartAsyncTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext

# Enable basic logging to see connections in the Docker logs
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def run_server():
    # Initialize Modbus Registers
    # Holding registers (Function Code 3), starting at address 0.
    # Values: [1150, 2300, 500] represents 115.0 kV, 230.0 kV, and 50 MW
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0]*100), # Discrete Inputs
        co=ModbusSequentialDataBlock(0, [0]*100), # Coils
        hr=ModbusSequentialDataBlock(0, [1150, 2300, 500, 0, 0]), # Holding Registers
        ir=ModbusSequentialDataBlock(0, [0]*100)  # Input Registers
    )
    
    # single=True means all slave IDs map to this same context
    context = ModbusServerContext(slaves=store, single=True)
    
    # Device identity (useful for Nmap/reconnaissance ML detection)
    identity = ModbusDeviceIdentification()
    identity.VendorName = 'GridSim_Lab'
    identity.ProductCode = 'TX-RTU-01'
    identity.ModelName = 'Transmission Substation RTU'
    identity.MajorMinorRevision = '1.0'
    
    logger.info("Starting Transmission RTU Modbus TCP Server on 0.0.0.0:502...")
    
    # Start the server listening on all interfaces inside the container
    await StartAsyncTcpServer(
        context=context, 
        identity=identity, 
        address=("0.0.0.0", 502)
    )

if __name__ == "__main__":
    asyncio.run(run_server())
