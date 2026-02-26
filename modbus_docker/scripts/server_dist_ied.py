import asyncio
import logging
from pymodbus.server import StartAsyncTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def run_server():
    # Initialize Modbus Registers for a Breaker Relay
    # Coils: 1 = Closed (energized), 0 = Open (de-energized). 
    # Let's say we have 4 breakers. 3 are closed, 1 is open.
    # Discrete Inputs: 0 = Normal, 1 = Alarm/Trip condition.
    store = ModbusSlaveContext(
        co=ModbusSequentialDataBlock(0, [1, 1, 1, 0]), 
        di=ModbusSequentialDataBlock(0, [0, 0, 0, 0]), 
        hr=ModbusSequentialDataBlock(0, [0]*100),      
        ir=ModbusSequentialDataBlock(0, [0]*100)       
    )
    
    context = ModbusServerContext(slaves=store, single=True)
    
    # Unique identity for ML feature extraction
    identity = ModbusDeviceIdentification()
    identity.VendorName = 'GridSim_Lab'
    identity.ProductCode = 'DIST-IED-01'
    identity.ModelName = 'Feeder Protection Relay'
    identity.MajorMinorRevision = '2.1'
    
    logger.info("Starting Distribution IED Server on 0.0.0.0:502...")
    
    await StartAsyncTcpServer(
        context=context, 
        identity=identity, 
        address=("0.0.0.0", 502)
    )

if __name__ == "__main__":
    asyncio.run(run_server())
