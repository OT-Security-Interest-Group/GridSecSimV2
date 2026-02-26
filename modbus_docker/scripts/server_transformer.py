import asyncio
import logging
from pymodbus.server import StartAsyncTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def run_server():
    # Initialize Modbus Registers for an Analog Sensor
    # Input Registers (Read-Only): 
    # [650, 420, 100] could represent 65.0 C Top Oil Temp, 42.0 ppm Hydrogen gas, 1.00% Moisture
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0]*100), 
        co=ModbusSequentialDataBlock(0, [0]*100), 
        hr=ModbusSequentialDataBlock(0, [0]*100), 
        ir=ModbusSequentialDataBlock(0, [650, 420, 100, 0, 0]) 
    )
    
    context = ModbusServerContext(slaves=store, single=True)
    
    identity = ModbusDeviceIdentification()
    identity.VendorName = 'GridSim_Lab'
    identity.ProductCode = 'XFMR-SENS-01'
    identity.ModelName = 'Dissolved Gas & Temp Monitor'
    identity.MajorMinorRevision = '1.5'
    logger.info("Starting Transformer Sensor Server on 0.0.0.0:502...")
    
    await StartAsyncTcpServer(
        context=context, 
        identity=identity, 
        address=("0.0.0.0", 502)
    )

if __name__ == "__main__":
    asyncio.run(run_server())
