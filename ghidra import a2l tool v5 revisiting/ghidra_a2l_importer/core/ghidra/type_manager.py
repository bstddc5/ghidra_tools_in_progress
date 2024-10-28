# core/ghidra/type_manager.py
class TypeManager:
    def __init__(self, current_program):
        self.program = current_program
        self.data_type_manager = current_program.getDataTypeManager()
        
    def __enter__(self):
        self.transaction = self.program.startTransaction("A2L Type Import")
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.program.endTransaction(self.transaction, True)
        
    def apply_datatype(self, address, datatype_name):
        """Apply a datatype at the specified address"""
        addr = self.program.getAddressFactory().getAddress(hex(address))
        datatype = self.data_type_manager.getDataType(f"/{datatype_name}")
        if datatype:
            self.program.getListing().createData(addr, datatype)