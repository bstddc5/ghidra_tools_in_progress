# core/ghidra/symbol_manager.py
class SymbolManager:
    def __init__(self, current_program):
        self.program = current_program
        self.symbol_table = current_program.getSymbolTable()
        
    def __enter__(self):
        self.transaction = self.program.startTransaction("A2L Symbol Import")
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.program.endTransaction(self.transaction, True)
        
    def create_symbol(self, name, address, source_type):
        """Create a symbol at the specified address"""
        addr = self.program.getAddressFactory().getAddress(hex(address))
        return self.symbol_table.createLabel(addr, name, source_type)