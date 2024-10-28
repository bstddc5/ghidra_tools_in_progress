# core/parser/parser_utils.py
class ParserUtils:
    @staticmethod
    def parse_address(addr_str):
        """Convert address string to integer"""
        try:
            return int(addr_str.strip(), 16)
        except ValueError:
            return None
            
    @staticmethod
    def parse_datatype(dtype_str):
        """Convert A2L datatype to Ghidra datatype"""
        # Mapping of A2L datatypes to Ghidra datatypes
        type_map = {
            'UBYTE': 'uint8_t',
            'SBYTE': 'int8_t',
            'UWORD': 'uint16_t',
            'SWORD': 'int16_t',
            'ULONG': 'uint32_t',
            'SLONG': 'int32_t',
            'A_UINT64': 'uint64_t',
            'A_INT64': 'int64_t',
            'FLOAT32_IEEE': 'float',
            'FLOAT64_IEEE': 'double'
        }
        return type_map.get(dtype_str.upper())