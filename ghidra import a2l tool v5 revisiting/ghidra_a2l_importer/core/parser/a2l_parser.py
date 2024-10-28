# core/parser/a2l_parser.py
class BlockType:
    """Enum-like class for block types"""
    MEASUREMENT = "MEASUREMENT"
    CHARACTERISTIC = "CHARACTERISTIC"
    AXIS_PTS = "AXIS_PTS"
    COMPU_METHOD = "COMPU_METHOD"
    COMPU_TAB = "COMPU_TAB"
    RECORD_LAYOUT = "RECORD_LAYOUT"
    FUNCTION = "FUNCTION"
    GROUP = "GROUP"
    FRAME = "FRAME"
    MEMORY_SEGMENT = "MEMORY_SEGMENT"
    MODULE = "MODULE"

class CompuMethod:
    """Computation method information"""
    def __init__(self, name, format="", unit="", coeffs=None, compu_tab_ref=""):
        self.name = name
        self.format = format
        self.unit = unit
        self.coeffs = coeffs or []
        self.compu_tab_ref = compu_tab_ref

class CompuTab:
    """Computation table information"""
    def __init__(self, name, pairs=None):
        self.name = name
        self.pairs = pairs or {}

class RecordLayout:
    """Record layout information"""
    def __init__(self, name, alignment=1, byte_order="", axis_pts_x=0, 
                 axis_pts_y=0, fix_no_axis_pts_x=0, fix_no_axis_pts_y=0):
        self.name = name
        self.alignment = alignment
        self.byte_order = byte_order
        self.axis_pts_x = axis_pts_x
        self.axis_pts_y = axis_pts_y
        self.fix_no_axis_pts_x = fix_no_axis_pts_x
        self.fix_no_axis_pts_y = fix_no_axis_pts_y

class MemorySegment:
    """Memory segment information"""
    def __init__(self, name, start_address=0, size=0, attribute=""):
        self.name = name
        self.start_address = start_address
        self.size = size
        self.attribute = attribute

class A2LParser:
    def __init__(self, a2l_path):
        self.a2l_path = a2l_path
        self.variables = {}
        self.compu_methods = {}
        self.compu_tabs = {}
        self.record_layouts = {}
        self.memory_segments = {}
        self.functions = {}
        self.groups = {}
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        
    def cleanup(self):
        """Cleanup all resources"""
        self.variables.clear()
        self.compu_methods.clear()
        self.compu_tabs.clear()
        self.record_layouts.clear()
        self.memory_segments.clear()
        
    def parse_file(self):
        """Main parsing method"""
        try:
            with open(self.a2l_path, 'r') as f:
                content = f.readlines()
            
            self._parse_content(content)
            self._resolve_references()
            return self.variables
            
        except Exception as e:
            from utils.logger import Logger
            Logger.error("Error parsing A2L file: {}".format(str(e)))
            return {}
            
    def _parse_content(self, content):
        """Parse file content with block awareness"""
        current_block = None
        block_content = []
        block_stack = []  # For handling nested blocks
        
        for line in content:
            line = line.strip()
            
            if not line or line.startswith('//'):
                continue
                
            if line.startswith('/begin'):
                if current_block:
                    # Save current block context for nested blocks
                    block_stack.append((current_block, block_content))
                current_block = self._parse_begin_block(line)
                block_content = []
                
            elif line.startswith('/end'):
                if current_block:
                    self._process_block(current_block, block_content)
                    if block_stack:  # Return to parent block if exists
                        current_block, block_content = block_stack.pop()
                    else:
                        current_block = None
                        block_content = []
                        
            elif current_block:
                block_content.append(line)
                
    def _parse_begin_block(self, line):
        """Parse block type from begin statement"""
        parts = line.split()
        if len(parts) >= 3:
            block_type = parts[1]
            if hasattr(BlockType, block_type):
                return block_type
            from utils.logger import Logger
            Logger.debug("Unknown block type: {}".format(block_type))
        return None
        
    def _process_block(self, block_type, content):
        """Process different block types"""
        if not block_type:
            return
            
        processors = {
            BlockType.MEASUREMENT: self._process_measurement,
            BlockType.CHARACTERISTIC: self._process_characteristic,
            BlockType.COMPU_METHOD: self._process_compu_method,
            BlockType.COMPU_TAB: self._process_compu_tab,
            BlockType.RECORD_LAYOUT: self._process_record_layout,
            BlockType.MEMORY_SEGMENT: self._process_memory_segment
        }
        
        processor = processors.get(block_type)
        if processor:
            processor(content)
            
    def _process_measurement(self, content):
        """Process MEASUREMENT block"""
        var_info = {
            'type': 'MEASUREMENT',
            'datatype': None,
            'address': None,
            'compu_method': None,
            'record_layout': None,
            'matrix_dim': [],
            'bit_mask': None
        }
        
        name = content[0].strip()
        
        for line in content[1:]:
            parts = line.split()
            if not parts:
                continue
                
            key = parts[0]
            if key == 'DATATYPE':
                var_info['datatype'] = parts[1]
            elif key == 'ADDR_EPK':
                try:
                    var_info['address'] = int(parts[1], 16)
                except (ValueError, IndexError):
                    pass
            elif key == 'COMPU_METHOD':
                var_info['compu_method'] = parts[1]
            elif key == 'MATRIX_DIM':
                try:
                    var_info['matrix_dim'] = [int(x) for x in parts[1:]]
                except (ValueError, IndexError):
                    pass
            elif key == 'BIT_MASK':
                try:
                    var_info['bit_mask'] = int(parts[1], 16)
                except (ValueError, IndexError):
                    pass
                    
        self.variables[name] = var_info
        
    def _process_characteristic(self, content):
        """Process CHARACTERISTIC block"""
        var_info = {
            'type': 'CHARACTERISTIC',
            'datatype': None,
            'address': None,
            'record_layout': None,
            'axis_pts_ref': [],
            'max_diff': None,
            'conversion': None
        }
        
        name = content[0].strip()
        
        for line in content[1:]:
            parts = line.split()
            if not parts:
                continue
                
            key = parts[0]
            if key == 'RECORD_LAYOUT':
                var_info['record_layout'] = parts[1]
            elif key == 'AXIS_DESCR':
                axis_info = self._parse_axis_description(parts[1:])
                var_info['axis_pts_ref'].append(axis_info)
            elif key == 'MAX_DIFF':
                try:
                    var_info['max_diff'] = float(parts[1])
                except (ValueError, IndexError):
                    pass
            elif key == 'CONVERSION':
                var_info['conversion'] = parts[1]
                
        self.variables[name] = var_info
        
    def _process_compu_method(self, content):
        """Process COMPU_METHOD block"""
        name = content[0].strip()
        method = CompuMethod(name=name)
        
        for line in content[1:]:
            parts = line.split()
            if not parts:
                continue
                
            key = parts[0]
            if key == 'FORMAT':
                method.format = parts[1].strip('"')
            elif key == 'UNIT':
                method.unit = parts[1].strip('"')
            elif key == 'COEFFS':
                try:
                    method.coeffs = [float(x) for x in parts[1:]]
                except (ValueError, IndexError):
                    pass
            elif key == 'COMPU_TAB_REF':
                method.compu_tab_ref = parts[1]
                
        self.compu_methods[name] = method
        
    def _process_compu_tab(self, content):
        """Process COMPU_TAB block"""
        name = content[0].strip()
        tab = CompuTab(name=name)
        
        in_value_pairs = False
        for line in content[1:]:
            parts = line.split()
            if not parts:
                continue
                
            if line.strip() == 'VALUE_PAIRS':
                in_value_pairs = True
                continue
                
            if in_value_pairs and len(parts) >= 2:
                try:
                    input_val = float(parts[0])
                    output_val = float(parts[1])
                    tab.pairs[input_val] = output_val
                except (ValueError, IndexError):
                    pass
                    
        self.compu_tabs[name] = tab
        
    def _process_record_layout(self, content):
        """Process RECORD_LAYOUT block"""
        name = content[0].strip()
        layout = RecordLayout(name=name)
        
        for line in content[1:]:
            parts = line.split()
            if not parts:
                continue
                
            key = parts[0]
            try:
                if key == 'ALIGNMENT_BYTE':
                    layout.alignment = int(parts[1])
                elif key == 'BYTE_ORDER':
                    layout.byte_order = parts[1]
                elif key == 'AXIS_PTS_X':
                    layout.axis_pts_x = int(parts[1])
                elif key == 'AXIS_PTS_Y':
                    layout.axis_pts_y = int(parts[1])
            except (ValueError, IndexError):
                pass
                
        self.record_layouts[name] = layout
        
    def _process_memory_segment(self, content):
        """Process MEMORY_SEGMENT block"""
        name = content[0].strip()
        segment = MemorySegment(name=name)
        
        for line in content[1:]:
            parts = line.split()
            if not parts:
                continue
                
            key = parts[0]
            try:
                if key == 'START_ADDRESS':
                    segment.start_address = int(parts[1], 16)
                elif key == 'SIZE':
                    segment.size = int(parts[1])
                elif key == 'ATTRIBUTE':
                    segment.attribute = parts[1]
            except (ValueError, IndexError):
                pass
                
        self.memory_segments[name] = segment
        
    def _parse_axis_description(self, axis_parts):
        """Parse axis description for characteristics"""
        return {
            'type': axis_parts[0] if len(axis_parts) > 0 else None,
            'reference': axis_parts[1] if len(axis_parts) > 1 else None,
            'conversion': axis_parts[2] if len(axis_parts) > 2 else None
        }
        
    def _resolve_references(self):
        """Resolve references between different blocks"""
        for var_name, var_info in self.variables.items():
            # Resolve computation method
            if var_info.get('compu_method'):
                compu_method = self.compu_methods.get(var_info['compu_method'])
                if compu_method:
                    var_info['computation'] = compu_method
                    
                    # Resolve computation table if referenced
                    if compu_method.compu_tab_ref:
                        compu_tab = self.compu_tabs.get(compu_method.compu_tab_ref)
                        if compu_tab:
                            var_info['computation_table'] = compu_tab
                            
            # Resolve record layout
            if var_info.get('record_layout'):
                record_layout = self.record_layouts.get(var_info['record_layout'])
                if record_layout:
                    var_info['layout'] = record_layout
                    
    def get_memory_layout(self):
        """Return list of memory segments"""
        return self.memory_segments.values()
        
    def get_variable_info(self, name):
        """Get detailed information about a variable"""
        return self.variables.get(name)
        
    def get_conversion(self, name):
        """Get conversion method for a variable"""
        var_info = self.variables.get(name)
        if var_info and 'computation' in var_info:
            return var_info['computation']
        return None