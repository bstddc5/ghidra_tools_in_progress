# @category A2L
# @menupath Tools.A2L.Import
# @toolbar 

import json
from javax.swing import (JFrame, JPanel, JCheckBox, JButton, JFileChooser, 
                        BoxLayout, JLabel, BorderFactory)
from java.awt import BorderLayout
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import DataTypeManager

class A2LParser:
    def __init__(self, a2l_path):
        self.a2l_path = a2l_path
        self.variables = {}
        
    def parse_file(self):
        """Parse A2L file and extract variable information"""
        try:
            with open(self.a2l_path, 'r') as f:
                current_block = None
                for line in f:
                    line = line.strip()
                    
                    # Basic parsing of MEASUREMENT and CHARACTERISTIC blocks
                    if line.startswith('/begin MEASUREMENT') or line.startswith('/begin CHARACTERISTIC'):
                        current_block = line.split()[2]  # Get variable name
                        self.variables[current_block] = {'type': line.split()[1]}
                    
                    elif line.startswith('ADDR_EPK'):
                        if current_block:
                            addr = int(line.split()[1], 16)  # Convert hex address
                            self.variables[current_block]['address'] = addr
                            
                    elif line.startswith('DATATYPE'):
                        if current_block:
                            self.variables[current_block]['datatype'] = line.split()[1]
                            
                    elif line.startswith('/end'):
                        current_block = None
                        
        except Exception as e:
            print(f"Error parsing A2L file: {str(e)}")
        return self.variables

class A2LImporterGUI(JFrame):
    def __init__(self):
        super(A2LImporterGUI, self).__init__("A2L Importer")
        self.current_program = state.getCurrentProgram()
        self.setup_gui()
        
    def setup_gui(self):
        """Create the GUI elements"""
        self.setSize(400, 300)
        self.setLocationRelativeTo(None)
        
        main_panel = JPanel()
        main_panel.setLayout(BoxLayout(main_panel, BoxLayout.Y_AXIS))
        main_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # Add import options
        self.name_cb = JCheckBox("Import Variable Names", True)
        self.datatype_cb = JCheckBox("Import Data Types", True)
        self.comments_cb = JCheckBox("Add Comments", True)
        
        # Add buttons
        select_button = JButton("Select A2L File", actionPerformed=self.select_file)
        import_button = JButton("Import", actionPerformed=self.import_data)
        
        # Add components to panel
        main_panel.add(self.name_cb)
        main_panel.add(self.datatype_cb)
        main_panel.add(self.comments_cb)
        main_panel.add(select_button)
        main_panel.add(import_button)
        
        self.add(main_panel)
        
    def select_file(self, event):
        """Handle file selection"""
        chooser = JFileChooser()
        ret = chooser.showOpenDialog(None)
        
        if ret == JFileChooser.APPROVE_OPTION:
            self.a2l_path = chooser.getSelectedFile().getAbsolutePath()
            self.parser = A2LParser(self.a2l_path)
            print(f"Selected file: {self.a2l_path}")
            
    def import_data(self, event):
        """Import selected data into Ghidra"""
        if not hasattr(self, 'parser'):
            print("Please select an A2L file first")
            return
            
        variables = self.parser.parse_file()
        
        # Start transaction for bulk updates
        trans = self.current_program.startTransaction("A2L Import")
        
        try:
            symbol_table = self.current_program.getSymbolTable()
            
            for var_name, var_info in variables.items():
                if 'address' not in var_info:
                    continue
                    
                addr = self.current_program.getAddressFactory().getAddress(hex(var_info['address']))
                
                # Import variable name if selected
                if self.name_cb.isSelected():
                    symbol_table.createLabel(addr, var_name, SourceType.IMPORTED)
                
                # Import data type if selected
                if self.datatype_cb.isSelected() and 'datatype' in var_info:
                    # TODO: Implement data type creation/assignment
                    pass
                
                # Add comments if selected
                if self.comments_cb.isSelected():
                    self.current_program.getListing().setComment(addr, 0, 
                        f"A2L Import: {var_info['type']}")
                    
            print(f"Successfully imported {len(variables)} variables")
            
        except Exception as e:
            print(f"Error during import: {str(e)}")
        finally:
            self.current_program.endTransaction(trans, True)

def main():
    gui = A2LImporterGUI()
    gui.setVisible(True)

if __name__ == '__main__':
    main()