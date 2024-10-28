# gui/widgets/import_panel.py
from utils.logger import Logger

Logger.debug("Loading Import Panel imports...")
try:
    from javax.swing import (JPanel, JCheckBox, JButton, JFileChooser, BoxLayout,
                            JTable, JScrollPane, BorderFactory, JLabel)
    from javax.swing.table import DefaultTableModel
    from java.awt import BorderLayout, GridLayout, Dimension
    Logger.debug("Swing imports successful")
except Exception as e:
    Logger.error("Error loading Swing imports: {}".format(str(e)))

try:
    from ghidra.program.model.listing import CodeUnit
    from ghidra.program.model.symbol import SourceType
    Logger.debug("Ghidra imports successful")
except Exception as e:
    Logger.error("Error loading Ghidra imports: {}".format(str(e)))

try:
    from core.parser.a2l_parser import A2LParser
    Logger.debug("Local imports successful")
except Exception as e:
    Logger.error("Error loading local imports: {}".format(str(e)))

class ImportPanel(JPanel):
    """Panel for importing A2L data into Ghidra"""
    
    def __init__(self, current_program, flat_api, file_callback):
        """Initialize the import panel
        
        Args:
            current_program: Current Ghidra program
            flat_api: FlatProgramAPI instance
            file_callback: Callback function for file loading events
        """
        Logger.debug("Initializing ImportPanel")
        try:
            super(ImportPanel, self).__init__()
            self.current_program = current_program
            self.api = flat_api
            self.file_callback = file_callback
            Logger.debug("ImportPanel attributes set")
            self.setup_panel()
            Logger.debug("ImportPanel initialization complete")
        except Exception as e:
            Logger.error("Error in ImportPanel.__init__: {}".format(str(e)))
            import traceback
            Logger.debug("Full traceback: {}".format(traceback.format_exc()))
            
    def setup_panel(self):
        """Setup the panel components"""
        Logger.debug("Setting up ImportPanel components")
        try:
            # Set layout
            self.setLayout(BorderLayout(10, 10))
            self.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
            
            # Create options panel
            Logger.debug("Creating options panel")
            options_panel = JPanel(GridLayout(0, 2, 10, 5))
            options_panel.setBorder(BorderFactory.createTitledBorder("Import Options"))
            
            # Create checkboxes
            Logger.debug("Creating checkboxes")
            self.name_cb = JCheckBox("Variable Names", True)
            self.datatype_cb = JCheckBox("Data Types", True)
            self.comments_cb = JCheckBox("Comments", True)
            self.memory_cb = JCheckBox("Memory Layout", True)
            self.conversion_cb = JCheckBox("Conversion Methods", True)
            self.functions_cb = JCheckBox("Functions", True)
            self.groups_cb = JCheckBox("Groups", True)
            
            # Add checkboxes to options panel
            options = [self.name_cb, self.datatype_cb, self.comments_cb,
                      self.memory_cb, self.conversion_cb, self.functions_cb,
                      self.groups_cb]
            for opt in options:
                options_panel.add(opt)
                
            # Create preview table
            Logger.debug("Creating preview table")
            self.table_model = DefaultTableModel(
                ["Name", "Type", "Address", "DataType", "Conversion"], 0
            )
            self.preview_table = JTable(self.table_model)
            table_scroll = JScrollPane(self.preview_table)
            table_scroll.setPreferredSize(Dimension(600, 300))
            
            # Create button panel
            Logger.debug("Creating buttons")
            button_panel = JPanel()
            self.select_button = JButton("Select A2L File",
                                       actionPerformed=self.select_file)
            self.import_button = JButton("Import Selected",
                                       actionPerformed=self.import_data)
            self.import_button.setEnabled(False)
            button_panel.add(self.select_button)
            button_panel.add(self.import_button)
            
            # Assemble the panel
            Logger.debug("Assembling panel components")
            north_panel = JPanel(BorderLayout())
            north_panel.add(options_panel, BorderLayout.CENTER)
            north_panel.add(button_panel, BorderLayout.SOUTH)
            
            self.add(north_panel, BorderLayout.NORTH)
            self.add(table_scroll, BorderLayout.CENTER)
            
            Logger.debug("Panel setup complete")
            
        except Exception as e:
            Logger.error("Error in setup_panel: {}".format(str(e)))
            import traceback
            Logger.debug("Full traceback: {}".format(traceback.format_exc()))
            
    def select_file(self, event):
        """Handle file selection"""
        Logger.debug("File selection started")
        try:
            chooser = JFileChooser()
            if chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
                self.a2l_path = chooser.getSelectedFile().getAbsolutePath()
                Logger.debug("Selected file: {}".format(self.a2l_path))
                self.parser = A2LParser(self.a2l_path)
                self.update_preview()
                self.import_button.setEnabled(True)
        except Exception as e:
            Logger.error("Error selecting file: {}".format(str(e)))
            import traceback
            Logger.debug("Full traceback: {}".format(traceback.format_exc()))
            
    def update_preview(self):
        """Update preview table with parsed data"""
        Logger.debug("Updating preview table")
        try:
            self.table_model.setRowCount(0)
            variables = self.parser.parse_file()
            Logger.debug("Parsed {} variables".format(len(variables)))
            
            for name, info in variables.items():
                addr = info.get('address', 0)
                addr_str = hex(addr) if addr else ''
                row = [
                    name,
                    info.get('type', ''),
                    addr_str,
                    info.get('datatype', ''),
                    info.get('compu_method', '')
                ]
                self.table_model.addRow(row)
                
            if self.file_callback:
                Logger.debug("Calling file callback")
                self.file_callback(self.parser)
                
        except Exception as e:
            Logger.error("Error updating preview: {}".format(str(e)))
            import traceback
            Logger.debug("Full traceback: {}".format(traceback.format_exc()))
            
    def import_data(self, event):
        """Import selected data into Ghidra"""
        Logger.debug("Starting data import")
        if not hasattr(self, 'parser'):
            Logger.error("No A2L file selected")
            return
            
        # Start transaction
        transaction = None
        try:
            transaction = self.current_program.startTransaction("A2L Import")
            variables = self.parser.parse_file()
            imported_count = 0
            
            Logger.debug("Processing {} variables".format(len(variables)))
            for name, info in variables.items():
                if 'address' not in info:
                    continue
                    
                addr = self.current_program.getAddressFactory().getAddress(
                    hex(info['address']))
                Logger.debug("Processing variable {} at {}".format(name, addr))
                
                # Import variable name if selected
                if self.name_cb.isSelected():
                    self.current_program.getSymbolTable().createLabel(
                        addr, name, SourceType.IMPORTED)
                    imported_count += 1
                    
                # Import data type if selected
                if self.datatype_cb.isSelected() and 'datatype' in info:
                    Logger.debug("Data type import not yet implemented")
                    pass
                
                # Add comments if selected
                if self.comments_cb.isSelected():
                    self.current_program.getListing().setComment(
                        addr, CodeUnit.EOL_COMMENT,
                        "A2L Import: {}".format(info['type']))
                        
            Logger.info("Successfully imported {} variables".format(imported_count))
            
        except Exception as e:
            Logger.error("Error during import: {}".format(str(e)))
            import traceback
            Logger.debug("Full traceback: {}".format(traceback.format_exc()))
        finally:
            if transaction is not None:
                self.current_program.endTransaction(transaction, True)
                Logger.debug("Import transaction completed")

if __name__ == "__main__":
    Logger.debug("Import Panel module loaded")