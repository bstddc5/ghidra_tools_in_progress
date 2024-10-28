# A2LImporter.py (put this in your Ghidra scripts folder)
#@category A2L
#@menupath Tools.A2L.Import
#@toolbar

import os
import sys
import traceback

# Simple logger implementation to avoid import issues
class Logger(object):
    DEBUG = True
    
    @classmethod
    def debug(cls, msg):
        if cls.DEBUG:
            print("[DEBUG] " + str(msg))
    
    @classmethod
    def info(cls, msg):
        print("[INFO] " + str(msg))
    
    @classmethod
    def error(cls, msg):
        print("[ERROR] " + str(msg))
    
    @classmethod
    def warning(cls, msg):
        print("[WARNING] " + str(msg))

# Ghidra/Java imports
try:
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.listing import CodeUnit
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.task import ConsoleTaskMonitor
    from java.awt import BorderLayout, Dimension, GridLayout
    from javax.swing import (JFrame, JTabbedPane, JSplitPane, JScrollPane, 
                           JPanel, BorderFactory, JOptionPane, JButton, 
                           JCheckBox, JLabel, JProgressBar, JTable, 
                           JFileChooser)
    from javax.swing.table import DefaultTableModel
except Exception as e:
    Logger.error("Error loading Ghidra/Java imports: {}".format(str(e)))
    raise

# Panel implementations
class BasePanel(JPanel):
    def __init__(self, current_program, flat_api):
        super(BasePanel, self).__init__()
        self.current_program = current_program
        self.api = flat_api
        self.setup_panel()
    
    def setup_panel(self):
        pass

class ImportPanel(BasePanel):
    def setup_panel(self):
        try:
            self.setLayout(BorderLayout(10, 10))
            self.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
            
            # Create options panel
            options_panel = JPanel()
            options_panel.setLayout(BorderLayout())
            options_panel.setBorder(BorderFactory.createTitledBorder("Import Options"))
            
            # Create checkboxes panel
            checkbox_panel = JPanel(GridLayout(0, 2, 5, 5))
            self.name_cb = JCheckBox("Variable Names", True)
            self.datatype_cb = JCheckBox("Data Types", True)
            self.comments_cb = JCheckBox("Comments", True)
            self.memory_cb = JCheckBox("Memory Layout", True)
            
            # Add checkboxes
            checkbox_panel.add(self.name_cb)
            checkbox_panel.add(self.datatype_cb)
            checkbox_panel.add(self.comments_cb)
            checkbox_panel.add(self.memory_cb)
            
            options_panel.add(checkbox_panel, BorderLayout.CENTER)
            
            # Create button panel
            button_panel = JPanel()
            self.select_button = JButton("Select A2L File", actionPerformed=self.select_file)
            self.import_button = JButton("Import", actionPerformed=self.import_data)
            self.import_button.setEnabled(False)
            
            button_panel.add(self.select_button)
            button_panel.add(self.import_button)
            
            # Create preview table
            self.table_model = DefaultTableModel(
                ["Name", "Type", "Address", "DataType", "Conversion"], 0
            )
            self.preview_table = JTable(self.table_model)
            scroll_pane = JScrollPane(self.preview_table)
            
            # Add components
            top_panel = JPanel(BorderLayout())
            top_panel.add(options_panel, BorderLayout.CENTER)
            top_panel.add(button_panel, BorderLayout.SOUTH)
            
            self.add(top_panel, BorderLayout.NORTH)
            self.add(scroll_pane, BorderLayout.CENTER)
            
        except Exception as e:
            Logger.error("Error setting up Import Panel: {}".format(str(e)))
            
    def select_file(self, event):
        try:
            chooser = JFileChooser()
            if chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
                path = chooser.getSelectedFile().getAbsolutePath()
                Logger.info("Selected file: {}".format(path))
                self.import_button.setEnabled(True)
        except Exception as e:
            Logger.error("Error selecting file: {}".format(str(e)))
            
    def import_data(self, event):
        try:
            Logger.info("Starting import...")
            # TODO: Implement import logic
        except Exception as e:
            Logger.error("Error during import: {}".format(str(e)))

class MemoryPanel(BasePanel):
    def setup_panel(self):
        try:
            self.setLayout(BorderLayout(10, 10))
            self.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
            
            # Create table
            self.table_model = DefaultTableModel(
                ["Segment", "Start Address", "Size", "Type", "Permissions"], 0
            )
            self.memory_table = JTable(self.table_model)
            scroll_pane = JScrollPane(self.memory_table)
            
            # Add test data
            self.table_model.addRow(["ROM", "0x00000000", "64KB", "Flash", "RX"])
            
            # Create controls
            controls_panel = JPanel()
            refresh_button = JButton("Refresh", actionPerformed=self.refresh_data)
            controls_panel.add(refresh_button)
            
            self.add(controls_panel, BorderLayout.NORTH)
            self.add(scroll_pane, BorderLayout.CENTER)
            
        except Exception as e:
            Logger.error("Error setting up Memory Panel: {}".format(str(e)))
            
    def refresh_data(self, event):
        try:
            Logger.info("Refreshing memory data...")
        except Exception as e:
            Logger.error("Error refreshing data: {}".format(str(e)))

class ConversionPanel(BasePanel):
    def setup_panel(self):
        try:
            self.setLayout(BorderLayout(10, 10))
            self.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
            
            # Create split pane
            split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            
            # Methods table
            self.methods_model = DefaultTableModel(
                ["Name", "Type", "Format", "Unit"], 0
            )
            methods_table = JTable(self.methods_model)
            methods_scroll = JScrollPane(methods_table)
            methods_panel = JPanel(BorderLayout())
            methods_panel.setBorder(BorderFactory.createTitledBorder("Conversion Methods"))
            methods_panel.add(methods_scroll)
            
            # Values table
            self.values_model = DefaultTableModel(
                ["Method", "Input", "Output"], 0
            )
            values_table = JTable(self.values_model)
            values_scroll = JScrollPane(values_table)
            values_panel = JPanel(BorderLayout())
            values_panel.setBorder(BorderFactory.createTitledBorder("Conversion Values"))
            values_panel.add(values_scroll)
            
            # Setup split pane
            split_pane.setTopComponent(methods_panel)
            split_pane.setBottomComponent(values_panel)
            split_pane.setDividerLocation(200)
            
            self.add(split_pane, BorderLayout.CENTER)
            
        except Exception as e:
            Logger.error("Error setting up Conversion Panel: {}".format(str(e)))

class StatusPanel(JPanel):
    def __init__(self):
        super(StatusPanel, self).__init__()
        self.setup_panel()
        
    def setup_panel(self):
        try:
            self.setLayout(BorderLayout())
            self.setBorder(BorderFactory.createEtchedBorder())
            
            # Create status label
            self.status_label = JLabel(" ")
            self.status_label.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5))
            
            # Create progress bar
            self.progress_bar = JProgressBar()
            self.progress_bar.setVisible(False)
            
            # Add components
            self.add(self.status_label, BorderLayout.CENTER)
            self.add(self.progress_bar, BorderLayout.EAST)
            
        except Exception as e:
            Logger.error("Error setting up Status Panel: {}".format(str(e)))
            
    def set_status(self, message):
        self.status_label.setText(message)
        
    def show_progress(self, visible):
        self.progress_bar.setVisible(visible)
        
    def set_progress(self, value):
        self.progress_bar.setValue(value)

class A2LImporterGUI(JFrame):
    def __init__(self, ghidra_state):
        try:
            super(A2LImporterGUI, self).__init__("A2L Importer")
            self.ghidra_state = ghidra_state
            
            # Get current program
            self.current_program = self.ghidra_state.getCurrentProgram()
            Logger.debug("Current program: {}".format(
                "Found" if self.current_program else "None"))
            
            if not self.current_program:
                Logger.error("No program is currently open")
                JOptionPane.showMessageDialog(None,
                    "Please open a program before running this script.",
                    "No Program Open",
                    JOptionPane.ERROR_MESSAGE)
                return
            
            # Initialize Ghidra API
            self.monitor = ConsoleTaskMonitor()
            self.api = FlatProgramAPI(self.current_program, self.monitor)
            
            self.setup_gui()
            
        except Exception as e:
            Logger.error("Error in A2LImporterGUI.__init__: {}".format(str(e)))
            Logger.debug("Full traceback: {}".format(traceback.format_exc()))
            
    def setup_gui(self):
        try:
            # Set window properties
            self.setSize(800, 600)
            self.setLocationRelativeTo(None)
            self.setLayout(BorderLayout())
            
            # Create panels
            self.tab_pane = JTabbedPane()
            self.import_panel = ImportPanel(self.current_program, self.api)
            self.memory_panel = MemoryPanel(self.current_program, self.api)
            self.conversion_panel = ConversionPanel(self.current_program, self.api)
            self.status_panel = StatusPanel()
            
            # Add tabs
            self.tab_pane.addTab("Import", self.import_panel)
            self.tab_pane.addTab("Memory Layout", self.memory_panel)
            self.tab_pane.addTab("Conversions", self.conversion_panel)
            
            # Add components
            self.add(self.tab_pane, BorderLayout.CENTER)
            self.add(self.status_panel, BorderLayout.SOUTH)
            
            # Set close operation
            self.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
            
            # Set initial status
            self.status_panel.set_status("Ready")
            
        except Exception as e:
            Logger.error("Error in setup_gui: {}".format(str(e)))
            Logger.debug("Full traceback: {}".format(traceback.format_exc()))

def run():
    """Main entry point for the script"""
    try:
        Logger.info("Starting A2L Import Tool")
        gui = A2LImporterGUI(state)
        if gui.current_program:
            gui.setVisible(True)
    except Exception as e:
        Logger.error("Error running script: {}".format(str(e)))
        Logger.debug("Full traceback: {}".format(traceback.format_exc()))

if __name__ == '__main__':
    run()