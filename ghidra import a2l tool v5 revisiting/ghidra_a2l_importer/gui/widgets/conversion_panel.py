# gui/widgets/conversion_panel.py
from javax.swing import (JPanel, JTable, JScrollPane, JSplitPane,
                        BorderFactory, JLabel)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, Dimension

class ConversionPanel(JPanel):
    def __init__(self, current_program, flat_api):
        JPanel.__init__(self)
        self.current_program = current_program
        self.api = flat_api
        self.setup_panel()
        
    def setup_panel(self):
        """Setup conversion methods panel"""
        self.setLayout(BorderLayout(10, 10))
        self.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # Create tables for conversion methods and tables
        self.methods_model = DefaultTableModel(
            ["Name", "Format", "Unit"], 0
        )
        self.methods_table = JTable(self.methods_model)
        methods_scroll = JScrollPane(self.methods_table)
        
        self.tabs_model = DefaultTableModel(
            ["Name", "Input", "Output"], 0
        )
        self.tabs_table = JTable(self.tabs_model)
        tabs_scroll = JScrollPane(self.tabs_table)
        
        # Create split pane
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                          methods_scroll,
                          tabs_scroll)
        split.setDividerLocation(300)
        
        # Add labels
        methods_label = JLabel("Conversion Methods")
        tabs_label = JLabel("Conversion Tables")
        
        top_panel = JPanel(BorderLayout())
        top_panel.add(methods_label, BorderLayout.NORTH)
        top_panel.add(methods_scroll, BorderLayout.CENTER)
        
        bottom_panel = JPanel(BorderLayout())
        bottom_panel.add(tabs_label, BorderLayout.NORTH)
        bottom_panel.add(tabs_scroll, BorderLayout.CENTER)
        
        # Create split pane
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                          top_panel,
                          bottom_panel)
        split.setDividerLocation(300)
        
        self.add(split, BorderLayout.CENTER)
        
    def update_data(self, compu_methods, compu_tabs):
        """Update conversion data"""
        self.methods_model.setRowCount(0)
        self.tabs_model.setRowCount(0)
        
        for name, method in compu_methods.items():
            self.methods_model.addRow([
                name,
                method.format,
                method.unit
            ])
            
        for name, tab in compu_tabs.items():
            for input_val, output_val in tab.pairs.items():
                self.tabs_model.addRow([
                    name,
                    str(input_val),
                    str(output_val)
                ])