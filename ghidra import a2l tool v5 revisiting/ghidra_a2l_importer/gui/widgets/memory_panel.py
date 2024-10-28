# gui/widgets/memory_panel.py
from javax.swing import (JPanel, JTable, JScrollPane, BorderFactory)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, Dimension

class MemoryPanel(JPanel):
    def __init__(self, current_program, flat_api):
        JPanel.__init__(self)
        self.current_program = current_program
        self.api = flat_api
        self.setup_panel()
        
    def setup_panel(self):
        """Setup memory layout panel"""
        self.setLayout(BorderLayout(10, 10))
        self.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # Create table for memory segments
        self.table_model = DefaultTableModel(
            ["Name", "Start Address", "Size", "Type"], 0
        )
        self.memory_table = JTable(self.table_model)
        scroll_pane = JScrollPane(self.memory_table)
        scroll_pane.setPreferredSize(Dimension(600, 300))
        
        self.add(scroll_pane, BorderLayout.CENTER)
        
    def update_data(self, memory_segments):
        """Update memory segment data"""
        self.table_model.setRowCount(0)
        for segment in memory_segments:
            self.table_model.addRow([
                segment.name,
                hex(segment.start_address),
                str(segment.size),
                segment.attribute
            ])