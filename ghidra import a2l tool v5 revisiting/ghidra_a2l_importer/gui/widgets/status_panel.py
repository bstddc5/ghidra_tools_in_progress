# gui/widgets/status_panel.py
from javax.swing import JPanel, JLabel, BorderFactory
from java.awt import BorderLayout

class StatusPanel(JPanel):
    def __init__(self):
        JPanel.__init__(self)
        self.setup_panel()
        
    def setup_panel(self):
        """Setup status panel"""
        self.setLayout(BorderLayout())
        self.setBorder(BorderFactory.createEtchedBorder())
        
        self.status_label = JLabel(" ")
        self.add(self.status_label, BorderLayout.WEST)
        
    def set_status(self, message):
        """Update status message"""
        self.status_label.setText(message)