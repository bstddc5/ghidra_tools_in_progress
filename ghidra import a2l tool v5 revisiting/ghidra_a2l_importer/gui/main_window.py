"""Main window implementation for A2L Importer"""

from utils.logger import Logger
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

class BasePanel(JPanel):
    # ... (rest of the implementation as before)
