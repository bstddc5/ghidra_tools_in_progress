# verify_and_fix.py
import os
import shutil

def create_directory_structure(base_path):
    """Create the required directory structure"""
    directories = [
        'config',
        'core/parser',
        'gui/widgets',
        'utils'
    ]
    
    for directory in directories:
        dir_path = os.path.join(base_path, directory)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
            print("Created directory: {}".format(dir_path))

def create_init_files(base_path):
    """Create all necessary __init__.py files"""
    init_contents = {
        '__init__.py': '"""A2L Importer package"""',
        'config/__init__.py': '"""Configuration package"""',
        'core/__init__.py': '"""Core package"""',
        'core/parser/__init__.py': '"""Parser package"""\nfrom .a2l_parser import A2LParser',
        'gui/__init__.py': '"""GUI package"""\nfrom .main_window import A2LImporterGUI',
        'gui/widgets/__init__.py': '"""Widgets package"""',
        'utils/__init__.py': '"""Utils package"""\nfrom .logger import Logger'
    }
    
    for rel_path, content in init_contents.items():
        full_path = os.path.join(base_path, rel_path)
        with open(full_path, 'w') as f:
            f.write(content)
        print("Created: {}".format(full_path))

def create_main_script(base_path):
    """Create the __main__.py script"""
    content = '''#@category A2L
#@menupath Tools.A2L.Import
#@toolbar 

import os
import sys
import traceback

# Add the project root to Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

try:
    # Import local logger first
    from utils.logger import Logger
    
    Logger.info("Starting A2L Import Tool")
    Logger.debug("Script directory: {}".format(script_dir))
    Logger.debug("Python path: {}".format(sys.path))
    
    # Import GUI
    from gui.main_window import A2LImporterGUI
    
    def run_script():
        try:
            gui = A2LImporterGUI(state)
            if gui.current_program:
                gui.setVisible(True)
        except Exception as e:
            Logger.error("Error running script: {}".format(str(e)))
            Logger.debug("Traceback: {}".format(traceback.format_exc()))
    
    if __name__ == '__main__':
        run_script()
        
except Exception as e:
    print("Error during script initialization: {}".format(str(e)))
    print("Traceback: {}".format(traceback.format_exc()))
'''
    path = os.path.join(base_path, '__main__.py')
    with open(path, 'w') as f:
        f.write(content)
    print("Created: {}".format(path))

def create_logger(base_path):
    """Create the logger.py file"""
    content = '''"""Logging utility for A2L Importer"""

class Logger(object):
    DEBUG = True
    
    @classmethod
    def debug(cls, msg):
        if cls.DEBUG:
            print("[DEBUG] {}".format(msg))
    
    @classmethod
    def info(cls, msg):
        print("[INFO] {}".format(msg))
    
    @classmethod
    def error(cls, msg):
        print("[ERROR] {}".format(msg))
    
    @classmethod
    def warning(cls, msg):
        print("[WARNING] {}".format(msg))
'''
    path = os.path.join(base_path, 'utils', 'logger.py')
    with open(path, 'w') as f:
        f.write(content)
    print("Created: {}".format(path))

def create_main_window(base_path):
    """Create the main_window.py file"""
    # Copy the content from your A2LImporter.py (the one we created earlier)
    # but remove the Logger class and import it from utils instead
    path = os.path.join(base_path, 'gui', 'main_window.py')
    with open(path, 'w') as f:
        f.write('''"""Main window implementation for A2L Importer"""

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
''')
    print("Created: {}".format(path))

def verify_structure(base_path):
    """Verify the file structure is correct"""
    required_files = [
        '__init__.py',
        '__main__.py',
        'config/__init__.py',
        'core/__init__.py',
        'core/parser/__init__.py',
        'gui/__init__.py',
        'gui/main_window.py',
        'gui/widgets/__init__.py',
        'utils/__init__.py',
        'utils/logger.py'
    ]
    
    missing = []
    for file_path in required_files:
        full_path = os.path.join(base_path, file_path)
        if not os.path.exists(full_path):
            missing.append(file_path)
    
    return missing

def main():
    # Get the current directory as base path
    base_path = os.path.dirname(os.path.abspath(__file__))
    print("Base path: {}".format(base_path))
    
    # Create structure
    create_directory_structure(base_path)
    create_init_files(base_path)
    create_main_script(base_path)
    create_logger(base_path)
    create_main_window(base_path)
    
    # Verify structure
    missing = verify_structure(base_path)
    if missing:
        print("\nMissing files:")
        for file_path in missing:
            print("  " + file_path)
    else:
        print("\nAll required files present")
        
    print("\nAdd this directory to your Python path:")
    print(base_path)

if __name__ == '__main__':
    main()