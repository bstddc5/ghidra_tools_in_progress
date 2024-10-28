# ghidra_a2l_importer/verify_structure.py

import os
import sys

def create_project_structure(base_path):
    """Create or verify the project structure"""
    # Ensure we're working with absolute paths
    base_path = os.path.abspath(base_path)
    print("Creating structure in: {}".format(base_path))
    
    # Define the directory structure
    directories = [
        'config',
        'core',
        'core/parser',
        'gui',
        'gui/widgets',
        'utils'
    ]
    
    # Create directories
    for dir_path in directories:
        full_path = os.path.join(base_path, dir_path)
        if not os.path.exists(full_path):
            os.makedirs(full_path)
            print("Created directory: {}".format(full_path))
            
        # Create __init__.py in each directory
        init_file = os.path.join(full_path, '__init__.py')
        if not os.path.exists(init_file):
            with open(init_file, 'w') as f:
                f.write("")
            print("Created: {}".format(init_file))
    
    # Create/update the logger.py file
    logger_content = """
class Logger(object):
    \"\"\"Simple logging utility for the A2L importer\"\"\"
    
    DEBUG = True
    
    @classmethod
    def debug(cls, message):
        \"\"\"Log debug message\"\"\"
        if cls.DEBUG:
            print("[DEBUG] {}".format(message))
    
    @classmethod
    def info(cls, message):
        \"\"\"Log info message\"\"\"
        print("[INFO] {}".format(message))
    
    @classmethod
    def error(cls, message):
        \"\"\"Log error message\"\"\"
        print("[ERROR] {}".format(message))
    
    @classmethod
    def warning(cls, message):
        \"\"\"Log warning message\"\"\"
        print("[WARNING] {}".format(message))
"""
    
    logger_path = os.path.join(base_path, 'utils', 'logger.py')
    with open(logger_path, 'w') as f:
        f.write(logger_content.strip())
    print("Created/Updated: {}".format(logger_path))
    
    # Create/update utils/__init__.py
    utils_init_content = """# utils/__init__.py
from .logger import Logger

__all__ = ['Logger']
"""
    utils_init_path = os.path.join(base_path, 'utils', '__init__.py')
    with open(utils_init_path, 'w') as f:
        f.write(utils_init_content.strip())
    print("Created/Updated: {}".format(utils_init_path))
    
    # Create/update root __init__.py
    root_init_content = """# Make core modules available at package level
from .utils.logger import Logger

__all__ = ['Logger']
"""
    root_init_path = os.path.join(base_path, '__init__.py')
    with open(root_init_path, 'w') as f:
        f.write(root_init_content.strip())
    print("Created/Updated: {}".format(root_init_path))
    
    # Create/update __main__.py
    main_content = """#@category A2L
#@menupath Tools.A2L.Import
#@toolbar 

import os
import sys
import traceback

try:
    # Get absolute path of script directory
    script_dir = os.path.abspath(os.path.dirname(__file__))
    
    # Add script directory to Python path
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
        
    # Use absolute imports from package
    from ghidra_a2l_importer.utils.logger import Logger
    
    Logger.info("Starting A2L Import Tool")
    Logger.debug("Script directory: {}".format(script_dir))
    Logger.debug("Python path: {}".format(sys.path))
    
    from ghidra_a2l_importer.gui.main_window import A2LImporterGUI
    
    def run_script():
        try:
            gui = A2LImporterGUI(state)
            if gui.current_program:
                gui.setVisible(True)
                Logger.info("GUI initialized successfully")
            else:
                Logger.error("No program is currently open")
        except Exception as e:
            Logger.error("Error running script: {}".format(str(e)))
            Logger.debug("Traceback: {}".format(traceback.format_exc()))
    
    if __name__ == '__main__':
        run_script()
        
except Exception as e:
    print("Error during script initialization: {}".format(str(e)))
    print("Traceback: {}".format(traceback.format_exc()))
"""
    
    main_path = os.path.join(base_path, '__main__.py')
    with open(main_path, 'w') as f:
        f.write(main_content.strip())
    print("Created/Updated: {}".format(main_path))

def verify_imports(base_path):
    """Test the imports"""
    print("\nTesting imports...")
    
    # Add the parent directory to Python path
    parent_dir = os.path.dirname(base_path)
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    
    print("Python path:")
    for p in sys.path:
        print("  " + str(p))
        
    try:
        print("\nTrying to import Logger...")
        from ghidra_a2l_importer.utils.logger import Logger
        print("Successfully imported Logger")
        Logger.info("Test message")
    except ImportError as e:
        print("Failed to import Logger: {}".format(str(e)))
        
if __name__ == '__main__':
    # Get the project root directory (ghidra_a2l_importer folder)
    project_root = os.path.dirname(os.path.abspath(__file__))
    print("Project root: {}".format(project_root))
    
    # Create/verify structure
    create_project_structure(project_root)
    
    # Verify imports
    verify_imports(project_root)