#@category A2L
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
