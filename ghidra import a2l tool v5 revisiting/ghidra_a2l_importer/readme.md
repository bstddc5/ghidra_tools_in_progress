# Project Structure
ghidra_a2l_importer/
├── __init__.py                # Empty file to mark as package
├── __main__.py
├── config/
│   ├── __init__.py           # Empty file
│   └── settings.py
├── core/
│   ├── __init__.py           # Empty file
│   ├── parser/
│   │   ├── __init__.py       # Empty file
│   │   └── a2l_parser.py
│   └── ghidra/
│       ├── __init__.py       # Empty file
│       ├── symbol_manager.py
│       └── type_manager.py
├── gui/
│   ├── __init__.py           # Empty file
│   ├── main_window.py
│   └── widgets/
│       ├── __init__.py       # Empty file
│       ├── import_panel.py
│       ├── memory_panel.py
│       ├── conversion_panel.py
│       └── status_panel.py
└── utils/
    ├── __init__.py           # Empty file
    └── logger.py