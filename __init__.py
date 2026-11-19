"""Binary Ninja TTD Behavior plugin."""
try:
    from binaryninja import PluginCommand
    from .widget import open_behavior
    PluginCommand.register('TTD Extras\\Behavior', 'Browse Windows API calls from a TTD report', open_behavior)
except ImportError:
    # Allow the report reader and extractor path logic to be used outside Binary Ninja.
    pass
