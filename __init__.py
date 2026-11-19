"""Binary Ninja TTD Behavior sidebar plugin."""
try:
    import binaryninjaui  # noqa: F401
except ImportError:
    pass
else:
    from . import widget  # registers the sidebar when Binary Ninja loads the plugin
