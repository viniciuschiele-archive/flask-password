from importlib import import_module

def force_bytes(data):
    if isinstance(data, bytes):
        return data

    if isinstance(data, str):
        return data.encode()

    return str(data).encode()

def force_text(data):
    if isinstance(data, bytes):
        return data.decode()

    if isinstance(data, str):
        return data

    return str(data)

def import_string(dotted_path):
    """
    Import a dotted module path and return the attribute/class designated by the
    last name in the path. Raise ImportError if the import failed.
    """
    try:
        module_path, class_name = dotted_path.rsplit('.', 1)
    except ValueError:
        msg = "%s doesn't look like a module path" % dotted_path
        raise LookupError(msg)

    module = import_module(module_path)

    try:
        return getattr(module, class_name)
    except AttributeError:
        msg = 'Module "%s" does not define a "%s" attribute/class' % (dotted_path, class_name)
        raise LookupError(msg)
