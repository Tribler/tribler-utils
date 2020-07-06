import ast
import distutils.sysconfig as sysconfig
import importlib
import importlib.util
import pathlib
import pkgutil
import os
import sys


external_modules = set()

tribler_source_dirs = [
    os.path.join(sys.argv[1], 'src'),
    os.path.join(sys.argv[1], 'src', 'anydex'),
    os.path.join(sys.argv[1], 'src', 'pyipv8'),
    os.path.join(sys.argv[1], 'src', 'tribler-common'),
    os.path.join(sys.argv[1], 'src', 'tribler-core'),
    os.path.join(sys.argv[1], 'src', 'tribler-gui')
]
sys.path.extend(tribler_source_dirs)
original_sys_path = sys.path
naked_sys_path = [os.path.dirname(os.path.dirname(importlib.__file__))]
naked_sys_path.append(os.path.join(naked_sys_path[0], 'lib-dynload'))

global_imports = set()
local_imports = set()


def is_external_module(path, name):
    """
    Check if we can import this module from somewhere in the local file structure.
    (Filter out imports within the workspace)
    """
    # The AST "module" field may be None
    if not name:
        return

    # Normalize the name to the package, e.g.:
    #  ..bar in foo/bar.py becomes foo.bar
    for source_path in tribler_source_dirs:
        if path.startswith(source_path):
            local_path = path[len(source_path)+1:]
            name = importlib.util.resolve_name(name, local_path.replace(os.sep, '.') or path.split(os.sep)[-1])
    package_name = name.split('.')[0]

    # Strip all external import paths and reload.
    # Anything imported at level 0 at this point is a standard library.
    try:
        naked_sys = importlib.reload(sys)
        naked_sys.path = ['/usr/lib/python3.8', '/usr/lib/python3.8/lib-dynload']
        imported = __import__(package_name, globals={'sys': naked_sys}, locals={}, level=0)
        if ((not getattr(imported, '__file__', None))
                or ('site-packages' not in imported.__file__ and 'dist-packages' not in imported.__file__)):
            global_imports.add(package_name)
            return
    except ImportError:
        # This is not a standard library, continue.
        pass

    # Reinstate the source imports and attempt to import again.
    # Anything not reachable from this location is truly an external import.
    try:
        original_sys = importlib.reload(sys)
        original_sys.path = original_sys_path
        imported = __import__(package_name, globals={'sys': original_sys}, locals={}, level=0)
        if ((not getattr(imported, '__file__', None))
                or ('site-packages' not in imported.__file__ and 'dist-packages' not in imported.__file__)):
            local_imports.add(package_name)
            return
    except ImportError:
        # The module could not be imported, it is not a standard library and also not in our local scope.
        external_modules.add(package_name)
    # The module could be imported, but it is not a standard library or in our local scope.
    external_modules.add(package_name)


location = os.path.abspath(sys.argv[1])
for dirpath, dirnames, filenames in os.walk(location):
    py_filenames = [filename for filename in filenames if filename.endswith('.py')]
    for filename in py_filenames:
        with pathlib.Path(dirpath, filename).open() as file:
            file_contents = file.read()
        if not file_contents:
            continue
        try:
            node = ast.parse(file_contents)
            for subnode in ast.walk(node):
                if isinstance(subnode, ast.Import):
                    for import_name in (alias.name for alias in subnode.names):
                        is_external_module(dirpath, import_name)
                if isinstance(subnode, ast.ImportFrom):
                    if subnode.module is not None:
                        is_external_module(dirpath, '.' * subnode.level + subnode.module)
        except:
            print("ERROR: Failed to parse", filename, file=sys.stderr)


for external_name in sorted(external_modules):
    print(external_name)

