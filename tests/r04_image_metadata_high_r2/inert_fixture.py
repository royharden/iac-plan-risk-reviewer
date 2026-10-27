"""Ordinary synthetic tree adapter. No OS effects, candidate code, links or cleanup."""
import hashlib
from pathlib import Path
import stat
import types


class Writer:
    def __init__(self, tree, key):
        assert key not in tree.files and key not in tree.directories
        self.tree, self.key = tree, key
        self.raw = bytearray()

    def __enter__(self):
        return self

    def write(self, raw):
        self.raw.extend(raw)
        return len(raw)

    def __exit__(self, *error):
        assert error == (None, None, None)
        self.tree.files[self.key] = bytes(self.raw)


class BuildPath:
    """Only the original builder's Path operations, backed by ordinary inert nodes."""
    def __init__(self, tree, path):
        self.tree, self.path = tree, Path(path)

    def __truediv__(self, child):
        return BuildPath(self.tree, self.path / child)

    @property
    def parent(self):
        return BuildPath(self.tree, self.path.parent)

    @property
    def parents(self):
        return tuple(BuildPath(self.tree, path) for path in self.path.parents)

    def exists(self):
        return self.path in self.tree.directories or self.path in self.tree.files

    def mkdir(self, parents=False, exist_ok=False):
        assert self.path not in self.tree.files
        if self.path in self.tree.directories:
            assert exist_ok
            return
        if parents:
            self.tree.directories.update(self.path.parents)
        else:
            assert self.path.parent in self.tree.directories
        self.tree.directories.add(self.path)

    def lstat(self):
        if self.path in self.tree.directories:
            mode = stat.S_IFDIR | 0o755
        elif self.path in self.tree.files:
            mode = stat.S_IFREG | 0o644
        else:
            raise FileNotFoundError(str(self.path))
        return types.SimpleNamespace(st_mode=mode, st_nlink=1, st_file_attributes=0)

    def open(self, mode):
        assert mode == "xb" and self.path.parent in self.tree.directories
        return Writer(self.tree, self.path)


class Tree:
    def __init__(self, root):
        self.root = Path(root)
        self.directories = set(self.root.parents)
        self.files = {}
        self.calls = []
        self.node_overrides = {}
        self.entry_overrides = {}
        self.read_overrides = {}
        self.denied_reads = set()

    def builder_root(self):
        return BuildPath(self, self.root)

    def freeze_manifest(self):
        return {str(path): {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                for path, raw in sorted(self.files.items(), key=lambda item: str(item[0]))}

    def observations(self, node_type):
        tree = self

        class CompleteObservations:
            def lstat(self, path):
                assert isinstance(path, Path)
                tree.calls.append(("lstat", str(path)))
                if path in tree.node_overrides:
                    return tree.node_overrides[path]
                if path in tree.directories:
                    return node_type("directory")
                if path in tree.files:
                    return node_type("file", size=len(tree.files[path]))
                raise FileNotFoundError(str(path))

            def entries(self, path):
                assert isinstance(path, Path)
                tree.calls.append(("entries", str(path)))
                if path in tree.entry_overrides:
                    return tree.entry_overrides[path]
                if path not in tree.directories:
                    raise NotADirectoryError(str(path))
                names = {str(item.name) for item in tree.directories | set(tree.files)
                         if item != path and item.parent == path}
                return tuple(sorted(names))

            def read(self, path, limit):
                assert isinstance(path, Path)
                assert type(limit) is int and limit >= 0
                tree.calls.append(("read", str(path), limit))
                if path in tree.denied_reads:
                    raise OSError("inert denied anchor " + str(path))
                if path in tree.read_overrides:
                    return tree.read_overrides[path]
                raw = tree.files[path]
                if len(raw) > limit:
                    raise ValueError("inert read exceeds requested limit")
                return raw

        return CompleteObservations()


def build(original, oracle, data, variant, root):
    tree = Tree(root)
    image, core, checkov, source_sha = original.build(tree.builder_root(), oracle, data, variant)
    return tree, (image.path, core.path, checkov.path), source_sha
