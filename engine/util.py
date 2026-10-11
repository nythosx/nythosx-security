import os
import tempfile
from pathlib import Path


def safe_name(s, maxlen=80):
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)[:maxlen]


def atomic_write_text(path, text, encoding="utf-8"):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(text)
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def atomic_write_json(path, obj, indent=2):
    import json
    atomic_write_text(path, json.dumps(obj, indent=indent, default=str))


def strict_yaml_load(text):
    """yaml.safe_load with duplicate-key detection.

    Raises yaml.constructor.ConstructorError on duplicate mapping keys.
    """
    import yaml

    class _StrictLoader(yaml.SafeLoader):
        pass

    def _no_dupes(loader, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    None, None,
                    f"found duplicate key: {key!r}",
                    key_node.start_mark,
                )
            value = loader.construct_object(value_node, deep=deep)
            mapping[key] = value
        return mapping

    _StrictLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_dupes,
    )
    return yaml.load(text, Loader=_StrictLoader)


def strict_yaml_load_file(path):
    from pathlib import Path as _P
    return strict_yaml_load(_P(path).read_text(encoding="utf-8"))

