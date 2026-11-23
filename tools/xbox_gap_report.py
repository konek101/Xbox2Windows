"""Report which Xbox-only imports a PE image still lacks, and whether provider DLLs now supply them.

Reads a `tools/pe_inventory.py` report and the export tables of provider DLLs (for example the
loader-gap stubs built from src/xbox_stub_providers.cpp). It opens files for reading only and never
loads or runs an image. An edge counts as closed when a provider whose base name matches the
requested module exports the exact symbol. This checks the static import surface; it does not prove
that the provider's behavior matches the console.
"""

import argparse
from collections import defaultdict
import json
from pathlib import Path
import sys

import pefile


def provider_exports(paths):
    """Map each provider file name to the set of named exports it advertises."""
    exports = {}
    for path in paths:
        with pefile.PE(str(path), fast_load=True) as pe:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
            names = set()
            directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
            if directory is not None:
                for symbol in directory.symbols:
                    if symbol.name:
                        names.add(symbol.name.decode("ascii", errors="replace"))
        exports[path.name.casefold()] = names
    return exports


def collect(paths):
    files = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(p for p in path.iterdir() if p.suffix.casefold() == ".dll"))
        elif path.is_file():
            files.append(path)
        else:
            raise ValueError(f"no such provider path: {path}")
    if not files:
        raise ValueError("no provider DLLs found")
    return provider_exports(files)


def report(inventory, image, providers):
    edges = inventory["unresolved_edges"]
    selected = [edge for edge in edges if image is None or edge["image"] == image]
    closed, open_edges = [], []
    for edge in selected:
        names = providers.get(edge["dll"].casefold())
        row = dict(image=edge["image"], dll=edge["dll"], symbol=edge["symbol"], kind=edge["kind"])
        (closed if names is not None and edge["symbol"] in names else open_edges).append(row)
    by_module = defaultdict(lambda: {"closed": [], "open": []})
    for row in closed:
        by_module[row["dll"].casefold()]["closed"].append(row["symbol"])
    for row in open_edges:
        by_module[row["dll"].casefold()]["open"].append(row["symbol"])
    return {
        "image": image or "(all)",
        "provider_modules": {name: len(names) for name, names in sorted(providers.items())},
        "closed_edges": len(closed),
        "open_edges": len(open_edges),
        "modules": {name: {"closed": sorted(set(v["closed"])), "open": sorted(set(v["open"]))}
                    for name, v in sorted(by_module.items())},
        "open": open_edges,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path, help="pe_inventory.py JSON report")
    parser.add_argument("providers", type=Path, nargs="+", help="provider DLLs or a directory of them")
    parser.add_argument("--image", help="restrict to this caller image (for example the executable)")
    parser.add_argument("--output", type=Path, help="write the full report as JSON")
    parser.add_argument("--fail-on-open", action="store_true",
                        help="exit 1 when any selected edge is still unprovided")
    args = parser.parse_args(argv)
    try:
        inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
        providers = collect(args.providers)
    except (OSError, ValueError, KeyError, TypeError, pefile.PEFormatError) as exc:
        parser.error(str(exc))
    result = report(inventory, args.image, providers)
    print(f"{result['image']}: {result['closed_edges']} closed | {result['open_edges']} open")
    for module, lists in result["modules"].items():
        if lists["open"]:
            print(f"  open {module}: {', '.join(lists['open'])}")
        if lists["closed"]:
            print(f"  closed {module}: {len(lists['closed'])} export(s)")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                               encoding="utf-8")
    return 1 if args.fail_on_open and result["open_edges"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
