"""Locate direct call sites for the Xbox-only imports an image still lacks, without running it.

The image is read, never loaded or executed. Targets come from a `tools/pe_inventory.py` report:
the `unresolved_edges` that name the given image. For each target the scanner looks for the
RIP-relative call and jump forms the linker emits for an import (`FF 15`/`FF 25`), a one-level
import thunk (`jmp [slot]` called with `E8 rel32`) and the `.pdata` function that contains each
site. Sites inside the entry point or a TLS callback are marked `tls`/`entry`; a site reached by
one or two direct branches from those regions is marked `entry+1`/`entry+2`.

This is static evidence for prioritization, not observed order. Register-indirect calls, jump
tables, computed imports and runtime-dispatched code are missed, and the executable is never run,
so which stub fails first in practice is unverified.
"""

import argparse
import bisect
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

import pefile

SCN_EXECUTE = 0x20000000
CALL = 0x15
JMP = 0x25
INDIRECT = re.compile(rb"\xff[\x15\x25]")
REX = range(0x40, 0x50)


def normalized(name):
    name = name.decode("ascii", errors="replace").casefold()
    if name.endswith("."):
        return name[:-1]
    if "." not in name:
        return name + ".dll"
    return name


def read_functions(pe):
    """Sorted (begin, end) x64 runtime-function intervals from the exception directory."""
    intervals = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", []):
        begin, end = entry.struct.BeginAddress, entry.struct.EndAddress
        if begin < end <= pe.OPTIONAL_HEADER.SizeOfImage:
            intervals.append((begin, end))
    intervals.sort()
    return intervals


def function_at(intervals, begins, rva):
    i = bisect.bisect_right(begins, rva) - 1
    if i >= 0 and intervals[i][0] <= rva < intervals[i][1]:
        return intervals[i]
    return None


def tls_callbacks(pe):
    base = pe.OPTIONAL_HEADER.ImageBase
    directory = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if directory is None or not directory.struct.AddressOfCallBacks:
        return []
    slot = directory.struct.AddressOfCallBacks - base
    callbacks = []
    for index in range(64):
        raw = pe.get_data(slot + 8 * index, 8)
        if len(raw) != 8:
            break
        pointer = int.from_bytes(raw, "little")
        if not pointer:
            break
        callbacks.append(pointer - base)
    return callbacks


def exports_by_rva(pe):
    names = defaultdict(list)
    for symbol in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []):
        if symbol.name and symbol.address:
            names[symbol.address].append(symbol.name.decode("ascii", errors="replace"))
    return names


def startup_regions(pe, intervals, begins):
    """Entry point and TLS callbacks, resolved to their containing function intervals."""
    base = pe.OPTIONAL_HEADER.ImageBase
    callbacks = tls_callbacks(pe)
    entries = {}
    entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if entry:
        entries[entry] = "entry"
    for callback in callbacks:
        entries.setdefault(callback, "tls")
    regions = {}
    for rva, kind in entries.items():
        interval = function_at(intervals, begins, rva)
        if interval is not None:
            regions.setdefault(interval, kind)
    return dict(entry_rva=entry, tls_callbacks=[hex(r) for r in callbacks],
                regions={f"{hex(b)}-{hex(e)}": k for (b, e), k in sorted(regions.items())},
                mapping=regions)


def image_sections(pe):
    for section in pe.sections:
        if section.Characteristics & SCN_EXECUTE:
            start = section.VirtualAddress
            data = section.get_data()
            if section.Misc_VirtualSize:
                data = data[:section.Misc_VirtualSize]
            yield start, data


def direct_branch_targets(pe, ranges):
    """Direct `call`/`jmp` targets inside the given [lo, hi) RVAs, from bytes only.

    A targeted scan of the small startup intervals, not a decoder: enough to follow the entry's
    tail jump and the first calls it makes.
    """
    targets = []
    for start, data in image_sections(pe):
        end = start + len(data)
        for lo, hi in ranges:
            a, b = max(lo, start), min(hi, end)
            if a >= b:
                continue
            blob = data[a - start:b - start]
            for match in re.finditer(rb"[\xe8\xe9\xeb]", blob):
                off = match.start()
                ip = a + off
                if blob[off] in (0xE8, 0xE9):
                    if off + 5 <= len(blob):
                        targets.append(ip + 5 + struct.unpack_from("<i", blob, off + 1)[0])
                elif off + 2 <= len(blob):
                    targets.append(ip + 2 + struct.unpack_from("<b", blob, off + 1)[0])
    return targets


def scan_sites(pe, slots, intervals, begins):
    """Direct `call/jmp [slot]` sites, one-level thunk callers, and direct-call edges."""
    sites, thunks, calls_to = [], [], defaultdict(list)
    for start, data in image_sections(pe):
        for match in INDIRECT.finditer(data):
            off = match.start()
            if off + 6 > len(data):
                continue
            target = start + off + 6 + struct.unpack_from("<i", data, off + 2)[0]
            if target not in slots:
                continue
            ip = start + off
            if off and data[off - 1] in REX:
                ip -= 1
            transfer = "call" if data[off + 1] == CALL else "jmp"
            interval = function_at(intervals, begins, ip)
            thunk = transfer == "jmp" and (interval is None or interval[0] == ip)
            sites.append(dict(rva=ip, slot=target, transfer=transfer, thunk=thunk,
                              function=interval))
            if thunk:
                thunks.append(ip)
        for match in re.finditer(rb"\xe8", data):
            off = match.start()
            if off + 5 > len(data):
                continue
            target = start + off + 5 + struct.unpack_from("<i", data, off + 1)[0]
            ip = start + off
            interval = function_at(intervals, begins, ip)
            calls_to[target].append((ip, interval))
    return sites, set(thunks), calls_to


def best_startup(labels):
    for wanted in ("tls", "entry", "entry+1", "entry+2"):
        if wanted in labels:
            return wanted
    return None


def collect(inventory, image_name):
    return [edge for edge in inventory["unresolved_edges"]
            if edge["image"].casefold() == image_name.casefold()]


def inspect(path, inventory, image_name):
    data = path.read_bytes()
    with pefile.PE(data=data, fast_load=True) as pe:
        directory = pefile.DIRECTORY_ENTRY
        pe.parse_data_directories(directories=[
            directory["IMAGE_DIRECTORY_ENTRY_IMPORT"], directory["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            directory["IMAGE_DIRECTORY_ENTRY_EXCEPTION"], directory["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
            directory["IMAGE_DIRECTORY_ENTRY_TLS"]])
        if pe.FILE_HEADER.Machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            raise ValueError("expected an x64 image")
        base = pe.OPTIONAL_HEADER.ImageBase
        targets = collect(inventory, image_name)
        wanted = {(edge["dll"].casefold(), edge["symbol"]) for edge in targets}
        slots = {}
        for kind, directory_name in (("import", "DIRECTORY_ENTRY_IMPORT"), ("delay", "DIRECTORY_ENTRY_DELAY_IMPORT")):
            for desc in getattr(pe, directory_name, []):
                module = normalized(desc.dll)
                for imp in desc.imports:
                    if imp.name is None:
                        continue
                    symbol = imp.name.decode("ascii", errors="replace")
                    if (module, symbol) in wanted:
                        slots[imp.address - base] = (module, symbol, kind)
        intervals = read_functions(pe)
        begins = [b for b, _ in intervals]
        startup = startup_regions(pe, intervals, begins)
        sites, _, calls_to = scan_sites(pe, slots, intervals, begins)
        exports = exports_by_rva(pe)

        def describe(interval):
            if interval is None:
                return None
            begin, end = interval
            return dict(begin=hex(begin), end=hex(end), exports=exports.get(begin, []))

        distance = {interval: 0 for interval in startup["mapping"]}
        frontier = list(startup["mapping"])
        for depth in (1, 2):
            found_next = []
            for target in direct_branch_targets(pe, frontier):
                interval = function_at(intervals, begins, target)
                if interval is not None and interval not in distance:
                    distance[interval] = depth
                    found_next.append(interval)
            frontier = found_next

        def labels(interval):
            if interval is None:
                return set()
            if interval in startup["mapping"]:
                return {startup["mapping"][interval]}
            if interval in distance:
                return {f"entry+{distance[interval]}"}
            return set()

        rows = defaultdict(list)
        for site in sites:
            interval = site["function"]
            found = labels(interval)
            if site["thunk"]:
                for ip, caller in calls_to.get(site["rva"], []):
                    caller_labels = labels(caller)
                    rows[site["slot"]].append(dict(
                        kind="thunk-caller", site=hex(ip), function=describe(caller),
                        startup=best_startup(caller_labels), labels=sorted(caller_labels)))
            rows[site["slot"]].append(dict(
                kind="thunk" if site["thunk"] else site["transfer"], site=hex(site["rva"]),
                function=describe(interval), startup=best_startup(found), labels=sorted(found)))

        output, without = [], []
        for slot, (module, symbol, kind) in sorted(slots.items()):
            records = rows.get(slot, [])
            all_labels = {label for record in records for label in record["labels"]}
            consumers = sorted({record["function"]["begin"] for record in records
                                if record["function"] and record["kind"] != "thunk"})
            row = dict(module=module, symbol=symbol, import_kind=kind, iat_rva=hex(slot),
                       startup=best_startup(all_labels), records=records,
                       consumer_functions=consumers)
            (output if records else without).append(row)
        covered = {(row["module"], row["symbol"]) for row in output}
        missing = [dict(module=e["dll"].casefold(), symbol=e["symbol"]) for e in targets
                   if (e["dll"].casefold(), e["symbol"]) not in covered]
        return dict(
            format=1, image=image_name, sha256=hashlib.sha256(data).hexdigest(),
            startup=dict(entry_rva=hex(startup["entry_rva"]) if startup["entry_rva"] else None,
                         entry_regions=list(startup["regions"]),
                         tls_callbacks=startup["tls_callbacks"]),
            symbols=output,
            no_direct_sites=without,
            no_import_match=missing,
            notes=["Static direct calls only; register-indirect and computed calls are not seen.",
                   "The image is read, never loaded or run; first failure order is unverified."])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("image", type=Path)
    parser.add_argument("inventory", type=Path, help="pe_inventory.py JSON report")
    parser.add_argument("--image-name", help="inventory key for the image (default: file name)")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
        report = inspect(args.image, inventory, args.image_name or args.image.name)
    except (OSError, ValueError, KeyError, TypeError, pefile.PEFormatError) as exc:
        parser.error(str(exc))
    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    startup = [row for row in report["symbols"] if row["startup"]]
    print(f"{report['image']}: {len(report['symbols'])} symbols with direct sites, "
          f"{len(report['no_direct_sites'])} without, {len(startup)} reachable from startup")
    for row in startup:
        print(f"  {row['startup']:7} {row['module']}!{row['symbol']} "
              f"({len(row['records'])} record(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
