#!/usr/bin/env python3
"""Capture Linux x64 Node code after ThinLTO for a bounded, manual review.

Byte correlation proves only that captured instruction excerpts occur in the
linked library. It does not establish constant-time execution or audit the FFI.
Uses only Python's standard library, Cargo/rustc and GNU objdump.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
FUNCTIONS = {
    "post_quantum_platform::opaque_u8",
    "post_quantum_core::arithmetic::equal_mask",
    "post_quantum_core::ml_kem::PrivateKey::decapsulate",
    "post_quantum_core::ml_dsa::norm_exceeds",
    "post_quantum_core::symmetric::tag",
    "post_quantum_core::symmetric::open",
}

# GNU objdump on some GitHub runners does not demangle this LLVM-suffixed Rust
# symbol, even though the function remains a separate symbol in the object.
# Match its exact legacy mangling prefix rather than making the tag check optional.
TAG_MANGLED = re.compile(r"_ZN17post_quantum_core9symmetric3tag17h[0-9a-f]+E(?:\.llvm\.\d+)?")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def manifest():
    # Conservatively includes tests, but permits documentation edits in parallel.
    paths = [ROOT / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml")]
    paths += [p for p in (ROOT / "crates").rglob("*")
              if p.is_file() and (p.suffix == ".rs" or p.name == "Cargo.toml")]
    if (ROOT / ".cargo").is_dir():
        paths += [p for p in (ROOT / ".cargo").rglob("*") if p.is_file()]
    return [{"path": str(p.relative_to(ROOT)), "sha256": digest(p.read_bytes())}
            for p in sorted(set(paths))]


def run(command, report, directory, name):
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    log = directory / (name + ".log")
    log.write_text(result.stdout + result.stderr)
    report["commands"].append({"argv": command, "exitCode": result.returncode,
                               "log": str(log.relative_to(ROOT)),
                               "logSha256": digest(log.read_bytes())})
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}); see {log}")
    return result.stdout


def functions(assembly):
    for body in re.split(r"(?=^[0-9a-f]+ <)", assembly, flags=re.M):
        first = body.splitlines()[0] if body else ""
        match = re.fullmatch(r"[0-9a-f]+ <(.+)>:", first)
        if match:
            name = match[1]
            if TAG_MANGLED.fullmatch(name):
                name = "post_quantum_core::symmetric::tag"
            if name in FUNCTIONS:
                yield name, body


def correlate(body, binary):
    """Match relocation-free runs; linkers may rewrite relocation instructions.

    Exclude a generous instruction-sized neighborhood around each relocation.
    Keep four longest runs, retaining exact offsets/bytes/hashes for inspection.
    No meaning is inferred from instruction mnemonics or branch counts.
    """
    memory, excluded = {}, set()
    for line in body.splitlines():
        relocation = re.match(r"\s*([0-9a-f]+):\s+R_X86_64_", line)
        if relocation:
            offset = int(relocation[1], 16)
            excluded.update(range(max(0, offset - 15), offset + 16))
            continue
        instruction = re.match(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} ?)+)\s", line)
        if instruction:
            offset = int(instruction[1], 16)
            memory.update((offset + i, byte)
                          for i, byte in enumerate(bytes.fromhex(instruction[2])))
    runs, start, current = [], None, bytearray()
    for offset in range(max(memory, default=-1) + 2):
        if offset not in memory or offset in excluded:
            if len(current) >= 16:
                runs.append((start, bytes(current)))
            start, current = None, bytearray()
        else:
            if start is None:
                start = offset
            current.append(memory[offset])
    result = []
    for offset, data in sorted(runs, key=lambda entry: len(entry[1]), reverse=True)[:4]:
        positions, cursor = [], -1
        while True:
            cursor = binary.find(data, cursor + 1)
            if cursor < 0:
                break
            positions.append(cursor)
        result.append({"objectFunctionOffset": offset, "length": len(data),
                       "sha256": digest(data), "hex": data.hex(),
                       "linkedLibraryFileOffsets": positions})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="artifacts/validation/linked-codegen.json")
    args = parser.parse_args()
    output = (ROOT / args.output).resolve()
    output.relative_to(ROOT)  # Reports use repository-relative paths.
    directory = output.with_suffix("")
    directory.mkdir(parents=True, exist_ok=True)
    before = manifest()
    report = {"schemaVersion": 1, "target": "x86_64-unknown-linux-gnu",
              "startedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "scope": "Native objects after Node ThinLTO; selected functions and exact byte correlation to the linked library. Not a constant-time proof or a complete binary audit.",
              "sourceBefore": before, "commands": [], "objects": [], "functions": [],
              "captureAndCorrelationPassed": False}
    try:
        toolchain = run(["rustc", "-Vv"], report, directory, "rustc")
        report["toolchain"] = toolchain
        if "host: x86_64-unknown-linux-gnu" not in toolchain:
            raise RuntimeError("This bounded final-link capture requires a Linux GNU x64 host")
        run(["objdump", "--version"], report, directory, "objdump")
        with tempfile.TemporaryDirectory(prefix="pq-linked-codegen-") as scratch:
            command = ["cargo", "rustc", "-p", "post-quantum-node", "--release",
                       "--frozen", "--target-dir", scratch, "--", "-C", "save-temps=yes"]
            run(command, report, directory, "cargo")
            library = Path(scratch) / "release/libpost_quantum.so"
            binary = library.read_bytes()
            destination = directory / library.name
            shutil.copyfile(library, destination)
            report["linkedLibrary"] = {"path": str(destination.relative_to(ROOT)),
                                       "sha256": digest(binary), "bytes": len(binary)}
            dependencies = Path(scratch) / "release/deps"
            objects = sorted(dependencies.glob("post_quantum.post_quantum_*rcgu.o.rcgu.o"))
            if not objects:
                raise RuntimeError("No post-ThinLTO objects found; inspect rustc's changed output naming")
            seen = set()
            for index, obj in enumerate(objects):
                copied = directory / obj.name
                shutil.copyfile(obj, copied)
                assembly = run(["objdump", "-dr", "--demangle", str(obj)],
                               report, directory, f"object-{index}")
                disassembly = directory / (obj.name + ".asm")
                disassembly.write_text(assembly)
                report["objects"].append({"path": str(copied.relative_to(ROOT)),
                                           "sha256": digest(copied.read_bytes()),
                                           "disassembly": str(disassembly.relative_to(ROOT)),
                                           "disassemblySha256": digest(assembly.encode())})
                for function, body in functions(assembly):
                    seen.add(function)
                    matches = correlate(body, binary)
                    if not matches or not all(m["linkedLibraryFileOffsets"] for m in matches):
                        raise RuntimeError(f"Byte correlation changed for {function}; manual investigation required")
                    report["functions"].append({"name": function,
                                                "object": str(copied.relative_to(ROOT)),
                                                "disassemblySha256": digest(body.encode()),
                                                "correlatedExcerpts": matches})
            if seen != FUNCTIONS:
                raise RuntimeError(f"Selected function layout changed; missing: {sorted(FUNCTIONS - seen)}")
        report["sourceAfter"] = manifest()
        report["compilerInputsUnchanged"] = before == report["sourceAfter"]
        if not report["compilerInputsUnchanged"]:
            raise RuntimeError("Rust/Cargo inputs changed during final-link capture")
        report["captureAndCorrelationPassed"] = True
    except (OSError, RuntimeError, ValueError) as error:
        report["error"] = str(error)
    finally:
        report["finishedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(output.relative_to(ROOT)),
                      "captureAndCorrelationPassed": report["captureAndCorrelationPassed"],
                      "error": report.get("error")}))
    return 0 if report["captureAndCorrelationPassed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
