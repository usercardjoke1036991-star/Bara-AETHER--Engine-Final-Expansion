"""Puerta de totalidad del kernel: producción sin panic! ni unreachable!.

Complementa el grep de unwrap/expect del CI. Los ítems `#[cfg(test)]` pueden
usar panic! como aserción. Comentarios y cadenas no cuentan. El indexado `[]`
no entra en esta puerta: en este árbol es ruido, no una señal de aborto.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
NEEDLES = ("panic!", "unreachable!")


def scan(text: str) -> list[int]:
    """Líneas 1-based de producción que invocan panic! o unreachable!."""
    hits: list[int] = []
    i = 0
    n = len(text)
    line = 1
    depth = 0
    skip: list[int] = []
    pending = False
    block = False
    string: str | None = None
    raw_hashes = 0

    def at(pos: int, token: str) -> bool:
        return text.startswith(token, pos)

    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if block:
            if at(i, "*/"):
                block = False
                i += 2
            else:
                i += 1
            continue
        if string is not None:
            if string == "raw":
                if at(i, '"' + ("#" * raw_hashes)):
                    string = None
                    i += 1 + raw_hashes
                else:
                    i += 1
                continue
            if ch == "\\":
                i += 2
                continue
            if ch == string:
                string = None
            i += 1
            continue
        if at(i, "/*"):
            block = True
            i += 2
            continue
        if at(i, "//"):
            end = text.find("\n", i)
            i = n if end < 0 else end
            continue
        if ch == "r" and i + 1 < n and (text[i + 1] == "#" or text[i + 1] == '"'):
            j = i + 1
            hashes = 0
            while j < n and text[j] == "#":
                hashes += 1
                j += 1
            if j < n and text[j] == '"':
                string = "raw"
                raw_hashes = hashes
                i = j + 1
                continue
        if ch in {'"', "'"}:
            string = ch
            i += 1
            continue
        if at(i, "#[cfg(test)]"):
            pending = True
            i += len("#[cfg(test)]")
            continue
        if ch == ";" and pending:
            pending = False
            i += 1
            continue
        if ch == "{":
            depth += 1
            if pending:
                skip.append(depth)
                pending = False
            i += 1
            continue
        if ch == "}":
            if skip and skip[-1] == depth:
                skip.pop()
            depth = max(0, depth - 1)
            i += 1
            continue
        if not skip:
            for needle in NEEDLES:
                if at(i, needle):
                    hits.append(line)
                    break
        i += 1
    return hits


def main() -> int:
    failed = False
    for path in sorted(SRC.rglob("*.rs")):
        lines = scan(path.read_text(encoding="utf-8"))
        for line in lines:
            failed = True
            rel = path.relative_to(ROOT).as_posix()
            print(f"{rel}:{line}: panic!/unreachable! en producción", file=sys.stderr)
    if failed:
        print(
            "::error::apareció panic!() o unreachable!() fuera de #[cfg(test)]",
            file=sys.stderr,
        )
        return 1
    print("OK: src/ sin panic!() ni unreachable!() en producción.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
