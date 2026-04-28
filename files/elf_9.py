#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Анализ ELF: разбор структур (как в методичке lab9_разбор) и ответы на вопросы
лабораторной (Лабораторная_работа_9.md). Поддержка ELF32 и ELF64.

Отчёт сохраняется как Markdown (*.md): таблицы и блоки hex-дампа (стиль xxd)
удобно смотреть в предпросмотре MD.
"""
from __future__ import annotations

import os
import struct
import sys
from typing import Any, BinaryIO, List

# --- константы ELF ---

ET_NONE, ET_REL, ET_EXEC, ET_DYN, ET_CORE = 0, 1, 2, 3, 4
PT_NULL, PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE, PT_SHLIB, PT_PHDR, PT_TLS = range(8)
SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_HASH, SHT_DYNAMIC, SHT_NOBITS = (
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    8,
)

PF_X, PF_W, PF_R = 1, 2, 4

EM_386, EM_X86_64 = 0x3, 0x3E

PT_TYPE_NAMES = {
    0: "PT_NULL",
    1: "PT_LOAD",
    2: "PT_DYNAMIC",
    3: "PT_INTERP",
    4: "PT_NOTE",
    5: "PT_SHLIB",
    6: "PT_PHDR",
    7: "PT_TLS",
    0x60000000: "PT_LOOS",
    0x6FFFFFFF: "PT_HIOS",
    0x70000000: "PT_LOPROC",
    0x7FFFFFFF: "PT_HIPROC",
}

SHT_TYPE_NAMES = {
    0: "SHT_NULL",
    1: "SHT_PROGBITS",
    2: "SHT_SYMTAB",
    3: "SHT_STRTAB",
    4: "SHT_RELA",
    5: "SHT_HASH",
    6: "SHT_DYNAMIC",
    7: "SHT_NOTE",
    8: "SHT_NOBITS",
    9: "SHT_REL",
    10: "SHT_SHLIB",
    11: "SHT_DYNSYM",
}

EI_CLASS_32, EI_CLASS_64 = 1, 2


def _read_cstr(data: bytes, off: int) -> str:
    if off >= len(data):
        return ""
    end = data.find(b"\x00", off)
    if end < 0:
        end = len(data)
    return data[off:end].decode("utf-8", errors="replace")


def _ph_flags_str(p_flags: int) -> str:
    r = "R" if p_flags & PF_R else "-"
    w = "W" if p_flags & PF_W else "-"
    x = "X" if p_flags & PF_X else "-"
    return f"{r}{w}{x}"


def _ph_flags_bits(p_flags: int) -> str:
    parts = []
    if p_flags & PF_R:
        parts.append("PF_R (0x4) — чтение")
    if p_flags & PF_W:
        parts.append("PF_W (0x2) — запись")
    if p_flags & PF_X:
        parts.append("PF_X (0x1) — исполнение")
    if (p_flags & 0x0FFFFFFF) and not (p_flags & 7):
        parts.append(f"доп. биты: 0x{p_flags:08X}")
    if not parts:
        parts.append("ни один стандартный бит (0)")
    return "; ".join(parts)


def _sh_flags_str(f: int) -> str:
    parts = []
    if f & 0x1:
        parts.append("W")
    if f & 0x2:
        parts.append("A")
    if f & 0x4:
        parts.append("X")
    if f & 0x400:
        parts.append("T")
    return "".join(parts) if parts else "—"


def _hex_bytes_lower(data: bytes) -> str:
    """Hex с пробелами, нижний регистр (как в методичке: 7f 45 4c 46)."""
    return data.hex(" ").lower()


def _hex_bytes_lower_br(data: bytes, chunk: int = 8) -> str:
    """Длинные последовательности байт с переносами <br> (как в lab9_разбор)."""
    if not data:
        return ""
    chunks = [data[i : i + chunk].hex(" ").lower() for i in range(0, len(data), chunk)]
    return "<br>".join(chunks)


def _md_cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\r\n", "<br>").replace("\n", "<br>")


def format_hex_dump_xxd(blob: bytes, base_addr: int = 0, bytes_per_line: int = 16) -> str:
    """
    Текстовый hex-дамп в стиле xxd / hex-редактора: адрес строки, ровно ``bytes_per_line``
    байт на строку (пары ``hh hh``), справа столбец ASCII длиной ``bytes_per_line``.

    Недостающие байты до конца строки (конец файла на не кратном 16 смещении) показываются
    как ``--``, чтобы можно было визуально совместить строку с редактором с колонками 00..0f.
    """
    lines: list[str] = []
    n = len(blob)
    for line_start in range(0, n, bytes_per_line):
        addr = base_addr + line_start
        hex_parts: list[str] = []
        ascii_chars: list[str] = []
        for i in range(0, bytes_per_line, 2):
            lo = line_start + i
            hi = lo + 2
            seg = blob[lo:hi] if lo < n else b""
            if len(seg) == 2:
                hex_parts.append(seg.hex())
            elif len(seg) == 1:
                hex_parts.append(f"{seg[0]:02x} --")
            else:
                hex_parts.append("-- --")
            for j in range(lo, hi):
                if j < n:
                    b = blob[j]
                    ascii_chars.append(chr(b) if 32 <= b < 127 else ".")
                else:
                    ascii_chars.append(".")
        hex_str = " ".join(hex_parts)
        ascii_repr = "".join(ascii_chars)
        lines.append(f"{addr:08x}: {hex_str}  {ascii_repr}")
    return "\n".join(lines)


def md_code_block(lang: str, body: str) -> str:
    """Оформление fenced block для Markdown."""
    body = body.rstrip("\n")
    return f"```{lang}\n{body}\n```"


def log_md_code_block(log, lang: str, body: str) -> None:
    log(md_code_block(lang, body))


def _ph_flags_methodology_ru(p_flags: int) -> str:
    """Расшифровка p_flags словами, как в методичке (R / W / E)."""
    r = (p_flags & PF_R) != 0
    w = (p_flags & PF_W) != 0
    x = (p_flags & PF_X) != 0
    if r and not w and not x:
        return "R (чтение)"
    if r and x and not w:
        return "R + E (чтение + исполнение)"
    if r and w and not x:
        return "R + W (чтение + запись)"
    parts = []
    if r:
        parts.append("R (чтение)")
    if w:
        parts.append("W (запись)")
    if x:
        parts.append("E (исполнение)")
    return " + ".join(parts) if parts else f"0x{p_flags:X}"


def _hex_spaced(data: bytes) -> str:
    return data.hex(" ")


def phdr_methodology_lines_elf32(raw: bytes, off: int) -> tuple[list[str], list[str]]:
    """
    Строки разбора Elf32_Phdr в формате методички:
    - p_type 01 00 00 00 = 0x01 = PT_LOAD.
    Возвращает (маркированный список, отдельные абзацы после списка).
    """
    b = raw[off : off + 32]
    tail: list[str] = []
    if len(b) < 32:
        return (["- *(недостаточно байт для Elf32_Phdr)*"], tail)
    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack("<8I", b)
    lines = [
        f"- p_type {_hex_spaced(b[0:4])} = 0x{p_type:08X} = {pt_name(p_type)}.",
        f"- p_offset {_hex_spaced(b[4:8])} = 0x{p_offset:08X}.",
        f"- p_vaddr {_hex_spaced(b[8:12])} = 0x{p_vaddr:08X}.",
        f"- p_paddr {_hex_spaced(b[12:16])} = 0x{p_paddr:08X}.",
        f"- p_filesz {_hex_spaced(b[16:20])} = 0x{p_filesz:X} = {p_filesz} байт.",
        f"- p_memsz {_hex_spaced(b[20:24])} = 0x{p_memsz:X} = {p_memsz} байт.",
        f"- p_flags {_hex_spaced(b[24:28])} = 0x{p_flags:08X} = {_ph_flags_methodology_ru(p_flags)}.",
        f"- p_align {_hex_spaced(b[28:32])} = 0x{p_align:X}.",
    ]
    tail.extend(_phdr_methodology_tail_paragraphs(p_type, p_flags, p_filesz))
    return (lines, tail)


def phdr_methodology_lines_elf64(raw: bytes, off: int) -> tuple[list[str], list[str]]:
    """Разбор Elf64_Phdr — порядок полей как в методичке (p_flags сразу после p_type)."""
    b = raw[off : off + 56]
    tail: list[str] = []
    if len(b) < 56:
        return (["- *(недостаточно байт для Elf64_Phdr)*"], tail)
    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack("<IIQQQQQQ", b)
    lines = [
        f"- p_type {_hex_spaced(b[0:4])} = 0x{p_type:08X} = {pt_name(p_type)}.",
        f"- p_flags {_hex_spaced(b[4:8])} = 0x{p_flags:08X} = {_ph_flags_methodology_ru(p_flags)}.",
        f"- p_offset  {_hex_spaced(b[8:16])} = 0x{p_offset:X}.",
        f"- p_vaddr  {_hex_spaced(b[16:24])} = 0x{p_vaddr:X}.",
        f"- p_paddr  {_hex_spaced(b[24:32])} = 0x{p_paddr:X}.",
        f"- p_filesz {_hex_spaced(b[32:40])} = 0x{p_filesz:X} = {p_filesz} байт.",
        f"- p_memsz {_hex_spaced(b[40:48])} = 0x{p_memsz:X} = {p_memsz} байт.",
        f"- p_align {_hex_spaced(b[48:56])} = 0x{p_align:X}.",
    ]
    tail.extend(_phdr_methodology_tail_paragraphs(p_type, p_flags, p_filesz))
    return (lines, tail)


def _phdr_methodology_tail_paragraphs(p_type: int, p_flags: int, p_filesz: int) -> list[str]:
    """Короткие поясняющие абзацы после списка полей (как в PDF)."""
    out: list[str] = []
    if p_type == PT_PHDR:
        out.append(
            f"Описывает саму таблицу Program Headers ({p_filesz} байт в файле)."
        )
    elif p_type == PT_INTERP:
        out.append("Содержит путь к программе-интерпретатору.")
    elif p_type == PT_LOAD:
        rwx = _ph_flags_str(p_flags)
        if "X" in rwx and "W" not in rwx:
            out.append("Исполняемый код программы.")
        elif "X" not in rwx and "W" not in rwx:
            out.append("Данные только для чтения.")
        elif "W" in rwx:
            out.append("Сегмент данных (чтение и запись).")
    return out


def phdr_layout_table_rows(ei_class: int) -> list[tuple[str, str, str, str]]:
    """Таблица «Смещение | Поле | Размер | Описание» для Elf32_Phdr или Elf64_Phdr."""
    if ei_class == EI_CLASS_64:
        return [
            ("0x00", "p_type", "4", "Тип сегмента"),
            ("0x04", "p_flags", "4", "Флаги доступа"),
            ("0x08", "p_offset", "8", "Смещение в<br>файле"),
            ("0x10", "p_vaddr", "8", "Виртуальный<br>адрес"),
            ("0x18", "p_paddr", "8", "Физический<br>адрес"),
            ("0x20", "p_filesz", "8", "Размер в файле"),
            ("0x28", "p_memsz", "8", "Размер в памяти"),
            ("0x30", "p_align", "8", "Выравнивание"),
        ]
    return [
        ("0x00", "p_type", "4", "Тип сегмента"),
        ("0x04", "p_offset", "4", "Смещение в файле"),
        ("0x08", "p_vaddr", "4", "Виртуальный адрес"),
        ("0x0C", "p_paddr", "4", "Физический адрес"),
        ("0x10", "p_filesz", "4", "Размер в файле"),
        ("0x14", "p_memsz", "4", "Размер в памяти"),
        ("0x18", "p_flags", "4", "Флаги доступа"),
        ("0x1C", "p_align", "4", "Выравнивание"),
    ]


def shdr_field_lines_elf32(raw: bytes, off: int) -> list[str]:
    b = raw[off : off + 40]
    if len(b) < 40:
        return ["- *(недостаточно байт для Elf32_Shdr)*"]
    u = struct.unpack("<IIIIIIIIII", b)

    def hx(i: int, n: int) -> str:
        return b[i : i + n].hex(" ")

    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = u
    return [
        f"- `sh_name` — `{hx(0, 4)}` → **0x{sh_name:08X}** (смещение имени в `.shstrtab`).",
        f"- `sh_type` — `{hx(4, 4)}` → **0x{sh_type:08X}** ({SHT_TYPE_NAMES.get(sh_type, '?')}).",
        f"- `sh_flags` — `{hx(8, 4)}` → **0x{sh_flags:08X}**.",
        f"- `sh_addr` — `{hx(12, 4)}` → **0x{sh_addr:08X}**.",
        f"- `sh_offset` — `{hx(16, 4)}` → **0x{sh_offset:08X}**.",
        f"- `sh_size` — `{hx(20, 4)}` → **0x{sh_size:08X}** ({sh_size} байт).",
        f"- `sh_link` — `{hx(24, 4)}` → **0x{sh_link:08X}**.",
        f"- `sh_info` — `{hx(28, 4)}` → **0x{sh_info:08X}**.",
        f"- `sh_addralign` — `{hx(32, 4)}` → **0x{sh_addralign:08X}**.",
        f"- `sh_entsize` — `{hx(36, 4)}` → **0x{sh_entsize:08X}**.",
    ]


def shdr_field_lines_elf64(raw: bytes, off: int) -> list[str]:
    b = raw[off : off + 64]
    if len(b) < 64:
        return ["- *(недостаточно байт для Elf64_Shdr)*"]
    sh_name, sh_type = struct.unpack_from("<II", b, 0)
    sh_flags = struct.unpack_from("<Q", b, 8)[0]
    sh_addr = struct.unpack_from("<Q", b, 16)[0]
    sh_offset = struct.unpack_from("<Q", b, 24)[0]
    sh_size = struct.unpack_from("<Q", b, 32)[0]
    sh_link, sh_info = struct.unpack_from("<II", b, 40)
    sh_addralign = struct.unpack_from("<Q", b, 48)[0]
    sh_entsize = struct.unpack_from("<Q", b, 56)[0]

    def hx(i: int, n: int) -> str:
        return b[i : i + n].hex(" ")

    return [
        f"- `sh_name` — `{hx(0, 4)}` → **0x{sh_name:08X}**.",
        f"- `sh_type` — `{hx(4, 4)}` → **0x{sh_type:08X}** ({SHT_TYPE_NAMES.get(sh_type, '?')}).",
        f"- `sh_flags` — `{hx(8, 8)}` → **0x{sh_flags:X}**.",
        f"- `sh_addr` — `{hx(16, 8)}` → **0x{sh_addr:X}**.",
        f"- `sh_offset` — `{hx(24, 8)}` → **0x{sh_offset:X}**.",
        f"- `sh_size` — `{hx(32, 8)}` → **0x{sh_size:X}** ({sh_size} байт).",
        f"- `sh_link` — `{hx(40, 4)}` → **0x{sh_link:08X}**.",
        f"- `sh_info` — `{hx(44, 4)}` → **0x{sh_info:08X}**.",
        f"- `sh_addralign` — `{hx(48, 8)}` → **0x{sh_addralign:X}**.",
        f"- `sh_entsize` — `{hx(56, 8)}` → **0x{sh_entsize:X}**.",
    ]


def slice_for_dump(
    raw: bytes,
    start: int,
    length: int,
    *,
    align16: bool = True,
) -> tuple[bytes, int, int]:
    """
    Возвращает ``(data, addr_start, len(data))`` с учётом границ файла.

    При ``align16=True`` (по умолчанию) начало окна опускается к адресу, кратному 16,
    а конец поднимается к следующей границе 16 байт (но не за пределы файла). Так первый
    адрес строки дампа совпадает с типичным hex-редактором (например ``...80``, ``...90``).
    """
    if start < 0:
        start = 0
    end = min(len(raw), start + length)
    if start >= len(raw):
        return b"", start, 0
    if not align16:
        chunk = raw[start:end]
        return chunk, start, len(chunk)
    a0 = (start // 16) * 16
    a1 = ((end + 15) // 16) * 16
    a1 = min(a1, len(raw))
    chunk = raw[a0:a1]
    return chunk, a0, len(chunk)


def pt_short(pt: int) -> str:
    """Краткое имя типа для итоговой таблицы PH (как в методичке: PHDR, LOAD, …)."""
    return {
        PT_NULL: "NULL",
        PT_LOAD: "LOAD",
        PT_DYNAMIC: "DYNAMIC",
        PT_INTERP: "INTERP",
        PT_NOTE: "NOTE",
        PT_SHLIB: "SHLIB",
        PT_PHDR: "PHDR",
        PT_TLS: "TLS",
    }.get(pt, f"0x{pt:X}")


def sht_short(st: int) -> str:
    return SHT_TYPE_NAMES.get(st, str(st)).replace("SHT_", "")


def ph_summary_naznachenie(pt: int, p_flags: int) -> str:
    """Колонка «Назначение» с переносами как в PDF."""
    if pt == PT_PHDR:
        return "Таблица Program<br>Headers"
    if pt == PT_INTERP:
        return "Интерпретатор"
    if pt == PT_LOAD:
        rwx = _ph_flags_str(p_flags)
        if "X" in rwx and "W" not in rwx:
            return "Исполняемый код"
        if "X" not in rwx and "W" not in rwx:
            return "Данные только<br>для чтения"
        if "W" in rwx:
            return "Сегмент данных<br>(чтение и запись)"
        return "Сегмент LOAD"
    if pt == PT_DYNAMIC:
        return "Динамическая<br>линковка"
    return pt_name(pt)


def ph_summary_flags_cell(pf: int) -> str:
    """Флаги как в методичке: «0x04 (R)», «0x05 (R+E)»."""
    s = _ph_flags_str(pf)
    lab = {"R-X": "R+E", "RW-": "R+W", "R--": "R", "---": "—"}.get(s, s.replace("X", "E"))
    return f"0x{pf & 0xFF:02X} ({lab})"


def shdr_layout_table_rows(ei_class: int) -> list[tuple[str, str, str, str]]:
    """Таблица структуры Section Header (lab9_разбор §3)."""
    if ei_class == EI_CLASS_64:
        return [
            ("0x00", "sh_name", "4", "Смещение в .shstrtab"),
            ("0x04", "sh_type", "4", "Тип секции"),
            ("0x08", "sh_flags", "8", "Флаги доступа"),
            ("0x10", "sh_addr", "8", "Виртуальный адрес"),
            ("0x18", "sh_offset", "8", "Смещение в файле"),
            ("0x20", "sh_size", "8", "Размер секции"),
            ("0x28", "sh_link", "4", "Ссылка на другую<br>секцию"),
            ("0x2C", "sh_info", "4", "Доп. информация"),
            ("0x30", "sh_addralign", "8", "Выравнивание"),
            ("0x38", "sh_entsize", "8", "Размер записи"),
        ]
    return [
        ("0x00", "sh_name", "4", "Смещение в .shstrtab"),
        ("0x04", "sh_type", "4", "Тип секции"),
        ("0x08", "sh_flags", "4", "Флаги доступа"),
        ("0x0C", "sh_addr", "4", "Виртуальный адрес"),
        ("0x10", "sh_offset", "4", "Смещение в файле"),
        ("0x14", "sh_size", "4", "Размер секции"),
        ("0x18", "sh_link", "4", "Ссылка на другую секцию"),
        ("0x1C", "sh_info", "4", "Доп. информация"),
        ("0x20", "sh_addralign", "4", "Выравнивание"),
        ("0x24", "sh_entsize", "4", "Размер записи"),
    ]


def shdr_methodology_shstrtab_lines(raw: bytes, off: int, ei_class: int) -> list[str]:
    """Разбор заголовка .shstrtab — только ключевые поля (как в PDF)."""
    if ei_class == EI_CLASS_64:
        b = raw[off : off + 64]
        if len(b) < 64:
            return []
        sh_name = struct.unpack_from("<I", b, 0)[0]
        sh_type = struct.unpack_from("<I", b, 4)[0]
        sh_offset = struct.unpack_from("<Q", b, 24)[0]
        sh_size = struct.unpack_from("<Q", b, 32)[0]
        return [
            f"- sh_name {_hex_spaced(b[0:4])} = 0x{sh_name:08X} (имя в начале .shstrtab).",
            f"- sh_type {_hex_spaced(b[4:8])} = 0x{sh_type:08X} ({sht_short(sh_type)}).",
            f"- sh_offset {_hex_spaced(b[24:32])} = 0x{sh_offset:X}.",
            f"- sh_size {_hex_spaced(b[32:40])} = 0x{sh_size:X} = {sh_size} байта.",
        ]
    b = raw[off : off + 40]
    if len(b) < 40:
        return []
    sh_name, sh_type, _, _, sh_offset, sh_size = struct.unpack("<IIIIII", b[:24])
    return [
        f"- sh_name {_hex_spaced(b[0:4])} = 0x{sh_name:08X} (имя в начале .shstrtab).",
        f"- sh_type {_hex_spaced(b[4:8])} = 0x{sh_type:08X} ({sht_short(sh_type)}).",
        f"- sh_offset {_hex_spaced(b[16:20])} = 0x{sh_offset:08X}.",
        f"- sh_size {_hex_spaced(b[20:24])} = 0x{sh_size:08X} = {sh_size} байта.",
    ]


def shdr_methodology_text_lines(raw: bytes, off: int, ei_class: int) -> list[str]:
    """Разбор заголовка .text «Разбираем заголовок.» — как в методичке."""
    if ei_class == EI_CLASS_64:
        b = raw[off : off + 64]
        if len(b) < 64:
            return []
        sh_name = struct.unpack_from("<I", b, 0)[0]
        sh_type = struct.unpack_from("<I", b, 4)[0]
        sh_flags = struct.unpack_from("<Q", b, 8)[0]
        sh_offset = struct.unpack_from("<Q", b, 24)[0]
        sh_size = struct.unpack_from("<Q", b, 32)[0]
        sh_addralign = struct.unpack_from("<Q", b, 48)[0]
        return [
            f"- sh_name {_hex_spaced(b[0:4])} = 0x{sh_name:X} (смещение в .shstrtab).",
            f"- sh_type {_hex_spaced(b[4:8])} = 0x{sh_type:08X} = {sht_short(sh_type)}.",
            f"- sh_flags {_hex_spaced(b[8:16])} = 0x{sh_flags:016X}.",
            f"- sh_offset {_hex_spaced(b[24:32])} = 0x{sh_offset:X}.",
            f"- sh_size {_hex_spaced(b[32:40])} = 0x{sh_size:X} = {sh_size} байт.",
            f"- sh_addralign {_hex_spaced(b[48:56])} = 0x{sh_addralign:X} = {sh_addralign} байт.",
        ]
    b = raw[off : off + 40]
    if len(b) < 40:
        return []
    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, _, _, sh_addralign, _ = struct.unpack(
        "<IIIIIIIIII", b
    )
    return [
        f"- sh_name {_hex_spaced(b[0:4])} = 0x{sh_name:X} (смещение в .shstrtab).",
        f"- sh_type {_hex_spaced(b[4:8])} = 0x{sh_type:08X} = {sht_short(sh_type)}.",
        f"- sh_flags {_hex_spaced(b[8:12])} = 0x{sh_flags:08X}.",
        f"- sh_offset {_hex_spaced(b[16:20])} = 0x{sh_offset:08X}.",
        f"- sh_size {_hex_spaced(b[20:24])} = 0x{sh_size:08X} = {sh_size} байт.",
        f"- sh_addralign {_hex_spaced(b[32:36])} = 0x{sh_addralign:08X}.",
    ]


def build_key_sections_table(
    shdrs: List[dict],
    sec_name_fn,
) -> list[tuple[str, str, str, str, str, str, str]]:
    """Таблица ключевых секций: Секция | Индекс | sh_name | sh_offset | sh_size | Тип | Флаги."""
    want = (".text", ".data", ".rodata", ".bss", ".shstrtab")
    rows: list[tuple[str, str, str, str, str, str, str]] = []
    for name in want:
        sh = next((s for s in shdrs if sec_name_fn(s) == name), None)
        if sh is None:
            continue
        fl = _sh_flags_str(int(sh["sh_flags"]))
        st = sht_short(int(sh["sh_type"]))
        off_cell = "—" if int(sh["sh_type"]) == SHT_NOBITS else f"0x{sh['sh_offset']:X}"
        rows.append(
            (
                f"**{name}**",
                str(sh["index"]),
                f"0x{sh['sh_name']:X}",
                off_cell,
                f"0x{sh['sh_size']:X}",
                st,
                fl,
            )
        )
    return rows


def _decode_ei_class(b: int) -> str:
    if b == 1:
        return "ELF32 (32-битная архитектура)"
    if b == 2:
        return "ELF64 (64-битная архитектура)"
    return f"неизвестный класс ({b})"


def _decode_ei_data(b: int) -> str:
    if b == 1:
        return "Little-Endian порядок байт"
    if b == 2:
        return "Big-Endian порядок байт"
    return f"EI_DATA={b}"


def _decode_e_type(t: int) -> str:
    return {
        ET_NONE: "ET_NONE (нет типа)",
        ET_REL: "ET_REL (перемещаемый объект)",
        ET_EXEC: "ET_EXEC (исполняемый файл)",
        ET_DYN: "ET_DYN (разделяемый объект / PIE)",
        ET_CORE: "ET_CORE (core dump)",
    }.get(t, f"0x{t:04X}")


def _decode_e_machine(m: int) -> str:
    if m == EM_386:
        return "EM_386 (Intel 80386)"
    if m == EM_X86_64:
        return "EM_X86_64 (x86-64 архитектура)"
    return f"архитектура 0x{m:04X}"


def log_markdown_table(
    log,
    headers: tuple[str, ...],
    rows: list[tuple[str, ...]],
    *,
    bold_first_col: bool = True,
    pad_columns: bool = True,
) -> None:
    """
    Пишет markdown-таблицу в отчёт (формат как в lab9_разбор.md).

    При pad_columns=True подбирает ширину столбцов по самому длинному содержимому
    и дополняет ячейки пробелами слева по содержимому (ljust). В редакторе с
    моноширинным шрифтом столбцы визуально выравниваются; при просмотре с рендером
    Markdown таблица остаётся обычной HTML-таблицей (лишние пробелы в ячейках
    обычно не мешают вёрстке).
    """
    ncols = len(headers)
    header_cells = [_md_cell(str(h)) for h in headers]

    row_cells_list: list[list[str]] = []
    for row in rows:
        cells: list[str] = []
        for i, c in enumerate(row):
            t = _md_cell(str(c))
            if bold_first_col and i == 0 and not t.startswith("**"):
                t = f"**{t}**"
            cells.append(t)
        while len(cells) < ncols:
            cells.append("")
        row_cells_list.append(cells[:ncols])

    widths = [0] * ncols
    if pad_columns and ncols:
        for i in range(ncols):
            w = len(header_cells[i])
            for rc in row_cells_list:
                w = max(w, len(rc[i]))
            widths[i] = w
        header_cells = [header_cells[i].ljust(widths[i]) for i in range(ncols)]
        row_cells_list = [
            [rc[i].ljust(widths[i]) for i in range(ncols)] for rc in row_cells_list
        ]

    hs = "| " + " | ".join(header_cells) + " |"
    if pad_columns and ncols:
        sep_parts = ["-" * max(3, widths[i]) for i in range(ncols)]
        sep = "| " + " | ".join(sep_parts) + " |"
    else:
        sep = "| " + " | ".join(["---"] * ncols) + " |"

    log(hs)
    log(sep)
    for cells in row_cells_list:
        log("| " + " | ".join(cells) + " |")


def build_elf_header_table_rows(raw: bytes, ei_class: int, ehdr: dict[str, Any]) -> list[tuple[str, str, str, str, str, str]]:
    """
    Строки таблицы: Смещение, Поле, Размер, Байты, Значение, Расшифровка.
    ELF32: заголовок 52 байта; ELF64: 64 байта.
    """
    rows: list[tuple[str, str, str, str, str, str]] = []
    ident = raw[0:16]

    def add(off: int, name: str, size: int, b: bytes, val: str, desc: str) -> None:
        rows.append(
            (
                f"0x{off:02X}",
                name,
                str(size),
                _hex_bytes_lower_br(b) if len(b) > 8 else _hex_bytes_lower(b),
                val if val != "" else "—",
                desc,
            )
        )

    add(0x00, "e_ident[EI_MAG0–3]", 4, ident[0:4], "—", 'Magic number «\\x7fELF»')
    add(0x04, "e_ident[EI_CLASS]", 1, ident[4:5], str(ident[4]), _decode_ei_class(ident[4]))
    add(0x05, "e_ident[EI_DATA]", 1, ident[5:6], str(ident[5]), _decode_ei_data(ident[5]))
    add(0x06, "e_ident[EI_VERSION]", 1, ident[6:7], str(ident[6]), "Версия формата ELF (обычно 1)")
    add(0x07, "e_ident[EI_OSABI]", 1, ident[7:8], str(ident[7]), "ABI: System V (0)" if ident[7] == 0 else f"OSABI={ident[7]}")
    add(0x08, "e_ident[EI_ABIVERSION]", 1, ident[8:9], str(ident[8]), "Версия ABI")
    add(0x09, "e_ident[EI_PAD]", 7, ident[9:16], "—", "Выравнивание / зарезервировано")

    et = ehdr["e_type"]
    em = ehdr["e_machine"]
    ev = ehdr["e_version"]

    if ei_class == EI_CLASS_32:
        add(0x10, "e_type", 2, raw[0x10:0x12], f"0x{et:04X}", _decode_e_type(et))
        add(0x12, "e_machine", 2, raw[0x12:0x14], f"0x{em:04X}", _decode_e_machine(em))
        add(0x14, "e_version", 4, raw[0x14:0x18], str(ev), "Версия объекта")
        e_entry = struct.unpack_from("<I", raw, 0x18)[0]
        add(0x18, "e_entry", 4, raw[0x18:0x1C], f"0x{e_entry:08X}", "Точка входа программы (VA)")
        e_phoff = struct.unpack_from("<I", raw, 0x1C)[0]
        add(0x1C, "e_phoff", 4, raw[0x1C:0x20], f"0x{e_phoff:08X}", "Смещение Program Headers в файле")
        e_shoff = struct.unpack_from("<I", raw, 0x20)[0]
        add(0x20, "e_shoff", 4, raw[0x20:0x24], f"0x{e_shoff:08X}", "Смещение Section Headers в файле")
        e_flags = struct.unpack_from("<I", raw, 0x24)[0]
        add(0x24, "e_flags", 4, raw[0x24:0x28], f"0x{e_flags:08X}", "Флаги архитектуры (часто 0)")
        e_ehsize, e_phentsize, e_phnum = struct.unpack_from("<HHH", raw, 0x28)
        add(0x28, "e_ehsize", 2, raw[0x28:0x2A], f"0x{e_ehsize:04X}", f"Размер ELF-заголовка = {e_ehsize} байт")
        add(0x2A, "e_phentsize", 2, raw[0x2A:0x2C], f"0x{e_phentsize:04X}", f"Размер одной записи Program Header = {e_phentsize} байт")
        add(0x2C, "e_phnum", 2, raw[0x2C:0x2E], f"{e_phnum}", f"Количество Program Headers = {e_phnum}")
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", raw, 0x2E)
        add(0x2E, "e_shentsize", 2, raw[0x2E:0x30], f"0x{e_shentsize:04X}", f"Размер Section Header = {e_shentsize} байт")
        add(0x30, "e_shnum", 2, raw[0x30:0x32], f"{e_shnum}", f"Количество Section Headers = {e_shnum}")
        add(0x32, "e_shstrndx", 2, raw[0x32:0x34], f"{e_shstrndx}", f"Индекс секции имён (.shstrtab) = {e_shstrndx}")
    else:
        add(0x10, "e_type", 2, raw[0x10:0x12], f"0x{et:04X}", _decode_e_type(et))
        add(0x12, "e_machine", 2, raw[0x12:0x14], f"0x{em:04X}", _decode_e_machine(em))
        add(0x14, "e_version", 4, raw[0x14:0x18], str(ev), "Версия объекта")
        e_entry = struct.unpack_from("<Q", raw, 0x18)[0]
        add(0x18, "e_entry", 8, raw[0x18:0x20], f"0x{e_entry:016X}", "Точка входа программы (VA)")
        e_phoff = struct.unpack_from("<Q", raw, 0x20)[0]
        add(0x20, "e_phoff", 8, raw[0x20:0x28], f"0x{e_phoff:016X}", "Смещение Program Headers в файле")
        e_shoff = struct.unpack_from("<Q", raw, 0x28)[0]
        add(0x28, "e_shoff", 8, raw[0x28:0x30], f"0x{e_shoff:016X}", "Смещение Section Headers в файле")
        e_flags = struct.unpack_from("<I", raw, 0x30)[0]
        add(0x30, "e_flags", 4, raw[0x30:0x34], f"0x{e_flags:08X}", "Флаги архитектуры (часто 0)")
        e_ehsize, e_phentsize, e_phnum = struct.unpack_from("<HHH", raw, 0x34)
        add(0x34, "e_ehsize", 2, raw[0x34:0x36], f"0x{e_ehsize:04X}", f"Размер ELF-заголовка = {e_ehsize} байт")
        add(0x36, "e_phentsize", 2, raw[0x36:0x38], f"0x{e_phentsize:04X}", f"Размер одной записи Program Header = {e_phentsize} байт")
        add(0x38, "e_phnum", 2, raw[0x38:0x3A], f"{e_phnum}", f"Количество Program Headers = {e_phnum}")
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", raw, 0x3A)
        add(0x3A, "e_shentsize", 2, raw[0x3A:0x3C], f"0x{e_shentsize:04X}", f"Размер Section Header = {e_shentsize} байт")
        add(0x3C, "e_shnum", 2, raw[0x3C:0x3E], f"{e_shnum}", f"Количество Section Headers = {e_shnum}")
        add(0x3E, "e_shstrndx", 2, raw[0x3E:0x40], f"{e_shstrndx}", f"Индекс секции имён (.shstrtab) = {e_shstrndx}")

    return rows


def parse_elf32_ehdr(f: BinaryIO) -> dict[str, Any]:
    f.seek(0)
    ident = f.read(16)
    if len(ident) < 16:
        raise ValueError("Файл слишком короткий для ELF")
    e_type, e_machine, e_version = struct.unpack("<HHI", f.read(8))
    e_entry, e_phoff, e_shoff = struct.unpack("<III", f.read(12))
    e_flags = struct.unpack("<I", f.read(4))[0]
    e_ehsize, e_phentsize, e_phnum = struct.unpack("<HHH", f.read(6))
    e_shentsize, e_shnum, e_shstrndx = struct.unpack("<HHH", f.read(6))
    return {
        "class": EI_CLASS_32,
        "ident": ident,
        "e_type": e_type,
        "e_machine": e_machine,
        "e_version": e_version,
        "e_entry": e_entry,
        "e_phoff": e_phoff,
        "e_shoff": e_shoff,
        "e_flags": e_flags,
        "e_ehsize": e_ehsize,
        "e_phentsize": e_phentsize,
        "e_phnum": e_phnum,
        "e_shentsize": e_shentsize,
        "e_shnum": e_shnum,
        "e_shstrndx": e_shstrndx,
    }


def parse_elf64_ehdr(f: BinaryIO) -> dict[str, Any]:
    f.seek(0)
    ident = f.read(16)
    e_type, e_machine, e_version = struct.unpack("<HHI", f.read(8))
    e_entry = struct.unpack("<Q", f.read(8))[0]
    e_phoff = struct.unpack("<Q", f.read(8))[0]
    e_shoff = struct.unpack("<Q", f.read(8))[0]
    e_flags = struct.unpack("<I", f.read(4))[0]
    e_ehsize, e_phentsize, e_phnum = struct.unpack("<HHH", f.read(6))
    e_shentsize, e_shnum, e_shstrndx = struct.unpack("<HHH", f.read(6))
    return {
        "class": EI_CLASS_64,
        "ident": ident,
        "e_type": e_type,
        "e_machine": e_machine,
        "e_version": e_version,
        "e_entry": e_entry,
        "e_phoff": e_phoff,
        "e_shoff": e_shoff,
        "e_flags": e_flags,
        "e_ehsize": e_ehsize,
        "e_phentsize": e_phentsize,
        "e_phnum": e_phnum,
        "e_shentsize": e_shentsize,
        "e_shnum": e_shnum,
        "e_shstrndx": e_shstrndx,
    }


def read_elf32_phdrs(raw: bytes, e_phoff: int, e_phnum: int, entsize: int) -> List[dict]:
    out = []
    for i in range(e_phnum):
        o = e_phoff + i * entsize
        chunk = raw[o : o + 32]
        if len(chunk) < 32:
            break
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack(
            "<8I", chunk
        )
        out.append(
            {
                "index": i,
                "file_off": o,
                "p_type": p_type,
                "p_offset": p_offset,
                "p_vaddr": p_vaddr,
                "p_paddr": p_paddr,
                "p_filesz": p_filesz,
                "p_memsz": p_memsz,
                "p_flags": p_flags,
                "p_align": p_align,
                "raw32": chunk,
            }
        )
    return out


def read_elf64_phdrs(raw: bytes, e_phoff: int, e_phnum: int, entsize: int) -> List[dict]:
    out = []
    for i in range(e_phnum):
        o = int(e_phoff) + i * entsize
        chunk = raw[o : o + 56]
        if len(chunk) < 56:
            break
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(
            "<IIQQQQQQ", chunk
        )
        out.append(
            {
                "index": i,
                "file_off": o,
                "p_type": p_type,
                "p_offset": p_offset,
                "p_vaddr": p_vaddr,
                "p_paddr": p_paddr,
                "p_filesz": p_filesz,
                "p_memsz": p_memsz,
                "p_flags": p_flags,
                "p_align": p_align,
                "raw64": chunk,
            }
        )
    return out


def read_elf32_shdrs(raw: bytes, e_shoff: int, e_shnum: int, entsize: int) -> List[dict]:
    out = []
    for i in range(e_shnum):
        o = e_shoff + i * entsize
        fields = struct.unpack("<IIIIIIIIII", raw[o : o + 40])
        out.append(
            {
                "index": i,
                "file_off": o,
                "sh_name": fields[0],
                "sh_type": fields[1],
                "sh_flags": fields[2],
                "sh_addr": fields[3],
                "sh_offset": fields[4],
                "sh_size": fields[5],
                "sh_link": fields[6],
                "sh_info": fields[7],
                "sh_addralign": fields[8],
                "sh_entsize": fields[9],
            }
        )
    return out


def read_elf64_shdrs(raw: bytes, e_shoff: int, e_shnum: int, entsize: int) -> List[dict]:
    out = []
    for i in range(e_shnum):
        o = int(e_shoff) + i * entsize
        rec = raw[o : o + 64]
        sh_name, sh_type = struct.unpack_from("<II", rec, 0)
        sh_flags = struct.unpack_from("<Q", rec, 8)[0]
        sh_addr = struct.unpack_from("<Q", rec, 16)[0]
        sh_offset = struct.unpack_from("<Q", rec, 24)[0]
        sh_size = struct.unpack_from("<Q", rec, 32)[0]
        sh_link, sh_info = struct.unpack_from("<II", rec, 40)
        sh_addralign = struct.unpack_from("<Q", rec, 48)[0]
        sh_entsize = struct.unpack_from("<Q", rec, 56)[0]
        out.append(
            {
                "index": i,
                "file_off": o,
                "sh_name": sh_name,
                "sh_type": sh_type,
                "sh_flags": sh_flags,
                "sh_addr": sh_addr,
                "sh_offset": sh_offset,
                "sh_size": sh_size,
                "sh_link": sh_link,
                "sh_info": sh_info,
                "sh_addralign": sh_addralign,
                "sh_entsize": sh_entsize,
            }
        )
    return out


def pt_name(t: int) -> str:
    return PT_TYPE_NAMES.get(t, f"0x{t:X} (неизвестный/специфичный)")


def analyze_elf(file_path: str) -> None:
    if not os.path.exists(file_path):
        print(f"Файл {file_path} не найден.")
        return

    report_path = f"{os.path.splitext(file_path)[0]}_report.md"
    raw = open(file_path, "rb").read()

    def log(text: str = "") -> None:
        out.write(text + "\n")

    def log_sep(char: str = "=", length: int = 110) -> None:
        log(char * length)

    ei_class = raw[4] if len(raw) > 4 else 0
    if raw[:4] != b"\x7fELF":
        print(f"Не похоже на ELF: {file_path}")
        return

    with open(report_path, "w", encoding="utf-8") as out:
        log_sep("=")
        log(f"{'ЛАБОРАТОРНАЯ РАБОТА №9 — АНАЛИЗ ELF':^110}")
        log(f"{('Файл: ' + os.path.basename(file_path)):^110}")
        log_sep("=")
        log()

        # --- заголовок ---
        bio = open(file_path, "rb")
        if ei_class == EI_CLASS_64:
            ehdr = parse_elf64_ehdr(bio)
            phdrs = read_elf64_phdrs(raw, ehdr["e_phoff"], ehdr["e_phnum"], ehdr["e_phentsize"])
            shdrs = read_elf64_shdrs(raw, ehdr["e_shoff"], ehdr["e_shnum"], ehdr["e_shentsize"])
            elf_fmt = "ELF64"
            phdr_struct = "Elf64_Phdr (56 байт)"
        else:
            ehdr = parse_elf32_ehdr(bio)
            phdrs = read_elf32_phdrs(raw, ehdr["e_phoff"], ehdr["e_phnum"], ehdr["e_phentsize"])
            shdrs = read_elf32_shdrs(raw, ehdr["e_shoff"], ehdr["e_shnum"], ehdr["e_shentsize"])
            elf_fmt = "ELF32"
            phdr_struct = "Elf32_Phdr (32 байта; порядок полей как в glibc/ABI)"
        bio.close()

        shstrndx = ehdr["e_shstrndx"]
        shstr_hdr = shdrs[shstrndx] if shstrndx < len(shdrs) else None
        shstrtab = b""
        if shstr_hdr is not None:
            so, ss = shstr_hdr["sh_offset"], shstr_hdr["sh_size"]
            shstrtab = raw[int(so) : int(so) + int(ss)]

        def sec_name(sh: dict) -> str:
            return _read_cstr(shstrtab, int(sh["sh_name"]))

        log("ЧАСТЬ 1. ОБЗОР И РАЗБОР СТРУКТУР (по шагам методички lab9_разбор)")
        log_sep("-")
        log()
        log(f"Файл анализа — `{os.path.basename(file_path)}`. Размеры структур для **{elf_fmt}**:")
        log()
        log(f"- ELF-заголовок — **{ehdr['e_ehsize']}** байт.")
        log(f"- Program Header — **{ehdr['e_phentsize']}** байт.")
        log(f"- Section Header — **{ehdr['e_shentsize']}** байт.")
        log()

        log("### 1) Анализ ELF-заголовка")
        log()
        log("Открываем файл в HEX-редакторе.")
        log()
        eh_preview_len = min(256, len(raw))
        prev_blob, prev_base, _ = slice_for_dump(raw, 0, eh_preview_len)
        log_md_code_block(log, "text", format_hex_dump_xxd(prev_blob, prev_base))
        log()
        log("Заполняем таблицу ELF-заголовка.")
        log()
        hdr_elf = (
            "Смещение",
            "Поле",
            "Размер<br>(байт)",
            "Байты",
            "Значение",
            "Расшифровка",
        )
        log_markdown_table(log, hdr_elf, build_elf_header_table_rows(raw, ei_class, ehdr))
        log()

        log("### 2) Анализ Program Headers")
        log()
        log("Находим таблицу Program Headers.")
        log()
        e_phoff_v = int(ehdr["e_phoff"])
        e_phent_v = int(ehdr["e_phentsize"])
        e_phnum_v = int(ehdr["e_phnum"])
        log(f"- Начало 0x{e_phoff_v:X} (из e_phoff).")
        log(f"- Размер одного {e_phent_v} байт (0x{e_phent_v:X} из e_phentsize).")
        log(f"- Количество {e_phnum_v} штук (из e_phnum).")
        log()
        log("Формула для поиска Program Header.")
        log()
        log(f"`PH_N_offset = 0x{e_phoff_v:X} + (N × 0x{e_phent_v:X})`")
        log()
        log("#### Рассчитываем смещения.")
        log()
        for i in range(e_phnum_v):
            off_i = e_phoff_v + i * e_phent_v
            step_hex = i * e_phent_v
            log(f"- PH_{i} 0x{e_phoff_v:X} + ({i} × {e_phent_v}) = 0x{e_phoff_v:X} + 0x{step_hex:X} = 0x{off_i:X}.")
        log()
        hdr_ph_layout = ("Смещение", "Поле", "Размер", "Описание")
        log_markdown_table(log, hdr_ph_layout, phdr_layout_table_rows(ei_class))
        log()
        log("Анализируем ключевые Program Headers.")
        log()
        ph_ent = e_phent_v
        for ph in phdrs:
            fo = int(ph["file_off"])
            idx = int(ph["index"])
            blob_ph, base_ph, ln_ph = slice_for_dump(raw, fo, ph_ent)
            if ln_ph == 0:
                continue
            log(f"PH_{idx} (смещение 0x{fo:X}).")
            log()
            log_md_code_block(log, "text", format_hex_dump_xxd(blob_ph, base_ph))
            log()
            if ei_class == EI_CLASS_64:
                lines_pf, tails_pf = phdr_methodology_lines_elf64(raw, fo)
            else:
                lines_pf, tails_pf = phdr_methodology_lines_elf32(raw, fo)
            for ln in lines_pf:
                log(ln)
            if tails_pf:
                log()
            for para in tails_pf:
                log(para)
            log()

        log("Заполняем итоговую таблицу Program Headers.")
        log()
        ph_summary_headers = (
            "№",
            "Тип",
            "Флаги",
            "Offset",
            "FileSiz",
            "MemSiz",
            "Назначение",
        )
        ph_summary_rows: list[tuple[str, ...]] = []
        for ph in phdrs:
            pt = int(ph["p_type"])
            pf = int(ph["p_flags"])
            ph_summary_rows.append(
                (
                    str(ph["index"]),
                    f"0x{pt:08X}<br>({pt_short(pt)})",
                    ph_summary_flags_cell(pf),
                    f"0x{ph['p_offset']:X}",
                    f"0x{ph['p_filesz']:X}",
                    f"0x{ph['p_memsz']:X}",
                    ph_summary_naznachenie(pt, pf),
                )
            )
        log_markdown_table(log, ph_summary_headers, ph_summary_rows)
        log()

        log("### 3) Анализ Section Headers")
        log()
        log("Находим таблицу Section Headers.")
        log()
        e_shoff_i = int(ehdr["e_shoff"])
        e_shentsize_i = int(ehdr["e_shentsize"])
        e_shnum_v = int(ehdr["e_shnum"])
        idx_str = int(shstrndx)
        log(f"- Начало 0x{e_shoff_i:X} (из e_shoff).")
        log(f"- Размер одного {e_shentsize_i} байт (0x{e_shentsize_i:X} из e_shentsize).")
        log(f"- Количество {e_shnum_v} (из e_shnum).")
        log(f"- Индекс .shstrtab {idx_str} (из e_shstrndx).")
        log()

        off_shstr_rec = e_shoff_i + idx_str * e_shentsize_i
        step_sh = idx_str * e_shentsize_i
        log(f"Находим секцию .shstrtab (секция {idx_str}).")
        log()
        log(
            f"- SH_{idx_str} = 0x{e_shoff_i:X} + ({idx_str} × {e_shentsize_i}) = "
            f"0x{e_shoff_i:X} + 0x{step_sh:X} = 0x{off_shstr_rec:X}."
        )
        log()
        log(f"Читаем заголовок секции #{idx_str} по 0x{off_shstr_rec:X}.")
        log()
        sh_dump_len = e_shentsize_i
        b_shd, a_shd, n_shd = slice_for_dump(raw, off_shstr_rec, sh_dump_len)
        if n_shd:
            log_md_code_block(log, "text", format_hex_dump_xxd(b_shd, a_shd))
            log()
            for ln in shdr_methodology_shstrtab_lines(raw, off_shstr_rec, ei_class):
                log(ln)
        log()

        hdr_sh_layout = ("Смещение", "Поле", "Размер", "Описание")
        log(f"#### Структура Section Header ({sh_dump_len} байт).")
        log()
        log_markdown_table(log, hdr_sh_layout, shdr_layout_table_rows(ei_class))
        log()

        text_sec = next((s for s in shdrs if sec_name(s) == ".text"), None)
        if text_sec is not None:
            ti = int(text_sec["index"])
            off_text_rec = e_shoff_i + ti * e_shentsize_i
            step_tx = ti * e_shentsize_i
            log(f"#### Находим и анализируем секцию .text (секция {ti}).")
            log()
            log(
                f"- SH_{ti} = 0x{e_shoff_i:X} + ({ti} × {e_shentsize_i}) = "
                f"0x{e_shoff_i:X} + 0x{step_tx:X} = 0x{off_text_rec:X}."
            )
            log()
            log(f"Читаем заголовок секции #{ti} по 0x{off_text_rec:X}.")
            log()
            b_tx, a_tx, n_tx = slice_for_dump(raw, off_text_rec, sh_dump_len)
            if n_tx:
                log_md_code_block(log, "text", format_hex_dump_xxd(b_tx, a_tx))
                log()
            log("Разбираем заголовок.")
            log()
            for ln in shdr_methodology_text_lines(raw, off_text_rec, ei_class):
                log(ln)
            log()

            shn = int(text_sec["sh_name"])
            if shstr_hdr is not None:
                sso_tab = int(shstr_hdr["sh_offset"])
                name_abs = sso_tab + shn
                log("Определяем имя секции .text.")
                log()
                log(f"Адрес_имени = shstrtab_offset + sh_name = 0x{sso_tab:X} + 0x{shn:X} = 0x{name_abs:X}.")
                log()
                log(f"Переходим к 0x{name_abs:X} в файле.")
                log()
                b_nm, a_nm, n_nm = slice_for_dump(raw, name_abs, 64)
                if n_nm:
                    log_md_code_block(log, "text", format_hex_dump_xxd(b_nm, a_nm))
                log()

        log("Заполняем таблицу ключевых секций.")
        log()
        hdr_key_sec = ("Секция", "Индекс", "sh_name", "sh_offset", "sh_size", "Тип", "Флаги")
        log_markdown_table(
            log,
            hdr_key_sec,
            build_key_sections_table(shdrs, sec_name),
            bold_first_col=False,
        )
        log()

        log("*Полная таблица всех записей Section Headers приведена в части 2.*")
        log()

        sh_headers = (
            "Индекс",
            "Имя",
            "Тип",
            "Флаги",
            "sh_addr",
            "sh_offset",
            "sh_size",
        )
        sh_rows: list[tuple[str, ...]] = []
        for sh in shdrs:
            nm = sec_name(sh)
            st = SHT_TYPE_NAMES.get(sh["sh_type"], str(sh["sh_type"]))
            fl = _sh_flags_str(int(sh["sh_flags"]))
            sh_rows.append(
                (
                    str(sh["index"]),
                    nm or "(пусто)",
                    st,
                    fl,
                    f"0x{sh['sh_addr']:X}",
                    f"0x{sh['sh_offset']:X}",
                    f"0x{sh['sh_size']:X}",
                )
            )

        log("### 4) Анализ содержимого файла")
        log()
        interp_ph = next((p for p in phdrs if p["p_type"] == PT_INTERP and int(p["p_filesz"]) > 0), None)
        interp_sec = next((s for s in shdrs if sec_name(s) == ".interp"), None)

        if interp_ph is not None:
            pix = int(interp_ph["index"])
            o = int(interp_ph["p_offset"])
            sz = int(interp_ph["p_filesz"])
            interp_path = _read_cstr(raw, o)
            log("Находим интерпретатор программы.")
            log()
            log(f"- Из PH_{pix} offset = 0x{o:X}, size = 0x{sz:X}.")
            log(f"- Переходим к 0x{o:X}.")
            log()
            align = max(0, (o // 16) * 16)
            span = min(len(raw) - align, max(64, ((o + sz - align + 15) // 16 + 1) * 16))
            bi, ai, ni = slice_for_dump(raw, align, span)
            if ni:
                log_md_code_block(log, "text", format_hex_dump_xxd(bi, ai))
            log()
            log(f"Интерпретатор `{interp_path}`.")
            log()
        elif interp_sec is not None and int(interp_sec["sh_size"]) > 0:
            io = int(interp_sec["sh_offset"])
            isz = int(interp_sec["sh_size"])
            interp_path = _read_cstr(raw, io)
            log("Находим интерпретатор программы.")
            log()
            log(f"- В таблице секций `.interp`: offset = 0x{io:X}, size = 0x{isz:X} (отдельного PT_INTERP в PH нет).")
            log(f"- Переходим к 0x{io:X}.")
            log()
            bi, ai, ni = slice_for_dump(raw, io, min(isz + 32, len(raw) - io))
            if ni:
                log_md_code_block(log, "text", format_hex_dump_xxd(bi, ai))
            log()
            log(f"Интерпретатор `{interp_path}`.")
            log()
        else:
            log("*Интерпретатор не найден (нет PT_INTERP и секции `.interp`).*")
            log()

        text_sec2 = next((s for s in shdrs if sec_name(s) == ".text"), None)
        ro_sec = next((s for s in shdrs if sec_name(s) == ".rodata"), None)

        if text_sec2 is not None and int(text_sec2["sh_size"]) > 0:
            toff = int(text_sec2["sh_offset"])
            tlen = min(256, int(text_sec2["sh_size"]))
            log("Анализируем исполняемый код (.text).")
            log()
            log(f"- Из секции .text offset = 0x{toff:X}.")
            log()
            log(f"- Переходим к 0x{toff:X}.")
            log()
            log("Читаем машинный код.")
            log()
            bt, at, nt = slice_for_dump(raw, toff, tlen)
            if nt:
                log_md_code_block(log, "text", format_hex_dump_xxd(bt, at))
            log()

        if ro_sec is not None and int(ro_sec["sh_size"]) > 0:
            roff = int(ro_sec["sh_offset"])
            rlen = min(256, int(ro_sec["sh_size"]))
            log("Находим строки в .rodata.")
            log()
            log(f"- Из секции .rodata offset = 0x{roff:X}.")
            log()
            log(f"- Переходим к 0x{roff:X}.")
            log()
            log("Ищем строки программы.")
            log()
            br, ar, nr = slice_for_dump(raw, roff, rlen)
            if nr:
                log_md_code_block(log, "text", format_hex_dump_xxd(br, ar))
            log()

        # --- Часть 2: ответы на вопросы лабораторной ---
        log()
        log_sep("=")
        log("ЧАСТЬ 2. ОТВЕТЫ НА ВОПРОСЫ (Лабораторная_работа_9.md)")
        log_sep("=")
        log()

        ph0 = phdrs[0] if phdrs else None
        ph1 = phdrs[1] if len(phdrs) > 1 else None

        # ---------- Вопрос 1 ----------
        log("Вопрос 1. Полный разбор Phdr[0]")
        log("-" * 80)
        if ph0:
            off0 = ph0["file_off"]
            log(f"1) Файловое смещение первого программного заголовка: 0x{off0:X} "
                f"(это e_phoff + 0 × e_phentsize = 0x{ehdr['e_phoff']:X}).")
            if ei_class == EI_CLASS_32:
                dump = raw[off0 : off0 + 32]
                log(f"2) 32 байта hex по этому смещению (Elf32_Phdr):")
                log(f"   {dump.hex(' ').upper()}")
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack(
                    "<8I", dump
                )
                log("3) Восемь полей Elf32_Phdr (по 4 байта, little-endian):")
                log(f"   p_type   = 0x{p_type:08X}  ({pt_name(p_type)})")
                log(f"   p_offset = 0x{p_offset:08X}")
                log(f"   p_vaddr  = 0x{p_vaddr:08X}")
                log(f"   p_paddr  = 0x{p_paddr:08X}")
                log(f"   p_filesz = 0x{p_filesz:08X}  ({p_filesz} байт)")
                log(f"   p_memsz  = 0x{p_memsz:08X}  ({p_memsz} байт)")
                log(f"   p_flags  = 0x{p_flags:08X}")
                log(f"   p_align  = 0x{p_align:08X}")
            else:
                off = ph0["file_off"]
                dump = raw[off : off + 56]
                log(f"2) 56 байт hex (Elf64_Phdr):")
                log(f"   {dump.hex(' ').upper()}")
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(
                    "<IIQQQQQQ", dump
                )
                log("3) Поля Elf64_Phdr:")
                log(f"   p_type   = 0x{p_type:08X}  ({pt_name(p_type)})")
                log(f"   p_flags  = 0x{p_flags:08X}")
                log(f"   p_offset = 0x{p_offset:X}")
                log(f"   p_vaddr  = 0x{p_vaddr:X}")
                log(f"   p_paddr  = 0x{p_paddr:X}")
                log(f"   p_filesz = 0x{p_filesz:X}")
                log(f"   p_memsz  = 0x{p_memsz:X}")
                log(f"   p_align  = 0x{p_align:X}")
                p_flags = int(p_flags)
            pt0 = int(ph0["p_type"])
            log(
                f"4) Декодирование p_type словесно: числовое значение 0x{pt0:X} соответствует типу сегмента "
                f"«{pt_name(pt0)}» (в заголовках ELF это константа семейства PT_*)."
            )
            log("5) Декодирование p_flags побитово:")
            log(f"   { _ph_flags_bits(int(ph0['p_flags'])) }")
            log(f"   Строка прав (как в задании): '{_ph_flags_str(int(ph0['p_flags']))}'")
        else:
            log("Phdr[0] отсутствует.")
        log()

        # ---------- Вопрос 2 ----------
        log("Вопрос 2. Полный разбор Phdr[1]")
        log("-" * 80)
        if ph1:
            off1 = ph1["file_off"]
            log(f"1) Смещение второго PH: 0x{off1:X} = e_phoff + 1 × e_phentsize.")
            if ei_class == EI_CLASS_32:
                dump = raw[off1 : off1 + 32]
                log(f"2) 32 байта: {dump.hex(' ').upper()}")
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack(
                    "<8I", dump
                )
                log("3) Поля Elf32_Phdr[1] (восемь полей по 4 байта, little-endian):")
                log(f"   p_type   = 0x{p_type:08X}  ({pt_name(p_type)})")
                log(f"   p_offset = 0x{p_offset:08X}")
                log(f"   p_vaddr  = 0x{p_vaddr:08X}")
                log(f"   p_paddr  = 0x{p_paddr:08X}")
                log(f"   p_filesz = 0x{p_filesz:08X}  ({p_filesz} байт)")
                log(f"   p_memsz  = 0x{p_memsz:08X}  ({p_memsz} байт)")
                log(f"   p_flags  = 0x{p_flags:08X}")
                log(f"   p_align  = 0x{p_align:08X}")
            else:
                dump = raw[off1 : off1 + 56]
                log(f"2) 56 байт: {dump.hex(' ').upper()}")
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(
                    "<IIQQQQQQ", dump
                )
                log("3) Поля Elf64_Phdr[1]:")
                log(f"   p_type   = 0x{p_type:08X}  ({pt_name(p_type)})")
                log(f"   p_flags  = 0x{p_flags:08X}")
                log(f"   p_offset = 0x{p_offset:X}")
                log(f"   p_vaddr  = 0x{p_vaddr:X}")
                log(f"   p_paddr  = 0x{p_paddr:X}")
                log(f"   p_filesz = 0x{p_filesz:X}")
                log(f"   p_memsz  = 0x{p_memsz:X}")
                log(f"   p_align  = 0x{p_align:X}")
            log(
                "4) Разница p_filesz и p_memsz: p_filesz — сколько байт берётся из файла; "
                "p_memsz — сколько байт выделяется в памяти сегмента. Если p_memsz > p_filesz, "
                "хвост сегмента в памяти инициализируется нулями (типично для сегмента, содержащего .bss: "
                "данные «без файла» занимают память, но не хранятся в образе)."
            )
            delta = int(ph1["p_memsz"]) - int(ph1["p_filesz"])
            log(f"   Здесь: p_memsz - p_filesz = 0x{ph1['p_memsz']:X} - 0x{ph1['p_filesz']:X} = 0x{delta:X} ({delta} байт).")
            nobits = [sh for sh in shdrs if sh["sh_type"] == SHT_NOBITS]
            log("5) Секции SHT_NOBITS и проверка sh_size = p_memsz − p_filesz для соответствующего LOAD:")
            found = False
            for sh in nobits:
                nm = sec_name(sh)
                sz = int(sh["sh_size"])
                if sz == delta and delta > 0:
                    log(f"   Секция '{nm}' (SHT_NOBITS): sh_size = 0x{sz:X} — совпадает с разницей сегмента Phdr[1].")
                    found = True
                elif delta > 0:
                    log(f"   Секция '{nm}' (SHT_NOBITS): sh_size = 0x{sz:X}.")
            if delta == 0:
                log("   Для этого файла p_memsz == p_filesz у второго сегмента — расширения BSS в данном LOAD нет.")
            elif not found and nobits:
                log("   (Уточните вручную соответствие сегмента и NOBITS при нескольких LOAD.)")
        else:
            log("Phdr[1] отсутствует.")
        log()

        # ---------- Вопрос 3 ----------
        log("Вопрос 3. Какие секции входят в первый PT_LOAD?")
        log("-" * 80)
        loads = [p for p in phdrs if p["p_type"] == PT_LOAD]
        first_load = loads[0] if loads else None
        if first_load:
            pv = int(first_load["p_vaddr"])
            pm = int(first_load["p_memsz"])
            end = pv + pm
            log(f"Первый PT_LOAD: p_vaddr = 0x{pv:X}, p_memsz = 0x{pm:X}, конец VA = 0x{end:X}.")
            log("Условие включения секции: sh_addr >= p_vaddr  И  sh_addr + sh_size <= p_vaddr + p_memsz.")
            log()
            hdr_q3 = ("Индекс", "Имя секции", "sh_addr", "sh_addr+sh_size", "входит?")
            rows_q3: list[tuple[str, ...]] = []
            for sh in shdrs:
                idx = sh["index"]
                if idx < 1 or idx > 8:
                    continue
                nm = sec_name(sh)
                sa = int(sh["sh_addr"])
                ss = int(sh["sh_size"])
                ta = sa + ss
                inside = sa >= pv and ta <= end and sh["sh_type"] != SHT_NULL
                if sh["sh_type"] == SHT_NULL:
                    inside = False
                mark = "да" if inside else "нет"
                rows_q3.append((str(idx), nm, f"0x{sa:08X}", f"0x{ta:08X}", mark))
            log_markdown_table(log, hdr_q3, rows_q3)
        else:
            log("PT_LOAD не найден.")
        log()

        # ---------- Вопрос 4 ----------
        log("Вопрос 4. p_flags всех PT_LOAD и выравнивание")
        log("-" * 80)
        for i, ph in enumerate(loads):
            log(f"PT_LOAD[{i}] (глобальный PH[{ph['index']}]): p_flags = 0x{ph['p_flags']:X} → '{_ph_flags_str(ph['p_flags'])}'")
            log(f"   Побитово: {_ph_flags_bits(ph['p_flags'])}")
        log(
            "Пояснение: у сегмента с кодом обычно выставлены R и X, но не W (защита от модификации кода). "
            "У сегмента данных — R и часто W, без X (данные не исполняются). "
            "Если добавить W к .text, страницы станут записываемыми и исполняемыми — упрощается эксплуатация "
            "(shellcode, самомодификация), нарушается W^X."
        )
        log()
        for ph in loads:
            pa = int(ph["p_align"])
            log(f"Сегмент PH[{ph['index']}]: p_align = 0x{pa:X} ({pa} байт). "
                f"Для загрузчика это требование выровнять начало сегмента в памяти по границе страницы/величине align.")
        log()
        for ph in loads:
            pv = int(ph["p_vaddr"])
            po = int(ph["p_offset"])
            pa = int(ph["p_align"])
            if pa == 0:
                log(f"PH[{ph['index']}]: p_align=0 — проверка (p_vaddr - p_offset) mod p_align не применима (деление на 0).")
                continue
            rem = (pv - po) % pa
            log(
                f"PH[{ph['index']}]: (p_vaddr - p_offset) mod p_align = (0x{pv:X} - 0x{po:X}) mod 0x{pa:X} "
                f"= {rem}  {'✓ условие выполнено' if rem == 0 else '✗ остаток ненулевой'}"
            )
        log()

        # ---------- Вопрос 5 ----------
        log("Вопрос 5. Суммарный виртуальный размер и адресное пространство")
        log("-" * 80)
        if len(loads) >= 2:
            ends = []
            starts = []
            for ph in loads:
                pv = int(ph["p_vaddr"])
                pm = int(ph["p_memsz"])
                starts.append(pv)
                ends.append(pv + pm)
                log(f"Сегмент PH[{ph['index']}]: p_vaddr = 0x{pv:X}, p_memsz = 0x{pm:X}, виртуальный конец = 0x{pv + pm:X}")
            min_v = min(starts)
            max_e = max(ends)
            vm_total = max_e - min_v
            log(f"Минимальный p_vaddr: 0x{min_v:X}; максимальный конец: 0x{max_e:X}.")
            log(f"vm_total = max_end − min_vaddr = 0x{max_e:X} − 0x{min_v:X} = 0x{vm_total:X} ({vm_total} байт).")
            log(f"В килобайтах (десятичное): {vm_total / 1024:.4f} КиБ.")
            log(
                "Смысл: это не «размер файла», а размах VA, который покрывают LOAD-сегменты при отображении в адресное пространство "
                "процесса; ОС выделяет страницы под эти диапазоны (с учётом выравнивания)."
            )
        elif len(loads) == 1:
            ph = loads[0]
            pv = int(ph["p_vaddr"])
            pm = int(ph["p_memsz"])
            vm_total = pm
            log(f"Один PT_LOAD: диапазон 0x{pv:X} .. 0x{pv + pm:X}, vm_total = 0x{vm_total:X}.")
        else:
            log("Нет PT_LOAD для расчёта.")
        log()

        log_sep("=")
        log("Конец отчёта.")
        log_sep("=")

    print(f"Отчёт записан: {report_path}")


if __name__ == "__main__":
    tgt = os.path.join(os.path.dirname(__file__), "student_20.elf")
    if len(sys.argv) > 1:
        tgt = sys.argv[1]
    analyze_elf(tgt)
