#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import sys
import traceback
from pathlib import Path

from qiling import Qiling
from qiling.const import QL_VERBOSE

from unicorn import (
    UcError,
    UC_PROT_READ,
    UC_PROT_WRITE,
    UC_PROT_EXEC,
)

from unicorn.x86_const import (
    UC_X86_REG_FS_BASE,
    UC_X86_REG_GS_BASE,
)


CAPTURE_DIR = Path("/work/capture")
#Пути
POINT_A_JSON = CAPTURE_DIR / "point_a.json"
POINT_A_MEMORY_JSON = CAPTURE_DIR / "point_a_memory.json"
POINT_B_JSON = CAPTURE_DIR / "point_b.json"
REQUEST_BUFFER_FILE = CAPTURE_DIR / "request_buffer.bin"

ROOTFS = "/opt/rootfs"
NGINX_BIN = "/opt/rootfs/usr/sbin/nginx"
NGINX_CONF = "/etc/nginx/nginx.conf"

MAX_INSTRUCTIONS = 2_000_000
PAGE_SIZE = 0x1000 #4096 байт
FS_TLS_OFFSET = 0x28

TRACE_FIRST_INSTRUCTIONS = 20
RECENT_RIPS_LIMIT = 64
DEBUG_BYTES = 32


STATE = {
    "point_b_reached": False,
    "emu_started": False,
    "emu_stopped_by_target": False,
    "instruction_count": 0,
    "recent_rips": [],
    "invalid_memory": [],
    "code_hook_handle": None,
    "invalid_hook_handle": None,
}


REGISTER_NAMES = [
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "rip",
    "eflags",
]


def log(message=""):
    print(f"[LOAD] {message}")
    sys.stdout.flush()


def fatal(message):
    log("")
    log("КРИТИЧЕСКАЯ ОШИБКА")
    log(message)
    sys.exit(1)


def load_json(path: Path):
    if not path.exists():
        fatal(f"Файл не найден: {path}")

    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        fatal(f"Не удалось прочитать {path}: {exc}")


def parse_int(value, field_name="value"):
    if value is None:
        raise ValueError(f"{field_name}: значение отсутствует")

    if isinstance(value, int):
        return value

    if isinstance(value, str):
        value = value.strip()

        if value.lower().startswith("0x"):
            return int(value, 16)

        return int(value, 10)

    raise ValueError(
        f"{field_name}: неизвестный тип {type(value)}"
    )


def parse_hex_or_zero(value):
    if value is None:
        return 0

    try:
        return parse_int(value)
    except Exception:
        return 0


def permissions_to_unicorn(permissions):
    if permissions is None:
        return UC_PROT_READ

    permissions = str(permissions)
    prot = 0

    if len(permissions) >= 1 and permissions[0] == "r":
        prot |= UC_PROT_READ

    if len(permissions) >= 2 and permissions[1] == "w":
        prot |= UC_PROT_WRITE

    if len(permissions) >= 3 and permissions[2] == "x":
        prot |= UC_PROT_EXEC

    return prot


def permissions_to_string(prot):
    result = ""
    result += "r" if prot & UC_PROT_READ else "-"
    result += "w" if prot & UC_PROT_WRITE else "-"
    result += "x" if prot & UC_PROT_EXEC else "-"
    return result


def load_capture_metadata():
    log("LOAD DUMP NGINX + QILING")
    log("Читаем Point A dump...")

    point_a = load_json(POINT_A_JSON)
    point_a_memory = load_json(POINT_A_MEMORY_JSON)

    if not isinstance(point_a_memory, list):
        fatal("point_a_memory.json должен содержать список mappings")

    function_name = point_a.get("function", "<unknown>")

    original_pid = point_a.get(
        "original_pid",
        point_a.get("pid"),
    )

    rip = parse_int(point_a["rip"], "point_a.rip")
    rsp = parse_int(point_a["rsp"], "point_a.rsp")
    rbp = parse_int(point_a["rbp"], "point_a.rbp")

    fs_base = parse_hex_or_zero(point_a.get("fs_base"))
    gs_base = parse_hex_or_zero(point_a.get("gs_base"))

    http_buffer = point_a.get("http_buffer", {})
    if not isinstance(http_buffer, dict):
        http_buffer = {}

    http_address = parse_hex_or_zero(
        http_buffer.get(
            "address",
            point_a.get("http_buffer_address"),
        )
    )

    http_received = parse_hex_or_zero(
        http_buffer.get(
            "received",
            point_a.get("http_received"),
        )
    )

    http_capacity = parse_hex_or_zero(
        http_buffer.get(
            "capacity",
            point_a.get("http_buffer_capacity"),
        )
    )

    log(f"Point A function = {function_name}")
    if original_pid is None:
        log("исходный PID = <нет поля в JSON>")
    else:
        log(f"исходный PID = {original_pid}")

    log(f"Point A RIP = 0x{rip:016x}")
    log(f"Point A RSP = 0x{rsp:016x}")
    log(f"Point A RBP = 0x{rbp:016x}")
    log(f"FS base = 0x{fs_base:016x}")
    log(f"GS base = 0x{gs_base:016x}")
    log(f"memory mappings = {len(point_a_memory)}")

    return {
        "point_a": point_a,
        "point_a_memory": point_a_memory,
        "function": function_name,
        "original_pid": original_pid,
        "rip": rip,
        "rsp": rsp,
        "rbp": rbp,
        "fs_base": fs_base,
        "gs_base": gs_base,
        "http_address": http_address,
        "http_received": http_received,
        "http_capacity": http_capacity,
    }


def create_qiling():
    log("СОЗДАНИЕ QILING")

    if not os.path.exists(NGINX_BIN):
        fatal(f"NGINX binary не найден: {NGINX_BIN}")

    if not os.path.exists(ROOTFS):
        fatal(f"ROOTFS не найден: {ROOTFS}")

    try:
        ql = Qiling(
            [NGINX_BIN, "-c", NGINX_CONF],
            ROOTFS,
            verbose=QL_VERBOSE.OFF,
            console=False,
            multithread=True,
        )
    except Exception as exc:
        traceback.print_exc()
        fatal(f"Не удалось создать Qiling: {exc}")

    log("Qiling создан успешно.")
    return ql


def get_mapping_file(mapping):
    file_value = mapping.get("file")
    if not file_value:
        return None

    file_path = Path(file_value)
    if file_path.is_absolute():
        return file_path

    return CAPTURE_DIR / file_path


def map_page_if_needed(ql, page_address, final_permissions):
    try:
        is_mapped = ql.mem.is_mapped(page_address, PAGE_SIZE)
    except Exception:
        is_mapped = False

    if is_mapped:
        ql.mem.protect(
            page_address,
            PAGE_SIZE,
            UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
        )
        return True

    ql.mem.map(
        page_address,
        PAGE_SIZE,
        UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
    )
    return False


def restore_memory_mappings(ql, mappings):
    log("ВОССТАНОВЛЕНИЕ MEMORY")

    total_mappings = len(mappings)
    mappings_ok = 0
    mappings_partial = 0
    mappings_failed = 0

    pages_created = 0
    pages_existing = 0
    pages_protection = 0
    pages_written = 0
    pages_failed = 0
    bytes_processed = 0

    for index, mapping in enumerate(mappings):
        try:
            start = parse_int(mapping["start"], "mapping.start")
            end = parse_int(mapping["end"], "mapping.end")
            size = end - start

            permissions = str(mapping.get("permissions", "r--p"))
            file_path = get_mapping_file(mapping)

            log(
                f"[{index}] 0x{start:016x}-0x{end:016x} "
                f"size={size} permissions={permissions}"
            )

            if file_path is None:
                log("  -> ОШИБКА: отсутствует поле file")
                mappings_failed += 1
                continue

            if not file_path.exists():
                log(f"  -> ОШИБКА: файл dump не найден: {file_path}")
                mappings_failed += 1
                continue

            actual_file_size = file_path.stat().st_size

            if actual_file_size < size:
                log(
                    "  -> ОШИБКА: размер dump-файла "
                    f"{actual_file_size} меньше ожидаемых {size}"
                )
                mappings_failed += 1
                continue

            if actual_file_size > size:
                log(
                    "  -> предупреждение: dump-файл больше mapping "
                    f"({actual_file_size} > {size})"
                )

            final_prot = permissions_to_unicorn(permissions)

            temporary_prot = (
                UC_PROT_READ
                | UC_PROT_WRITE
                | UC_PROT_EXEC
            )
            _ = temporary_prot

            mapping_pages = (size + PAGE_SIZE - 1) // PAGE_SIZE
            mapping_page_failures = 0
            mapping_bytes = 0

            with file_path.open("rb") as dump_file:
                for page_index in range(mapping_pages):
                    page_address = start + page_index * PAGE_SIZE
                    page_end = min(page_address + PAGE_SIZE, end)
                    page_size = page_end - page_address

                    dump_file.seek(page_index * PAGE_SIZE)
                    data = dump_file.read(page_size)

                    if len(data) != page_size:
                        mapping_page_failures += 1
                        pages_failed += 1
                        log(
                            f"  -> page 0x{page_address:016x}: "
                            "неполные данные"
                        )
                        continue

                    try:
                        existed = map_page_if_needed(
                            ql,
                            page_address,
                            final_prot,
                        )

                        if existed:
                            pages_existing += 1
                            pages_protection += 1
                        else:
                            pages_created += 1
                    except Exception as exc:
                        mapping_page_failures += 1
                        pages_failed += 1
                        log(
                            f"  -> page 0x{page_address:016x}: "
                            f"ошибка map/protect: {exc}"
                        )
                        continue

                    try:
                        ql.mem.write(page_address, data)
                        pages_written += 1
                        mapping_bytes += len(data)
                        bytes_processed += len(data)
                    except Exception as exc:
                        mapping_page_failures += 1
                        pages_failed += 1
                        log(
                            f"  -> page 0x{page_address:016x}: "
                            f"ошибка записи: {exc}"
                        )
                        continue

                    try:
                        ql.mem.protect(
                            page_address,
                            PAGE_SIZE,
                            final_prot,
                        )
                    except Exception as exc:
                        mapping_page_failures += 1
                        pages_failed += 1
                        log(
                            f"  -> page 0x{page_address:016x}: "
                            f"ошибка восстановления protection: {exc}"
                        )
                        continue

            if mapping_page_failures == 0:
                mappings_ok += 1
                log(
                    f"  -> mapping восстановлен ({mapping_pages} pages)"
                )
            else:
                mappings_partial += 1
                log(
                    "  -> mapping частично восстановлен: "
                    f"{mapping_pages - mapping_page_failures}/"
                    f"{mapping_pages} pages"
                )

            _ = mapping_bytes

        except Exception as exc:
            mappings_failed += 1
            log(f"  -> mapping НЕ восстановлен: {exc}")

    log("Итоги памяти")
    log(f"mappings всего        : {total_mappings}")
    log(f"mappings OK           : {mappings_ok}")
    log(f"mappings partial      : {mappings_partial}")
    log(f"mappings failed       : {mappings_failed}")
    log(f"pages создано         : {pages_created}")
    log(f"pages существовало    : {pages_existing}")
    log(f"pages protection      : {pages_protection}")
    log(f"pages записано        : {pages_written}")
    log(f"pages failed          : {pages_failed}")
    log(f"bytes обработано      : {bytes_processed}")

    return {
        "total_mappings": total_mappings,
        "mappings_ok": mappings_ok,
        "mappings_partial": mappings_partial,
        "mappings_failed": mappings_failed,
        "pages_created": pages_created,
        "pages_existing": pages_existing,
        "pages_protection": pages_protection,
        "pages_written": pages_written,
        "pages_failed": pages_failed,
        "bytes_processed": bytes_processed,
    }


def restore_request_buffer(ql, metadata):
    log("ВОССТАНОВЛЕНИЕ HTTP BUFFER")

    address = metadata["http_address"]
    received = metadata["http_received"]
    capacity = metadata["http_capacity"]

    if address == 0:
        log("HTTP buffer address отсутствует — пропуск восстановления")
        return

    data = None

    if REQUEST_BUFFER_FILE.exists():
        try:
            with REQUEST_BUFFER_FILE.open("rb") as f:
                data = f.read(received)
        except Exception as exc:
            log(f"Ошибка чтения request_buffer.bin: {exc}")

    if data is None:
        point_a = metadata["point_a"]
        http_buffer = point_a.get("http_buffer", {})
        data_hex = http_buffer.get("data_hex")

        if not data_hex:
            data_hex = point_a.get("http_request_hex", "")

        if data_hex:
            try:
                data = bytes.fromhex(data_hex)
            except Exception as exc:
                log(f"Ошибка декодирования data_hex: {exc}")

    if data is None:
        log("Данные HTTP buffer не найдены")
        return

    if len(data) != received:
        log(
            "размер HTTP data "
            f"{len(data)} != received {received}"
        )
        data = data[:received]

    log(f"address  = 0x{address:016x}")
    log(f"received = {received}")
    log(f"capacity = {capacity}")
    log(f"data     = {data!r}")

    try:
        ql.mem.write(address, data)
        read_back = ql.mem.read(address, len(data))
        log(f"прочитано обратно: {read_back!r}")

        if bytes(read_back) == data:
            log("HTTP buffer: OK")
        else:
            log("HTTP buffer: ОШИБКА — прочитанные данные отличаются.")
    except Exception as exc:
        log(f"HTTP buffer: ОШИБКА записи: {exc}")


def get_dump_registers(point_a):
    registers = point_a.get("registers", {})

    if isinstance(registers, dict) and registers:
        return registers

    result = {}
    for name in REGISTER_NAMES:
        if name in point_a:
            result[name] = point_a[name]

    return result


def restore_registers(ql, point_a, expected_metadata=None):
    log("ВОССТАНОВЛЕНИЕ РЕГИСТРОВ")

    registers = get_dump_registers(point_a)
    restored = 0
    failed = 0

    for name in REGISTER_NAMES:
        if name not in registers:
            log(f"  {name:<7} отсутствует в dump")
            continue

        try:
            expected = parse_int(registers[name], f"register {name}")
            setattr(ql.arch.regs, name, expected)
            actual = int(getattr(ql.arch.regs, name))

            log(
                f"  {name:<7} dump={expected:#018x} "
                f"actual={actual:#018x}"
            )

            if actual != expected:
                failed += 1
            else:
                restored += 1
        except Exception as exc:
            failed += 1
            log(f"  {name:<7} ошибка: {exc}")

    log(f"регистров восстановлено: {restored}")
    log(f"регистров с ошибкой: {failed}")

    if failed:
        log("часть регистров не удалось восстановить")


def restore_segment_bases(ql, point_a):
    log("ВОССТАНОВЛЕНИЕ FS/GS")

    fs_base = parse_hex_or_zero(point_a.get("fs_base"))
    gs_base = parse_hex_or_zero(point_a.get("gs_base"))

    try:
        ql.uc.reg_write(UC_X86_REG_FS_BASE, fs_base)
        actual_fs = ql.uc.reg_read(UC_X86_REG_FS_BASE)
        log(f"FS base dump   = {fs_base:#018x}")
        log(f"FS base Qiling = {actual_fs:#018x}")
        log("FS base: " + ("OK" if actual_fs == fs_base else "ERROR"))
    except Exception as exc:
        log(f"FS base: ОШИБКА: {exc}")

    try:
        ql.uc.reg_write(UC_X86_REG_GS_BASE, gs_base)
        actual_gs = ql.uc.reg_read(UC_X86_REG_GS_BASE)
        log(f"GS base dump   = {gs_base:#018x}")
        log(f"GS base Qiling = {actual_gs:#018x}")
        log("GS base: " + ("OK" if actual_gs == gs_base else "ERROR"))
    except Exception as exc:
        log(f"GS base: ОШИБКА: {exc}")


def verify_fs_tls(ql, point_a):
    log("ПРОВЕРКА FS:0x28")

    fs_base = parse_hex_or_zero(point_a.get("fs_base"))
    tls_info = point_a.get("fs_tls", {})
    expected_address = parse_hex_or_zero(tls_info.get("address"))
    expected_value = parse_hex_or_zero(tls_info.get("value"))
    calculated_address = fs_base + FS_TLS_OFFSET

    log(f"FS base = {fs_base:#018x}")
    log(f"ожидаемый адрес = {expected_address:#018x}")
    log(f"рассчитанный адрес = {calculated_address:#018x}")

    if expected_address != 0 and calculated_address != expected_address:
        log("TLS address: ERROR")

    try:
        actual_value = int.from_bytes(
            bytes(ql.mem.read(calculated_address, 8)),
            "little",
        )

        log(f"ожидаемое значение = {expected_value:#018x}")
        log(f"Qiling значение = {actual_value:#018x}")

        if expected_value != 0 and actual_value != expected_value:
            log("FS:0x28: ERROR")
        else:
            log("FS:0x28: OK")
    except Exception as exc:
        log(f"FS:0x28: ERROR: {exc}")


def print_state(ql):
    log("ТЕКУЩЕЕ СОСТОЯНИЕ CPU")

    for name in REGISTER_NAMES:
        try:
            value = getattr(ql.arch.regs, name)
            log(f"{name:<7} = {value:#018x}")
        except Exception as exc:
            log(f"{name:<7} = <ошибка: {exc}>")

    try:
        fs = ql.uc.reg_read(UC_X86_REG_FS_BASE)
        log(f"FS_BASE = {fs:#018x}")
    except Exception as exc:
        log(f"FS_BASE = <ошибка: {exc}>")

    try:
        gs = ql.uc.reg_read(UC_X86_REG_GS_BASE)
        log(f"GS_BASE = {gs:#018x}")
    except Exception as exc:
        log(f"GS_BASE = <ошибка: {exc}>")


def verify_point_a(ql, point_a):
    log("ПРОВЕРКА POINT A")

    expected_rip = parse_int(point_a["rip"], "point_a.rip")
    actual_rip = int(ql.arch.regs.rip)

    if actual_rip == expected_rip:
        log(
            f"RIP: expected={expected_rip:#018x}, "
            f"actual={actual_rip:#018x}"
        )
    else:
        log(
            f"RIP: ERROR expected={expected_rip:#018x}, "
            f"actual={actual_rip:#018x}"
        )

    expected_rsp = parse_int(point_a["rsp"], "point_a.rsp")
    actual_rsp = int(ql.arch.regs.rsp)
    if actual_rsp != expected_rsp:
        log(
            f"RSP: ERROR expected={expected_rsp:#018x}, "
            f"actual={actual_rsp:#018x}"
        )

    expected_rbp = parse_int(point_a["rbp"], "point_a.rbp")
    actual_rbp = int(ql.arch.regs.rbp)
    if actual_rbp != expected_rbp:
        log(
            f"RBP: ERROR expected={expected_rbp:#018x}, "
            f"actual={actual_rbp:#018x}"
        )

    expected_fs = parse_hex_or_zero(point_a.get("fs_base"))
    actual_fs = ql.uc.reg_read(UC_X86_REG_FS_BASE)

    log(
        f"FS base: expected={expected_fs:#018x}, "
        f"actual={actual_fs:#018x}"
    )

    if actual_rip == expected_rip:
        log("Точка А: состояние совпадает")
    else:
        log("Точка А: состояние НЕ совпадает")


def verify_memory(ql, metadata):
    log("ПРОВЕРКА MEMORY POINT A")

    rip = metadata["rip"]

    try:
        code = bytes(ql.mem.read(rip, 16))
        log(f"код @ 0x{rip:016x}: {code.hex(' ')}")
    except Exception as exc:
        log(f"код: ERROR: {exc}")

    address = metadata["http_address"]
    received = metadata["http_received"]

    if address == 0 or received == 0:
        log("HTTP buffer: пропущен.")
        return

    try:
        data = bytes(ql.mem.read(address, received))
        log(f"HTTP buffer @ 0x{address:016x}: {data!r}")
    except Exception as exc:
        log(f"HTTP buffer: ERROR: {exc}")


def hexdump_at(ql, address, size=DEBUG_BYTES):
    try:
        start = max(0, address - size)
        data = bytes(ql.mem.read(start, size * 2))

        log(f"bytes @ 0x{start:016x}:")

        for offset in range(0, len(data), 16):
            chunk = data[offset:offset + 16]
            log(
                f"  {start + offset:016x}: "
                f"{chunk.hex(' ')}"
            )
    except Exception as exc:
        log(f"hexdump ERROR: {exc}")


def inspect_address(ql, address):
    page = address & ~(PAGE_SIZE - 1)

    log(f"Проверка адреса: 0x{address:016x}")
    log(f"Страница: 0x{page:016x}")

    try:
        data = bytes(ql.mem.read(address, 16))
        log("READ = OK")
        log(f"bytes = {data.hex(' ')}")
    except Exception as exc:
        log(f"READ = ERROR: {exc}")


def make_code_hook(ql, target_rip):
    def code_hook(ql_obj, address, size):
        STATE["instruction_count"] += 1
        STATE["recent_rips"].append(address)

        if len(STATE["recent_rips"]) > RECENT_RIPS_LIMIT:
            STATE["recent_rips"].pop(0)

        count = STATE["instruction_count"]

        if count <= TRACE_FIRST_INSTRUCTIONS:
            log(
                f"EMU #{count}: RIP=0x{address:016x}, size={size}"
            )

        if address == target_rip:
            STATE["point_b_reached"] = True
            STATE["emu_stopped_by_target"] = True

            log(f"ДОСТИГНУТ POINT B: RIP=0x{address:016x}")
            log("Целевая функция: ngx_http_free_request")

            try:
                ql_obj.emu_stop()
            except Exception as exc:
                log(f"emu_stop error: {exc}")

    return code_hook


def invalid_memory_hook(ql, access, address, size, value):
    info = {
        "access": int(access),
        "address": int(address),
        "size": int(size),
        "value": int(value),
    }

    STATE["invalid_memory"].append(info)

    log("INVALID MEMORY ACCESS")
    log(f"access  = {access}")
    log(f"address = 0x{address:016x}")
    log(f"size    = {size}")
    log(f"value   = 0x{value:x}")

    try:
        print_state(ql)
    except Exception:
        pass

    return False


def install_hooks(ql, target_rip):
    log("УСТАНОВКА HOOKS")

    code_hook = make_code_hook(ql, target_rip)

    try:
        STATE["code_hook_handle"] = ql.hook_code(code_hook)
        log("code hook установлен.")
    except Exception as exc:
        fatal(f"Не удалось установить code hook: {exc}")

    try:
        STATE["invalid_hook_handle"] = ql.hook_mem_invalid(
            invalid_memory_hook
        )
        log("memory invalid hook установлен.")
    except Exception as exc:
        log(f"memory invalid hook не установлен: {exc}")


def load_point_b():
    if not POINT_B_JSON.exists():
        log("point_b.json не найден.")
        log("Будем использовать резервный адрес Point B.")
        return {
            "function": "ngx_http_free_request",
            "rip": "0x00005555555d4d98",
        }

    point_b = load_json(POINT_B_JSON)
    rip = parse_int(point_b["rip"], "point_b.rip")
    function = point_b.get(
        "function",
        "ngx_http_free_request",
    )

    log(f"Point B function = {function}")
    log(f"Point B RIP = 0x{rip:016x}")

    return {
        "function": function,
        "rip": rip,
    }


def start_emulation(ql, start_rip):
    log("СТАРТ ЭМУЛЯЦИИ")
    log(f"start RIP = 0x{start_rip:016x}")
    log(f"max instructions = {MAX_INSTRUCTIONS}")

    STATE["emu_started"] = True

    try:
        ql.uc.emu_start(
            start_rip,
            0,
            0,
            MAX_INSTRUCTIONS,
        )

        if STATE["point_b_reached"]:
            log("Причина остановки = достигнут Point B")
        elif STATE["instruction_count"] >= MAX_INSTRUCTIONS:
            log("Причина остановки = достигнут лимит инструкций")
        else:
            log("Причина остановки = эмуляция остановлена")

    except UcError as exc:
        log("UNICORN ОСТАНОВИЛ ЭМУЛЯЦИЮ С ОШИБКОЙ")
        log(f"тип = {type(exc).__name__}")
        log(f"ошибка = {exc}")

        try:
            current_rip = int(ql.arch.regs.rip)
            log(f"текущий RIP = 0x{current_rip:016x}")
            inspect_address(ql, current_rip)
            hexdump_at(ql, current_rip)
        except Exception as state_exc:
            log(f"Ошибка получения state: {state_exc}")

    except Exception as exc:
        log("Что то неожиданное")
        log(f"{type(exc).__name__}: {exc}")
        traceback.print_exc()

    finally:
        log("СТАТИСТИКА")
        log(f"instructions = {STATE['instruction_count']}")
        log(f"Point B reached = {STATE['point_b_reached']}")


def print_recent_rips():
    log("ПОСЛЕДНИЕ RIP ПЕРЕД ОСТАНОВКОЙ")

    if not STATE["recent_rips"]:
        log("История RIP пустая.")
        return

    for index, rip in enumerate(reversed(STATE["recent_rips"]), 1):
        log(f"{index:02d}: 0x{rip:016x}")


def save_result():
    result = {
        "point_b_reached": STATE["point_b_reached"],
        "emu_stopped_by_target": STATE["emu_stopped_by_target"],
        "instruction_count": STATE["instruction_count"],
        "recent_rips": [
            f"0x{x:016x}"
            for x in STATE["recent_rips"]
        ],
        "invalid_memory": STATE["invalid_memory"],
    }

    path = CAPTURE_DIR / "load_dump_result.json"

    try:
        with path.open("w", encoding="utf-8") as f:
            json.dump(
                result,
                f,
                indent=2,
                ensure_ascii=False,
            )

        log(f"результат сохранён: {path}")
    except Exception as exc:
        log(f"не удалось сохранить result: {exc}")


def main():
    metadata = load_capture_metadata()
    point_a = metadata["point_a"]
    mappings = metadata["point_a_memory"]

    point_b = load_point_b()
    target_rip = point_b["rip"]

    ql = create_qiling()

    restore_memory_mappings(ql, mappings)

    old_avx2_address = 0x7ffff7e62fcb
    inspect_address(ql, old_avx2_address)

    restore_request_buffer(ql, metadata)
    restore_registers(ql, point_a, metadata)
    restore_segment_bases(ql, point_a)

    print_state(ql)

    verify_point_a(ql, point_a)
    verify_memory(ql, metadata)
    verify_fs_tls(ql, point_a)

    install_hooks(ql, target_rip)

    start_emulation(ql, metadata["rip"])

    print_state(ql)
    print_recent_rips()
    save_result()

    log("LOAD DUMP ЗАВЕРШЁН")

    if STATE["point_b_reached"]:
        log("РЕЗУЛЬТАТ: Пройдено с точки А до точки Б")
    else:
        log("РЕЗУЛЬТАТ: Точка Б пока НЕ достигнута")
        log("Тут надо смотреть ошибку")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("остановлено самостоятельно")
        sys.exit(130)
    except Exception as exc:
        log("Что то критическое")
        log(f"{type(exc).__name__}: {exc}")
        traceback.print_exc()
        sys.exit(1)
