#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import traceback
from pathlib import Path
from typing import Any

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions import afl
from unicorn import UcError
from unicorn.x86_const import UC_X86_REG_FS_BASE, UC_X86_REG_GS_BASE

from load_dump import (
    load_capture_metadata,
    load_point_b,
    create_qiling,
    restore_memory_mappings,
    restore_request_buffer,
    restore_registers,
    restore_segment_bases,
    verify_point_a,
    verify_memory,
    verify_fs_tls,
    print_state,
)


CAPTURE_DIR = Path("/work/capture")
POINT_A_JSON = CAPTURE_DIR / "point_a.json"
POINT_A_MEMORY_JSON = CAPTURE_DIR / "point_a_memory.json"
POINT_B_JSON = CAPTURE_DIR / "point_b.json"
REQUEST_BUFFER_FILE = CAPTURE_DIR / "request_buffer.bin"

SNAPSHOT_FILE = CAPTURE_DIR / "qiling_point_a_fuzz.snapshot"
FUZZ_METADATA_FILE = CAPTURE_DIR / "fuzz_dump_metadata.json"
FUZZ_RESULT_FILE = CAPTURE_DIR / "fuzz_dump_result.json"

DEFAULT_MAX_INSTRUCTIONS = 2_000_000
PAGE_SIZE = 0x1000
# ngx_buf_t
BUF_POS_OFFSET = 0x00
BUF_LAST_OFFSET = 0x08
BUF_START_OFFSET = 0x20
BUF_END_OFFSET = 0x28
BUF_MIN_SEARCH_SIZE = 0x30
BUF_STRUCT_SIZE = 0x50

SCAN_CHUNK_SIZE = 1024 * 1024
MAX_SCAN_MAPPING_SIZE = 256 * 1024 * 1024

TRACE_FIRST_INSTRUCTIONS = 40
RECENT_RIPS_LIMIT = 64

REGISTER_NAMES = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "eflags",
]


STATE: dict[str, Any] = {
    "point_b_reached": False,
    "trace_instructions": 0,
    "recent_rips": [],
    "invalid_memory": [],
    "accepted": 0,
    "rejected": 0,
    "iterations": 0,
}


def log(message: str = "") -> None:
    print(f"[FUZZ] {message}", flush=True)


def error(message: str) -> None:
    print(f"[FUZZ][ERROR] {message}", file=sys.stderr, flush=True)


def die(message: str, code: int = 1) -> int:
    error(message)
    return code


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def parse_int(value: Any, field: str = "value") -> int:
    if value is None:
        raise ValueError(f"{field}: значение отсутствует")
    if isinstance(value, bool):
        raise ValueError(f"{field}: bool не является допустимым целым числом")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value.strip(), 0)
    raise ValueError(f"{field}: неподдерживаемый тип {type(value)!r}")


def validate_dump_files() -> None:
    required = [
        POINT_A_JSON,
        POINT_A_MEMORY_JSON,
        POINT_B_JSON,
        REQUEST_BUFFER_FILE,
    ]
    for path in required:
        if not path.exists():
            raise RuntimeError(f"не найден обязательный файл dump: {path}")


def load_metadata() -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    meta = load_capture_metadata()
    if not isinstance(meta, dict):
        raise RuntimeError(
            "Текущий load_dump.py::load_capture_metadata() должен возвращать словарь"
        )

    point_a = meta["point_a"]
    mappings = meta["point_a_memory"]
    point_b = load_point_b()
    return point_a, mappings, point_b


def get_point_a_rip(point_a: dict[str, Any]) -> int:
    return parse_int(point_a["rip"], "point_a.rip")


def get_point_b_rip(point_b: dict[str, Any]) -> int:
    return parse_int(point_b["rip"], "point_b.rip")


def get_http_buffer_metadata(point_a: dict[str, Any]) -> tuple[int, int, int]:
    http = point_a.get("http_buffer")
    if not isinstance(http, dict):
        raise RuntimeError("в point_a.json отсутствует объект http_buffer")

    address = parse_int(http.get("address"), "http_buffer.address")
    capacity = int(http.get("capacity", 0))
    received = int(http.get("received", 0))

    if address <= 0:
        raise RuntimeError("некорректный адрес http_buffer.address")
    if capacity <= 0:
        raise RuntimeError("http_buffer.capacity должен быть больше 0")
    if received < 0 or received > capacity:
        raise RuntimeError(
            f"http_buffer.received={received} выходит за диапазон 0..{capacity}"
        )

    return address, capacity, received


def read_u64(ql: Qiling, address: int) -> int:
    return int.from_bytes(bytes(ql.mem.read(address, 8)), "little")


def write_u64(ql: Qiling, address: int, value: int) -> None:
    ql.mem.write(address, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))


def inspect_buf(ql: Qiling, addr: int) -> dict[str, int]:
    return {
        "pos": read_u64(ql, addr + BUF_POS_OFFSET),
        "last": read_u64(ql, addr + BUF_LAST_OFFSET),
        "start": read_u64(ql, addr + BUF_START_OFFSET),
        "end": read_u64(ql, addr + BUF_END_OFFSET),
    }


def print_buf(ql: Qiling, addr: int) -> dict[str, int]:
    state = inspect_buf(ql, addr)
    log(f"ngx_buf_t @ {addr:#018x}")
    log(f"  pos   = {state['pos']:#018x}")
    log(f"  last  = {state['last']:#018x}")
    log(f"  start = {state['start']:#018x}")
    log(f"  end   = {state['end']:#018x}")
    return state


def verify_buf_point_a(
    ql: Qiling,
    buf_addr: int,
    expected_start: int,
    expected_end: int,
) -> None:
    state = inspect_buf(ql, buf_addr)
    if state["pos"] != expected_start:
        raise RuntimeError(
            f"ngx_buf_t->pos = {state['pos']:#x}, ожидалось {expected_start:#x}"
        )
    if state["last"] != expected_start:
        raise RuntimeError(
            f"ngx_buf_t->last = {state['last']:#x}, ожидалось {expected_start:#x}"
        )
    if state["start"] != expected_start:
        raise RuntimeError(
            f"ngx_buf_t->start = {state['start']:#x}, ожидалось {expected_start:#x}"
        )
    if state["end"] != expected_end:
        raise RuntimeError(
            f"ngx_buf_t->end = {state['end']:#x}, ожидалось {expected_end:#x}"
        )


def mapping_bounds(mapping: dict[str, Any]) -> tuple[int, int, str]:
    start = parse_int(mapping["start"], "mapping.start")
    end = parse_int(mapping["end"], "mapping.end")
    perms = str(mapping.get("permissions", mapping.get("perms", "")))
    return start, end, perms


def find_ngx_buf_struct(
    ql: Qiling,
    mappings: list[dict[str, Any]],
    buffer_start: int,
    buffer_end: int,
) -> int:

    if buffer_end <= buffer_start:
        raise RuntimeError("buffer_end должен быть больше buffer_start")

    needle = struct.pack("<Q", buffer_start)
    candidates: set[int] = set()

    log("")
    log("ПОИСК ngx_buf_t")

    for idx, mapping in enumerate(mappings):
        try:
            start, end, perms = mapping_bounds(mapping)
        except Exception:
            continue

        if "w" not in perms:
            continue

        size = end - start
        if size < BUF_MIN_SEARCH_SIZE or size > MAX_SCAN_MAPPING_SIZE:
            continue

        carry = b""
        cursor = start

        try:
            while cursor < end:
                chunk_len = min(SCAN_CHUNK_SIZE, end - cursor)
                chunk = bytes(ql.mem.read(cursor, chunk_len))
                data = carry + chunk
                base = cursor - len(carry)

                search_from = 0
                while True:
                    pos = data.find(needle, search_from)
                    if pos < 0:
                        break

                    pointer_addr = base + pos
                    candidate = pointer_addr - BUF_START_OFFSET

                    if candidate >= start and candidate + BUF_STRUCT_SIZE <= end:
                        if candidate % 8 == 0:
                            raw = data[pos - BUF_START_OFFSET:]
                            if len(raw) >= BUF_MIN_SEARCH_SIZE:
                                pos_v = int.from_bytes(raw[0:8], "little")
                                last_v = int.from_bytes(raw[8:16], "little")
                                start_v = int.from_bytes(raw[0x20:0x28], "little")
                                end_v = int.from_bytes(raw[0x28:0x30], "little")
                                if (
                                    pos_v == buffer_start
                                    and last_v == buffer_start
                                    and start_v == buffer_start
                                    and end_v == buffer_end
                                ):
                                    candidates.add(candidate)
                    search_from = pos + len(needle)

                carry = data[-(len(needle) + BUF_MIN_SEARCH_SIZE):]
                cursor += chunk_len

        except Exception:
            continue

    log(f"Найдено кандидатов ngx_buf_t: {len(candidates)}")
    for candidate in sorted(candidates):
        log(f"  candidate = {candidate:#018x}")

    if len(candidates) != 1:
        raise RuntimeError(
            "Не удалось однозначно определить ngx_buf_t: "
            f"найдено {len(candidates)} кандидатов для buffer "
            f"{buffer_start:#018x}. "
            "Если найдено несколько кандидатов, лучше добавить адрес b в capture_dump.py."
        )

    buf_addr = next(iter(candidates))
    log(f"ngx_buf_t = {buf_addr:#018x}")
    return buf_addr


def prepare_testcase(
    ql: Qiling,
    testcase: bytes,
    point_a: dict[str, Any],
    buf_addr: int,
    buffer_start: int,
    capacity: int,
) -> bytes:
    """Поместить один testcase в текущее восстановленное состояние Qiling."""

    if len(testcase) > capacity:
        raise ValueError(
            f"testcase too large: {len(testcase)} > buffer capacity {capacity}"
        )

    if testcase:
        ql.mem.write(buffer_start, testcase)

    write_u64(ql, buf_addr + BUF_POS_OFFSET, buffer_start)
    write_u64(ql, buf_addr + BUF_LAST_OFFSET, buffer_start)

    ql.arch.regs.rax = len(testcase)

    ql.arch.regs.rip = get_point_a_rip(point_a)

    return testcase


def create_snapshot(ql: Qiling) -> None:
    SNAPSHOT_FILE.parent.mkdir(parents=True, exist_ok=True)
    if SNAPSHOT_FILE.exists():
        SNAPSHOT_FILE.unlink()

    ql.save(
        reg=True,
        mem=True,
        hw=False,
        fd=False,
        cpu_context=False,
        os=False,
        loader=False,
        snapshot=str(SNAPSHOT_FILE),
    )
    log(f"снимок сохранён: {SNAPSHOT_FILE}")


def make_invalid_memory_hook(ql: Qiling):
    def invalid_memory(
        _ql: Qiling,
        access: int,
        address: int,
        size: int,
        value: int,
    ) -> bool:
        info = {
            "access": int(access),
            "address": int(address),
            "size": int(size),
            "value": int(value),
        }
        STATE["invalid_memory"].append(info)

        error(
            "INVALID MEMORY: "
            f"access={access} address={address:#018x} "
            f"size={size} value={value:#x}"
        )
        try:
            log(f"current RIP = {ql.arch.regs.rip:#018x}")
        except Exception:
            pass
        return False

    return invalid_memory


def make_trace_hook(ql: Qiling, point_b_rip: int):
    def trace_hook(_ql: Qiling, address: int, size: int) -> None:
        STATE["trace_instructions"] += 1
        STATE["recent_rips"].append(address)
        STATE["recent_rips"] = STATE["recent_rips"][-RECENT_RIPS_LIMIT:]

        count = STATE["trace_instructions"]
        if count <= TRACE_FIRST_INSTRUCTIONS:
            log(f"EMU #{count}: RIP={address:#018x}, size={size}")

        if address == point_b_rip:
            STATE["point_b_reached"] = True
            log(f"POINT B reached at {address:#018x}")
            _ql.uc.emu_stop()

    return trace_hook


def install_diagnostics(ql: Qiling) -> None:
    try:
        ql.hook_mem_invalid(make_invalid_memory_hook(ql))
        log("hook недопустимой памяти установлен")
    except Exception as exc:
        log(f"hook недопустимой памяти недоступен: {exc}")


def prepare_harness() -> tuple[Qiling, dict[str, Any], list[dict[str, Any]], dict[str, Any], int, int, int]:
    validate_dump_files()

    point_a, mappings, point_b = load_metadata()

    point_a_rip = get_point_a_rip(point_a)
    point_b_rip = get_point_b_rip(point_b)
    buffer_start, capacity, received = get_http_buffer_metadata(point_a)
    buffer_end = buffer_start + capacity

    if point_a_rip == point_b_rip:
        raise RuntimeError("Point A and Point B RIP are identical")

    log("PREPARE DUMP-BASED FUZZ HARNESS")
    log(f"Point A = {point_a_rip:#018x}")
    log(f"Point B = {point_b_rip:#018x}")
    log(f"HTTP buffer = {buffer_start:#018x}")
    log(f"HTTP capacity = {capacity}")
    log(f"Captured request length = {received}")

    ql = create_qiling()
    try:
        ql.bindtolocalhost = True
    except Exception:
        pass

    try:
        ql.debug_stop = False
    except Exception:
        pass

    restore_memory_mappings(ql, mappings)
    restore_request_buffer(ql, {
        "point_a": point_a,
        "http_address": buffer_start,
        "http_received": received,
        "http_capacity": capacity,
    })
    restore_registers(ql, point_a, {
        "point_a": point_a,
        "rip": point_a_rip,
        "rsp": parse_int(point_a["rsp"], "point_a.rsp"),
        "rbp": parse_int(point_a["rbp"], "point_a.rbp"),
    })
    restore_segment_bases(ql, point_a)

    log("Проверка восстановленного CPU/memory state...")
    print_state(ql)
    verify_point_a(ql, point_a)
    verify_memory(ql, {
        "rip": point_a_rip,
        "http_address": buffer_start,
        "http_received": received,
    })
    verify_fs_tls(ql, point_a)

    for name, addr in (
        ("Point A RIP", point_a_rip),
        ("Point B RIP", point_b_rip),
        ("HTTP buffer", buffer_start),
        ("RSP", parse_int(point_a["rsp"], "point_a.rsp")),
    ):
        try:
            if not ql.mem.is_mapped(addr, 1):
                raise RuntimeError(f"{name} {addr:#018x} is not mapped in Qiling")
        except Exception as exc:
            raise RuntimeError(f"mapping check failed for {name}: {exc}") from exc

    buf_addr = find_ngx_buf_struct(
        ql,
        mappings,
        buffer_start,
        buffer_end,
    )

    verify_buf_point_a(
        ql,
        buf_addr,
        buffer_start,
        buffer_end,
    )
    print_buf(ql, buf_addr)

    create_snapshot(ql)

    save_json(
        FUZZ_METADATA_FILE,
        {
            "point_a": {
                "function": point_a.get("function"),
                "rip": point_a["rip"],
                "rsp": point_a["rsp"],
                "rbp": point_a["rbp"],
            },
            "point_b": {
                "function": point_b.get("function"),
                "rip": point_b["rip"],
            },
            "http_buffer": {
                "address": f"0x{buffer_start:016x}",
                "capacity": capacity,
                "captured_length": received,
            },
            "ngx_buf_t": {
                "address": f"0x{buf_addr:016x}",
                "pos_offset": "0x00",
                "last_offset": "0x08",
                "start_offset": "0x20",
                "end_offset": "0x28",
            },
            "model": {
                "point_a_before_last_increment": True,
                "resume_pos_equals_start": True,
                "resume_last_equals_start": True,
                "resume_rax_equals_recv_length": True,
            },
            "snapshot": str(SNAPSHOT_FILE),
        },
    )

    install_diagnostics(ql)

    return ql, point_a, mappings, point_b, buf_addr, buffer_start, capacity


def run_one_shot(
    ql: Qiling,
    point_a: dict[str, Any],
    point_b: dict[str, Any],
    buf_addr: int,
    buffer_start: int,
    capacity: int,
    input_path: Path,
    max_instructions: int,
) -> bool:
    testcase = input_path.read_bytes()
    if len(testcase) > capacity:
        log(
            f"testcase {len(testcase)} > capacity {capacity}; "
            "one-shot rejected"
        )
        return False

    point_a_rip = get_point_a_rip(point_a)
    point_b_rip = get_point_b_rip(point_b)

    log("")
    log("ОДИНОЧНАЯ ПРОВЕРКА")
    log(f"input = {input_path}")
    log(f"length = {len(testcase)}")
    log(f"Point A = {point_a_rip:#018x}")
    log(f"Point B = {point_b_rip:#018x}")

    if SNAPSHOT_FILE.exists():
        ql.restore(snapshot=str(SNAPSHOT_FILE))

    install_diagnostics(ql)

    prepare_testcase(
        ql,
        testcase,
        point_a,
        buf_addr,
        buffer_start,
        capacity,
    )

    verify_buf_point_a(ql, buf_addr, buffer_start, buffer_start + capacity)
    log(f"RAX = {ql.arch.regs.rax:#x}")
    log(f"RIP = {ql.arch.regs.rip:#018x}")
    print_buf(ql, buf_addr)

    STATE["point_b_reached"] = False
    STATE["trace_instructions"] = 0
    STATE["recent_rips"] = []
    STATE["invalid_memory"] = []

    hook = ql.hook_code(make_trace_hook(ql, point_b_rip))

    try:
        ql.uc.emu_start(
            point_a_rip,
            0,
            0,
            max_instructions,
        )
    except UcError as exc:
        log(f"Unicorn error: {type(exc).__name__}: {exc}")
    except Exception as exc:
        log(f"Execution error: {type(exc).__name__}: {exc}")
        traceback.print_exc()
    finally:
        try:
            ql.hook_del(hook)
        except Exception:
            pass

    current_rip = int(ql.arch.regs.rip)

    log("")
    log("РЕЗУЛЬТАТ ОДИНОЧНОЙ ПРОВЕРКИ")
    log(f"instructions = {STATE['trace_instructions']}")
    log(f"final RIP    = {current_rip:#018x}")
    log(f"Point B      = {point_b_rip:#018x}")
    log(f"Point B reached = {STATE['point_b_reached']}")

    if STATE["recent_rips"]:
        log("Recent RIPs:")
        for rip in reversed(STATE["recent_rips"]):
            log(f"  {rip:#018x}")

    return bool(STATE["point_b_reached"])


def start_afl(
    ql: Qiling,
    point_a: dict[str, Any],
    point_b: dict[str, Any],
    buf_addr: int,
    buffer_start: int,
    capacity: int,
    input_file: Path,
) -> None:

    point_a_rip = get_point_a_rip(point_a)
    point_b_rip = get_point_b_rip(point_b)

    def place_input_callback(
        current_ql: Qiling,
        input_data: bytes,
        persistent_round: int,
    ) -> bool:
        del persistent_round

        STATE["iterations"] += 1

        try:
            testcase = bytes(input_data)

            if len(testcase) > capacity:
                STATE["rejected"] += 1
                if os.environ.get("QILING_AFL_LOG_REJECT", "0") == "1":
                    log(
                        f"reject testcase {len(testcase)} > capacity {capacity}"
                    )
                return False

            prepare_testcase(
                current_ql,
                testcase,
                point_a,
                buf_addr,
                buffer_start,
                capacity,
            )

            STATE["accepted"] += 1

            if os.environ.get("QILING_AFL_LOG_INPUT", "0") == "1":
                log(
                    f"iteration={STATE['iterations']} testcase={len(testcase)}"
                )

            return True

        except Exception as exc:
            error(
                "ошибка place_input_callback: "
                f"{type(exc).__name__}: {exc}"
            )
            traceback.print_exc()
            return False

    log("")
    log("ЗАПУСК AFL++")
    log(f"input_file = {input_file}")
    log(f"Point A = {point_a_rip:#018x}")
    log(f"Point B = {point_b_rip:#018x}")
    log("ql_afl_fuzz() ql.run() намеренно не используется.")

    ql.arch.regs.rip = point_a_rip

    try:
        result = afl.ql_afl_fuzz(
            ql,
            input_file=str(input_file),
            place_input_callback=place_input_callback,
            exits=[point_b_rip],
            persistent_iters=1,
        )

        log(f"ql_afl_fuzz завершён: {result!r}")

    except Exception as exc:
        error(
            "ошибка ql_afl_fuzz: "
            f"{type(exc).__name__}: {exc}"
        )
        traceback.print_exc()
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Фаззинг NGINX из dump через Qiling и AFL++"
    )
    parser.add_argument(
        "input_file",
        help="Файл входа AFL через @@; в режиме --trace укажите существующий seed",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Выполнить один testcase от Point A до Point B без запуска AFL",
    )
    parser.add_argument(
        "--max-instructions",
        type=int,
        default=DEFAULT_MAX_INSTRUCTIONS,
        help=f"Лимит инструкций для --trace (по умолчанию: {DEFAULT_MAX_INSTRUCTIONS})",
    )
    return parser.parse_args()


def write_final_result(exit_code: int | None = None) -> None:
    payload = {
        "point_b_reached": bool(STATE["point_b_reached"]),
        "iterations": int(STATE["iterations"]),
        "accepted": int(STATE["accepted"]),
        "rejected": int(STATE["rejected"]),
        "trace_instructions": int(STATE["trace_instructions"]),
        "recent_rips": [f"0x{x:016x}" for x in STATE["recent_rips"]],
        "invalid_memory": STATE["invalid_memory"],
    }
    if exit_code is not None:
        payload["exit_code"] = exit_code
    try:
        save_json(FUZZ_RESULT_FILE, payload)
    except Exception as exc:
        error(f"не удалось сохранить {FUZZ_RESULT_FILE}: {exc}")


def main() -> int:
    args = parse_args()
    input_file = Path(args.input_file)

    if args.trace:
        if not input_file.exists():
            return die(f"файл входа не найден: {input_file}")
        if not input_file.is_file():
            return die(f"путь входа не является обычным файлом: {input_file}")

    if args.max_instructions <= 0:
        return die("--max-instructions должен быть больше 0")

    try:
        ql, point_a, _mappings, point_b, buf_addr, buffer_start, capacity = prepare_harness()

        if args.trace:
            ok = run_one_shot(
                ql,
                point_a,
                point_b,
                buf_addr,
                buffer_start,
                capacity,
                input_file,
                args.max_instructions,
            )
            write_final_result(0 if ok else 2)
            if ok:
                log("ОДИНОЧНАЯ ПРОВЕРКА УСПЕШНА: Point A -> Point B")
                return 0
            log("ОДИНОЧНАЯ ПРОВЕРКА НЕУСПЕШНА: Point B не достигнут")
            return 2

        start_afl(
            ql,
            point_a,
            point_b,
            buf_addr,
            buffer_start,
            capacity,
            input_file,
        )
        write_final_result(0)
        return 0

    except KeyboardInterrupt:
        log("Самостоятельно остановил")
        write_final_result(130)
        return 130
    except SystemExit:
        raise
    except Exception as exc:
        error(f"{type(exc).__name__}: {exc}")
        traceback.print_exc()
        write_final_result(1)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
