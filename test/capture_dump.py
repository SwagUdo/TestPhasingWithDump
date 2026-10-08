#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import socket
import struct
import shutil
import threading

import gdb


# Настройки NGINX и результаты
NGINX_BIN = "/usr/sbin/nginx"
NGINX_CONF = "/etc/nginx/nginx.conf"

HOST = "127.0.0.1"
PORT = 8080

OUTPUT_DIR = "/work/capture"
MEMORY_DIR = os.path.join(
    OUTPUT_DIR,
    "point_a_memory",
)


# Отключение AVX2
GLIBC_TUNABLES_VALUE = (
    "glibc.cpu.hwcaps="
    "-AVX2,"
    "-AVX_Fast_Unaligned_Load"
)


# Исходный HTTP-запрос
REQUEST = (
    b"GET / HTTP/1.1\r\n"
    b"Host: fuzz\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

CONNECT_ATTEMPTS = 100
CONNECT_DELAY = 0.2
SOCKET_HOLD_TIME = 10.0


# Память
MAX_MAPPING_SIZE = 256 * 1024 * 1024
MEMORY_CHUNK_SIZE = 1024 * 1024


# Смещение TLS Thread Local Storage (stack canary)
# info registers fs
# objdump -d -M intel /usr/sbin/nginx
FS_TLS_OFFSET = 0x28


# Регистры
REGISTERS = [
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

# выводит сообщение в консоль  [CAPTURE] и сразу принудительно обновляет вывод
def log(message=""):
    print(f"[CAPTURE] {message}")
    sys.stdout.flush()

# удаление старой папки с результатами и создание снова папки для сохранения дампа памяти
def prepare_output_directory():
    if os.path.exists(OUTPUT_DIR):
        log(f"Удаляем старый {OUTPUT_DIR} ...")
        shutil.rmtree(OUTPUT_DIR)

    os.makedirs(
        MEMORY_DIR,
        exist_ok=True,
    )

# сохранение переданного текста в указанный файл внутри папки с результатами
def save_text(filename, content):
    path = os.path.join(
        OUTPUT_DIR,
        filename,
    )

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as f:
        f.write(content)

    return path

# сохранение переданных данных в JSON-файл внутри папки с результатами 
def save_json(filename, data):
    path = os.path.join(
        OUTPUT_DIR,
        filename,
    )

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            data,
            f,
            indent=2,
            ensure_ascii=False,
        )

    return path

#чтение значений основных регистров через GDB и сохранение их
def read_registers():
    result = {}

    for reg in REGISTERS:
        try:
            value = int(
                gdb.parse_and_eval(
                    f"${reg}"
                )
            )

            result[reg] = f"0x{value:016x}"

        except Exception as exc:
            log(f"Ошибка чтения ${reg}: {exc}")
            result[reg] = None

    return result

#получение значений регистров и сохранение их одновременно в JSON и текст
def save_registers(prefix):
    registers = read_registers()

    save_json(
        f"{prefix}_registers.json",
        registers,
    )

    lines = []

    for reg in REGISTERS:
        value = registers.get(reg)

        if value is None:
            lines.append(f"{reg:<8} = <error>")
        else:
            lines.append(f"{reg:<8} = {value}")

    save_text(
        f"{prefix}_registers.txt",
        "\n".join(lines) + "\n",
    )

    return registers

#чтение адресов FS и GS получение значения по адресу (FS + 0x28)
def read_fs_gs_tls():
    try:
        fs_base = int(
            gdb.parse_and_eval(
                "$fs_base"
            )
        )
    except Exception as exc:
        log(f"Ошибка чтения FS_BASE: {exc}")
        fs_base = 0

    try:
        gs_base = int(
            gdb.parse_and_eval(
                "$gs_base"
            )
        )
    except Exception as exc:
        log(f"Ошибка чтения GS_BASE: {exc}")
        gs_base = 0

    tls_address = fs_base + FS_TLS_OFFSET
    tls_value = None

    try:
        inferior = gdb.selected_inferior()
        data = inferior.read_memory(
            tls_address,
            8,
        )

        tls_value = struct.unpack(
            "<Q",
            bytes(data),
        )[0]

    except Exception as exc:
        log(f"Ошибка чтения FS:0x28: {exc}")

    return {
        "fs_base": f"0x{fs_base:016x}",
        "gs_base": f"0x{gs_base:016x}",
        "fs_tls": {
            "offset": f"0x{FS_TLS_OFFSET:x}",
            "address": f"0x{tls_address:016x}",
            "value": (
                None
                if tls_value is None
                else f"0x{tls_value:016x}"
            ),
        },
    }

#получение вызовов на текущий момент в GDB
def save_backtrace(prefix):
    try:
        text = gdb.execute(
            "bt",
            to_string=True,
        )
    except Exception as exc:
        text = f"Ошибка получения backtrace: {exc}\n"

    save_text(
        f"{prefix}_backtrace.txt",
        text,
    )

    return text

#получение инструкции по адресу RIP и все с ним связанное
def save_location(prefix):
    result = []

    try:
        result.append(
            gdb.execute(
                "x/i $rip",
                to_string=True,
            )
        )
    except Exception as exc:
        result.append(f"Ошибка x/i: {exc}\n")

    try:
        result.append(
            gdb.execute(
                "info line *$rip",
                to_string=True,
            )
        )
    except Exception as exc:
        result.append(f"Ошибка info line: {exc}\n")

    save_text(
        f"{prefix}_location.txt",
        "\n".join(result),
    )

#чтение /proc/<pid>/maps, разбор областей памяти процесса, попытка создать список
def parse_proc_maps(pid):
    path = f"/proc/{pid}/maps"
    mappings = []

    with open(
        path,
        "r",
        encoding="utf-8",
        errors="replace",
    ) as f:
        for line in f:
            line = line.rstrip("\n")

            if not line:
                continue

            parts = line.split(None, 5)

            if len(parts) < 5:
                continue

            address_range = parts[0]
            permissions = parts[1]
            offset = parts[2]
            device = parts[3]
            inode = parts[4]

            pathname = ""

            if len(parts) >= 6:
                pathname = parts[5]

            start_str, end_str = address_range.split("-", 1)

            start = int(start_str, 16)
            end = int(end_str, 16)

            mappings.append(
                {
                    "start": f"0x{start:016x}",
                    "end": f"0x{end:016x}",
                    "size": end - start,
                    "permissions": permissions,
                    "offset": int(offset, 16),
                    "device": device,
                    "inode": int(inode),
                    "pathname": pathname,
                }
            )

    return mappings

#сбор информации карты памяти процесса
def save_proc_maps(pid):
    maps_path = f"/proc/{pid}/maps"

    with open(
        maps_path,
        "r",
        encoding="utf-8",
        errors="replace",
    ) as f:
        maps_text = f.read()

    save_text(
        "point_a_maps.txt",
        maps_text,
    )

    mappings = parse_proc_maps(pid)

    save_json(
        "point_a_maps.json",
        mappings,
    )

    return mappings

#поиск в вызовах "кадры" относящиеся к нужной функции
def find_frame(function_name):
    frame = gdb.newest_frame()

    while frame is not None:
        try:
            name = frame.name() or ""

            if function_name in name:
                return frame

        except Exception:
            pass

        frame = frame.older()

    return None

#поиск HTTP-буфера NGINX из RAX
def get_http_buffer():
    frame = find_frame(
        "ngx_http_wait_request_handler"
    )

    if frame is None:
        raise RuntimeError(
            "Кадр ngx_http_wait_request_handler не найден"
        )

    b_value = None

    try:
        b_value = frame.read_var("b")
    except Exception:
        b_value = None

    if b_value is None:
        try:
            c_value = frame.read_var("c")
            c_object = c_value.dereference()
            b_value = c_object["buffer"]
        except Exception as exc:
            raise RuntimeError(
                f"Не удалось получить ngx_buf_t: {exc}"
            )

    b_object = b_value.dereference()

    start = int(b_object["start"])
    pos = int(b_object["pos"])
    last = int(b_object["last"])
    end = int(b_object["end"])

    received = int(
        gdb.parse_and_eval(
            "$rax"
        )
    )

    capacity = end - start

    if received < 0:
        received = 0

    if received > capacity:
        log("значение RAX превышает размер буфера")

        fallback = last - start

        if 0 <= fallback <= capacity:
            received = fallback

    return {
        "frame_function": frame.name(),
        "address": start,
        "pos": pos,
        "last": last,
        "end": end,
        "capacity": capacity,
        "received": received,
    }

#чтение содержимого HTTP-буфера 
def save_http_buffer(buffer_info):
    address = buffer_info["address"]
    received = buffer_info["received"]
    capacity = buffer_info["capacity"]

    inferior = gdb.selected_inferior()

    raw = inferior.read_memory(
        address,
        received,
    )

    data = bytes(raw)

    with open(
        os.path.join(
            OUTPUT_DIR,
            "request_buffer.bin",
        ),
        "wb",
    ) as f:
        f.write(data)

    text = data.decode(
        "utf-8",
        errors="replace",
    )

    return {
        "address": f"0x{address:016x}",
        "capacity": capacity,
        "received": received,
        "data_hex": data.hex(),
        "data_text": text,
    }

#сохранение содержимого всего в Точку А в отдельные бинарные файлы
def save_memory_dump(pid, mappings):
    inferior = gdb.selected_inferior()
    memory_entries = []

    total_bytes = 0
    readable_saved = 0
    readable_failed = 0

    log("")
    log("Сохранение памяти Point A")

    for index, mapping in enumerate(mappings):
        permissions = mapping["permissions"]

        if not permissions.startswith("r"):
            continue

        start = int(mapping["start"], 16)
        end = int(mapping["end"], 16)
        size = end - start

        if size <= 0:
            continue

        if size > MAX_MAPPING_SIZE:
            log(
                f"[{index}] Пропуск слишком большого mapping: {size} байт"
            )
            readable_failed += 1
            continue

        filename = (
            f"{index:04d}_"
            f"{start:016x}_"
            f"{end:016x}.bin"
        )

        relative_path = os.path.join(
            "point_a_memory",
            filename,
        )

        absolute_path = os.path.join(
            OUTPUT_DIR,
            relative_path,
        )

        log(
            f"[{index}] "
            f"0x{start:016x}-0x{end:016x} "
            f"size={size} "
            f"permissions={permissions}"
        )

        try:
            with open(
                absolute_path,
                "wb",
            ) as out:
                current = start

                while current < end:
                    chunk_size = min(
                        MEMORY_CHUNK_SIZE,
                        end - current,
                    )

                    data = inferior.read_memory(
                        current,
                        chunk_size,
                    )

                    data = bytes(data)
                    out.write(data)
                    current += chunk_size
                    total_bytes += len(data)

            entry = dict(mapping)
            entry["file"] = relative_path
            memory_entries.append(entry)
            readable_saved += 1

            log(
                f"  -> dump сохранён: {relative_path} ({size} байт)"
            )

        except Exception as exc:
            readable_failed += 1

            try:
                if os.path.exists(absolute_path):
                    os.remove(absolute_path)
            except Exception:
                pass

            log(
                f"  -> mapping не сохранён: {exc}"
            )

    save_json(
        "point_a_memory.json",
        memory_entries,
    )

    log("")
    log("Итог сохранения памяти Точки А")
    log(f"readable mappings сохранено: {readable_saved}")
    log(f"readable mappings с ошибкой: {readable_failed}")
    log(f"сохранено байт: {total_bytes}")

    return (
        memory_entries,
        total_bytes,
        readable_failed,
    )

#сбор состояния NGINX на основе всего, что сохранилось в Точке А
#регистры, TLS, вызовы
def capture_point_a():
    log("")
    log("Достигнут Point A")

    inferior = gdb.selected_inferior()
    pid = inferior.pid

    log(f"PID = {pid}")

    if pid <= 0:
        raise RuntimeError("Некорректный PID")

    registers = save_registers("point_a")
    fs_info = read_fs_gs_tls()

    save_backtrace("point_a")
    save_location("point_a")

    buffer_info = get_http_buffer()

    log(
        f"HTTP buffer = 0x{buffer_info['address']:016x}"
    )
    log(
        f"capacity = {buffer_info['capacity']}"
    )
    log(
        f"received = {buffer_info['received']}"
    )

    request_info = save_http_buffer(buffer_info)

    log(
        f"request = {request_info['data_text']!r}"
    )

    mappings = save_proc_maps(pid)

    rip = int(
        gdb.parse_and_eval(
            "$rip"
        )
    )

    rsp = int(
        gdb.parse_and_eval(
            "$rsp"
        )
    )

    rbp = int(
        gdb.parse_and_eval(
            "$rbp"
        )
    )

    point_a = {
        "function": "ngx_http_wait_request_handler",
        "original_pid": pid,
        "pid": pid,
        "rip": f"0x{rip:016x}",
        "rsp": f"0x{rsp:016x}",
        "rbp": f"0x{rbp:016x}",
        "fs_base": fs_info["fs_base"],
        "gs_base": fs_info["gs_base"],
        "fs_tls": fs_info["fs_tls"],
        "http_buffer": {
            "address": request_info["address"],
            "capacity": request_info["capacity"],
            "received": request_info["received"],
            "data_hex": request_info["data_hex"],
            "data_text": request_info["data_text"],
        },
        "http_buffer_address": request_info["address"],
        "http_buffer_capacity": request_info["capacity"],
        "http_received": request_info["received"],
        "http_request": request_info["data_text"],
        "registers": registers,
        "memory_mappings_total": len(mappings),
        "environment": {
            "GLIBC_TUNABLES": GLIBC_TUNABLES_VALUE,
        },
    }

    save_json(
        "point_a.json",
        point_a,
    )

    (
        memory_entries,
        total_bytes,
        failed_mappings,
    ) = save_memory_dump(
        pid,
        mappings,
    )

    point_a["memory_dump"] = {
        "mappings_total": len(mappings),
        "mappings_saved": len(memory_entries),
        "mappings_failed": failed_mappings,
        "bytes_saved": total_bytes,
    }

    save_json(
        "point_a.json",
        point_a,
    )

    log("")
    log("Point A сохранён")
    log(f"PID = {pid}")
    log(f"RIP = 0x{rip:016x}")
    log(f"RSP = 0x{rsp:016x}")
    log(f"RBP = 0x{rbp:016x}")
    log(f"FS base = {fs_info['fs_base']}")
    log(f"GS base = {fs_info['gs_base']}")
    log(f"FS:0x28 = {fs_info['fs_tls']['value']}")
    log(f"HTTP buffer = {request_info['address']}")
    log(f"HTTP bytes = {request_info['received']}")
    log(f"memory saved = {len(memory_entries)} mappings")
    log(f"memory bytes = {total_bytes}")

#сбор и сохранение состояния NGINX в Точку Б
def capture_point_b():
    log("")
    log("Point B")

    pid = gdb.selected_inferior().pid

    registers = save_registers("point_b")
    save_backtrace("point_b")
    save_location("point_b")

    rip = int(
        gdb.parse_and_eval(
            "$rip"
        )
    )

    rsp = int(
        gdb.parse_and_eval(
            "$rsp"
        )
    )

    rbp = int(
        gdb.parse_and_eval(
            "$rbp"
        )
    )

    request_ptr = int(
        gdb.parse_and_eval(
            "$rdi"
        )
    )

    point_b = {
        "function": "ngx_http_free_request",
        "original_pid": pid,
        "pid": pid,
        "rip": f"0x{rip:016x}",
        "rsp": f"0x{rsp:016x}",
        "rbp": f"0x{rbp:016x}",
        "request": f"0x{request_ptr:016x}",
        "registers": registers,
    }

    save_json(
        "point_b.json",
        point_b,
    )

    log(f"PID = {pid}")
    log(f"RIP = 0x{rip:016x}")
    log(f"request = 0x{request_ptr:016x}")

#Этот класс должен поключится к NGINX, отправить запрос и держать соединение
class HttpClientThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)

        self.connected = False
        self.finished = False
        self.error = None

    def run(self):
        log("")
        log("HTTP-клиент: запуск")

        sock = None

        try:
            for attempt in range(
                1,
                CONNECT_ATTEMPTS + 1,
            ):
                try:
                    sock = socket.socket(
                        socket.AF_INET,
                        socket.SOCK_STREAM,
                    )

                    sock.settimeout(1.0)

                    sock.connect(
                        (
                            HOST,
                            PORT,
                        )
                    )

                    self.connected = True

                    log(
                        "HTTP-клиент: подключение успешно "
                        f"попытка={attempt}"
                    )

                    break

                except Exception as exc:
                    try:
                        sock.close()
                    except Exception:
                        pass

                    sock = None

                    if attempt == CONNECT_ATTEMPTS:
                        raise RuntimeError(
                            "Не удалось подключиться "
                            f"к {HOST}:{PORT}: {exc}"
                        )

                    time.sleep(CONNECT_DELAY)

            if sock is None:
                raise RuntimeError("Socket отсутствует")

            log(
                f"HTTP-клиент: отправляет {len(REQUEST)} байт"
            )

            sock.sendall(REQUEST)

            log(
                f"HTTP-клиент: запрос отправлен {REQUEST!r}"
            )

            deadline = time.time() + SOCKET_HOLD_TIME

            while time.time() < deadline:
                try:
                    sock.settimeout(0.5)
                    data = sock.recv(4096)

                    if not data:
                        break

                except socket.timeout:
                    continue

                except Exception:
                    break

        except Exception as exc:
            self.error = exc
            log(f"HTTP-клиент: ошибка {exc}")

        finally:
            try:
                if sock is not None:
                    sock.close()
            except Exception:
                pass

            self.finished = True
            log("HTTP-клиент: завершён")

# Здесь хранение состояния
class CaptureState:
    def __init__(self):
        self.point_a_captured = False
        self.point_b_captured = False
        self.finish_pending = False
        self.recv_breakpoint = None
        self.process_breakpoint = None
        self.point_b_breakpoint = None

# как только дойдет до ngx_unix_recv(), остановка
class PointAFinishBreakpoint(gdb.FinishBreakpoint):
    def __init__(self, state):
        super().__init__(internal=True)
        self.state = state

    def stop(self):
        self.state.finish_pending = False

        if self.state.point_a_captured:
            return False

        self.state.point_a_captured = True

        log("")
        log("После ngx_unix_recv()")

        if self.state.recv_breakpoint is not None:
            self.state.recv_breakpoint.enabled = False

        try:
            capture_point_a()
        except Exception as exc:
            log(
                "Критическая ошибка Point A: "
                f"{exc}"
            )
            return True

        log("Point A сохранён.")
        log("Идет NGINX до Point B...")

        return False

# Должен увидеть вызов ngx_unix_recv() для остановки
class NgxUnixRecvBreakpoint(gdb.Breakpoint):
    def __init__(self, state):
        super().__init__(
            "ngx_unix_recv",
            type=gdb.BP_BREAKPOINT,
            internal=False,
        )

        self.state = state

        log(
            "останова ngx_unix_recv."
        )

    def stop(self):
        if self.state.point_a_captured:
            return False

        if self.state.finish_pending:
            return False

        log(
            "Найден ngx_unix_recv "
            "устанавливается точка возврата"
        )

        try:
            self.state.finish_pending = True
            PointAFinishBreakpoint(self.state)
        except Exception as exc:
            self.state.finish_pending = False
            log(
                "Ошибка "
                f"{exc}"
            )
            return True

        return False

#просмотр момента когда NGINX обрабатывает http
class ObserveProcessRequestBreakpoint(gdb.Breakpoint):
    def __init__(self, state):
        super().__init__(
            "ngx_http_process_request",
            type=gdb.BP_BREAKPOINT,
            internal=False,
        )

        self.state = state

        log(
            "Точка наблюдения"
            "ngx_http_process_request."
        )

    def stop(self):
        if self.state.point_a_captured:
            log(
                "Достигнута ngx_http_process_request."
            )

        return False

#Остановка для Точки Б
class PointBBreakpoint(gdb.Breakpoint):
    def __init__(self, state):
        super().__init__(
            "ngx_http_free_request",
            type=gdb.BP_BREAKPOINT,
            internal=False,
        )

        self.state = state

        log(
            "Остановка ngx_http_free_request."
        )

    def stop(self):
        if not self.state.point_a_captured:
            return False

        if self.state.point_b_captured:
            return True

        self.state.point_b_captured = True
        capture_point_b()

        log("")
        log("Дошли до Точки Б")

        return True

# настройка GDB 
def configure_gdb():
    commands = [
        "set pagination off",
        "set confirm off",
        "set disable-randomization on",
        "set breakpoint pending on",
        "set detach-on-fork on",
        "set follow-fork-mode child",
        "handle SIGPIPE nostop noprint pass",
        "set environment GLIBC_TUNABLES " + GLIBC_TUNABLES_VALUE,
        f"set args -c {NGINX_CONF}",
    ]

    for command in commands:
        try:
            gdb.execute(
                command,
                to_string=True,
            )
        except Exception as exc:
            log(
                f"не выполнилась команда GDB "
                f"'{command}': {exc}"
            )

    try:
        text = gdb.execute(
            "show environment GLIBC_TUNABLES",
            to_string=True,
        )

        save_text(
            "capture_environment.txt",
            text,
        )

        log(text.strip())

    except Exception as exc:
        log(
            f"не получилось сохранить окружение {exc}"
        )

#сохранение итог всех действий JSON-файл.
def save_capture_result(state, http_client):
    result = {
        "point_a_captured": state.point_a_captured,
        "point_b_captured": state.point_b_captured,
        "http_connected": http_client.connected,
        "http_error": (
            None
            if http_client.error is None
            else str(http_client.error)
        ),
        "environment": {
            "GLIBC_TUNABLES": GLIBC_TUNABLES_VALUE,
        },
    }

    save_json(
        "capture_result.json",
        result,
    )

#запуск всего
def main():
    log("NGINX DUMP CAPTURE")
    log(
        f"GLIBC_TUNABLES = {GLIBC_TUNABLES_VALUE}"
    )

    prepare_output_directory()
    configure_gdb()

    state = CaptureState()

    state.recv_breakpoint = NgxUnixRecvBreakpoint(state)
    state.process_breakpoint = ObserveProcessRequestBreakpoint(state)
    state.point_b_breakpoint = PointBBreakpoint(state)

    http_client = HttpClientThread()
    http_client.start()

    log("")
    log("Запуск NGINX")
    log(f"binary = {NGINX_BIN}")
    log(f"config = {NGINX_CONF}")
    log(
        f"GLIBC_TUNABLES = {GLIBC_TUNABLES_VALUE}"
    )

    try:
        gdb.execute("run")
    except gdb.error as exc:
        log(f"GDB run завершился: {exc}")
    except Exception as exc:
        log(f"ошибка GDB: {exc}")

    log("")
    log("GDB run завершён")
    log(f"Point A captured = {state.point_a_captured}")
    log(f"Point B captured = {state.point_b_captured}")

    if http_client.error is not None:
        log(f"HTTP error = {http_client.error}")

    save_capture_result(
        state,
        http_client,
    )

    if state.point_a_captured and state.point_b_captured:
        log("")
        log("Захват успешен")

    elif state.point_a_captured:
        log("")
        log("Точка А есть, Точка Б не достигнута")

    else:
        log("")
        log("Точка А не достигнута")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Самостоятельно остановлено")
        sys.exit(130)
    except Exception as exc:
        log(
            "ошибка: "
            f"{type(exc).__name__}: {exc}"
        )

        import traceback
        traceback.print_exc()
        sys.exit(1)
