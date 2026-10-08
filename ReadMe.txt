Фаззинг на основе NGINX через GDB Qiling/Unicorn и AFL++

Здесь реализуется фаззинг NGINX на основе ранее сохранённого состояния
Точка A выбрана после возврата из ngx_unix_recv(). Поэтому перед продолжением эмуляции для нового testcase выполняется:
b->pos  = b->start
b->last = b->start
RAX = длина (49)
RIP = точка а
Все основные зависимости устанавливаются из Докерфайла

Внутри контейнера файлы доступны как:
/work/capture_dump.py
/work/load_dump.py
/work/fuzz_dump.py
/work/capture/

1.
Сборка Docker

Открыть PowerShell в корне проекта:
cd C:\Users\<USER>\OneDrive\Desktop\FuzzWIthDumpGDB
Собрать образ

docker build -t nginx-dump-fuzz .

Проверить наличие образа

docker images nginx-dump-fuzz

проверка установленных инструментов

AFL++

/opt/AFLplusplus/afl-fuzz -V

UnicornAFL

python3 -c "import unicornafl; print('unicornafl OK')"

Qiling

python3 -c "import qiling; print(getattr(qiling, '__version__', '<unknown>'))"

2.
Запуск контейнера

Перейти в папку test

cd test

Запустить контейнер
Перед работой нужно вмонтировать папку проекта test с помощью команды терминала
docker run -it --rm `
  --cap-add=SYS_PTRACE `
  --security-opt seccomp=unconfined `
  -v ${PWD}:/work `
  nginx-dump-fuzz /bin/bash

--cap-add=SYS_PTRACE - Запуск GDB
--security-opt seccomp=unconfined - обязательно

После запуска должен появиться терминал контейнера

root@<container>:/work#

можно проверить рабочую директорию

ls -la /work

3
Проверка dump

Перед фаззингом необходимо иметь /work/capture полученный capture_dump.py.

можно проверить основные файлы

ls -lh /work/capture/

там должны быть

point_a.json
point_a_memory.json
point_a_memory/
point_b.json
request_buffer.bin

Проверить размер исходного HTTP testcase, в рабочей версии был 49 бт

ls -l /work/capture/request_buffer.bin

GET / HTTP/1.1\r\nHost: fuzz\r\nConnection: close\r\n\r\n

В случае если dump отсутствует его нужно получить:
находясь в контейнере, запустить capture_dump.py под GDB

gdb -q /usr/sbin/nginx -x /work/capture_dump.py

4
Создание seed для AFL++
вход AFL

mkdir -p /work/fuzz_input

Положить вышедшее как seed

cp /work/capture/request_buffer.bin /work/fuzz_input/seed

и проверить

ls -l /work/fuzz_input/seed

5
Нужно проверить что процесс проходит от А до Б

python3 /work/fuzz_dump.py \
    --trace \
    /work/fuzz_input/seed

конец Б находится в

0x00005555555d4d98

Если --trace не проходит то dump нужно исправлять

6
Запуск AFL++

Если есть старые результаты, стоит очистить

rm -rf /work/fuzz_output
mkdir -p /work/fuzz_output

Сначало нужен каталог для результатов, создание:

mkdir -p /work/fuzz_output

Переменная AFL_VERSION, AFL++ может решить что это ошибочная переменная, ее стоит убрать

unset AFL_VERSION

/proc/sys/kernel/core_pattern может быть недоступна для изменения контейнером. Поэтому стоит убрать:

AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

Запуск тестового 30-секундного прогона:

AFL_DEBUG=1 \
AFL_SKIP_CPUFREQ=1 \
AFL_PATH=/opt/AFLplusplus \
AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
/opt/AFLplusplus/afl-fuzz \
    -U \
    -m none \
    -t 5000+ \
    -V 30 \
    -i /work/fuzz_input \
    -o /work/fuzz_output \
    -- \
    python3 /work/fuzz_dump.py @@

параметры

-U Unicorn mode
-m none здесь можно ограничить память
-t 5000+ timeout на случай ошибок
-V 30 тут можно указать время теста в секундах
-i здесь указывается seed
-o указывает где будет результат
@@ путь

7
Результаты

статистика

cat /work/fuzz_output/default/fuzzer_stats

списки

find /work/fuzz_output/default/queue -type f | sort

find /work/fuzz_output/default/queue -type f | wc -l

find /work/fuzz_output/default/crashes -type f | sort

find /work/fuzz_output/default/hangs -type f | sort

Если в crashes и hangs пусты, это означает только что просто ничего не нашлось

X
Возможны предупреждения

В некоторых мутированных запросах Linux выводит

shutdown() failed (1: Operation not permitted)

Это не мешает тесту, он проводится

В конфигурации NGINX используется:

error_log stderr debug;

Поэтому сообщения NGINX могут перекрыть UI afl

XX
Изменения от начальных настроек

Параметры NGINX
   -O0 -g -fno-omit-frame-pointer
   --with-debug
   --with-select_module

nginx.conf
   master_process off;
   daemon off;
   error_log stderr debug;
   use select;

GLIBC_TUNABLES
   отключение AVX2, путей по типу AVX_Fast_Unaligned_Load

GDB/Python
   capture_dump.py

Qiling
   load_dump.py

AFL++
   fuzz_dump.py

Qiling системные вызовы и хуки