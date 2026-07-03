; ================================================================
; DNS BLOCKLIST MANAGER для БЭСМ-6
; Версия 2.0 - Рефакторинг
; ================================================================
; Лицензия: MIT
; Автор: Адаптировано с Python v11.0.0
; ================================================================

; ================================================================
; КОНСТАНТЫ
; ================================================================

; Размеры буферов
BUFFER_SIZE     ЭКВ  16384   ; общий буфер ввода/вывода
DOMAIN_LEN      ЭКВ  256     ; макс. длина домена (RFC 1035)
HASH_SIZE       ЭКВ  10007   ; размер хэш-таблицы (простое число)
MAX_DOMAINS     ЭКВ  50000   ; макс. количество доменов
MAX_LISTS       ЭКВ  1000    ; макс. размер whitelist/blacklist
HOSTS_LINE_LEN  ЭКВ  64      ; длина строки в hosts.txt

; Коды символов
CHAR_NUL        ЭКВ  0
CHAR_LF         ЭКВ  10
CHAR_CR         ЭКВ  13
CHAR_SPACE      ЭКВ  32
CHAR_HASH       ЭКВ  35     ; #
CHAR_DOT        ЭКВ  46     ; .
CHAR_SLASH      ЭКВ  47     ; /
CHAR_0          ЭКВ  48
CHAR_9          ЭКВ  57
CHAR_A          ЭКВ  65
CHAR_Z          ЭКВ  90
CHAR_a          ЭКВ  97
CHAR_z          ЭКВ  122
CHAR_STAR       ЭКВ  42     ; *
CHAR_COLON      ЭКВ  58     ; :

; Коды возврата
RC_SUCCESS      ЭКВ  0
RC_NO_DATA      ЭКВ  1
RC_WRITE_FAIL   ЭКВ  2
RC_MEMORY       ЭКВ  3
RC_IO_ERROR     ЭКВ  4
RC_PARSE_ERROR  ЭКВ  5

; ================================================================
; СТРУКТУРЫ ДАННЫХ
; ================================================================

; ------ Секция данных (адреса) ------
        ORG  1000

; Хэш-таблица доменов
; Формат: [индекс в DOMAIN_STORAGE][флаг_занятости]
DOMAIN_HASH     БЛК  HASH_SIZE * 2, 0

; Хранилище доменов
DOMAIN_STORAGE  БЛК  MAX_DOMAINS * DOMAIN_LEN, 0

; Списки фильтрации
WHITELIST       БЛК  MAX_LISTS * DOMAIN_LEN, 0
BLACKLIST       БЛК  MAX_LISTS * DOMAIN_LEN, 0
WILDCARD_LIST   БЛК  100 * DOMAIN_LEN, 0

; Буферы
INPUT_BUFFER    БЛК  BUFFER_SIZE, 0
OUTPUT_BUFFER   БЛК  BUFFER_SIZE, 0
HOSTS_BUFFER    БЛК  MAX_DOMAINS * HOSTS_LINE_LEN, 0
TEMP_BUFFER     БЛК  DOMAIN_LEN, 0
STATS_BUFFER    БЛК  256, 0

; Счетчики
DOMAIN_COUNT    КОН  0
WHITE_COUNT     КОН  0
BLACK_COUNT     КОН  0
WILD_COUNT      КОН  0

; Статистика
STATS           БЛК  6, 0
; Индексы STATS:
STATS_TOTAL     ЭКВ  0
STATS_OUTPUT    ЭКВ  1
STATS_WHITELIST ЭКВ  2
STATS_WILDCARD  ЭКВ  3
STATS_BLACKLIST ЭКВ  4
STATS_ERRORS    ЭКВ  5

; Флаги состояния
FLAGS           КОН  0
FLAG_VERBOSE    БИТ  0
FLAG_DRY_RUN    БИТ  1
FLAG_BACKUP     БИТ  2

; ================================================================
; ТОЧКА ВХОДА
; ================================================================

START   ПС  SYSTEM_INIT
        ПС  LOAD_CONFIG
        ПС  PROCESS_LISTS
        ПС  BUILD_BLOCKLIST
        ПС  GENERATE_HOSTS
        ПС  SAVE_STATS
        ПС  CLEANUP
        СТОП

; ================================================================
; ИНИЦИАЛИЗАЦИЯ СИСТЕМЫ
; ================================================================

SYSTEM_INIT
        ; Очистка хэш-таблицы
        УСТ  R0, DOMAIN_HASH
        УСТ  R1, HASH_SIZE * 2
        ПС  MEMSET, R0, 0, R1
        
        ; Очистка статистики
        УСТ  R0, STATS
        УСТ  R1, 6
        ПС  MEMSET, R0, 0, R1
        
        ; Инициализация флагов
        УСТ  FLAGS, 0
        
        ; Вывод заголовка
        ПС  PRINT_HEADER
        ВЗВ  R0, 0

; ================================================================
; MEMSET - заполнение памяти
; ВХОД: R0=адрес, R1=значение, R2=количество слов
; ================================================================
MEMSET
        СМ   R2, 0
        ПВ   R2, MEMSET_DONE
        ЗП   (R0), R1
        УВ   R0, 1
        УВ   R2, -1
        ПР   MEMSET
MEMSET_DONE
        ВЗВ  R0, 0

; ================================================================
; ЗАГРУЗКА КОНФИГУРАЦИИ
; ================================================================
LOAD_CONFIG
        ; Проверка наличия файла конфигурации
        ВНЕШ FILE_EXISTS, "config.ini", R0
        СМ   R0, 0
        ПВ   R0, CONFIG_LOAD_FAIL
        
        ; Чтение конфигурации
        ВНЕШ READ_CONFIG, "config.ini", R0
        СМ   R0, RC_SUCCESS
        ПВ   R0, CONFIG_LOAD_ERROR
        
        ; Установка флагов из конфига
        ВНЕШ GET_CONFIG_VALUE, "verbose", R0
        СМ   R0, 0
        ПВ   R0, CONFIG_VERBOSE_ON
        ПР   CONFIG_VERBOSE_DONE
CONFIG_VERBOSE_ON
        УСТ  FLAGS, FLAGS + FLAG_VERBOSE
CONFIG_VERBOSE_DONE

        ВНЕШ GET_CONFIG_VALUE, "dry_run", R0
        СМ   R0, 0
        ПВ   R0, CONFIG_DRY_ON
        ПР   CONFIG_DRY_DONE
CONFIG_DRY_ON
        УСТ  FLAGS, FLAGS + FLAG_DRY_RUN
CONFIG_DRY_DONE

        ВНЕШ GET_CONFIG_VALUE, "backup", R0
        СМ   R0, 0
        ПВ   R0, CONFIG_BACKUP_ON
        ПР   CONFIG_BACKUP_DONE
CONFIG_BACKUP_ON
        УСТ  FLAGS, FLAGS + FLAG_BACKUP
CONFIG_BACKUP_DONE

        ПС  PRINT_OK, "Configuration loaded"
        ВЗВ  R0, 0

CONFIG_LOAD_FAIL
        ПС  PRINT_WARNING, "config.ini not found, using defaults"
        ВЗВ  R0, 0

CONFIG_LOAD_ERROR
        ПС  PRINT_ERROR, "Failed to parse config.ini"
        ВЗВ  R0, 0

; ================================================================
; ОБРАБОТКА СПИСКОВ
; ================================================================
PROCESS_LISTS
        ; Загрузка whitelist
        ПС  LOAD_DOMAIN_LIST, "whitelist.txt", WHITELIST, WHITE_COUNT
        СМ   R0, RC_SUCCESS
        ПВ   R0, WHITE_LOAD_ERROR
        ПС  PRINT_INFO, "Whitelist loaded"

        ; Загрузка blacklist
        ПС  LOAD_DOMAIN_LIST, "blacklist.txt", BLACKLIST, BLACK_COUNT
        СМ   R0, RC_SUCCESS
        ПВ   R0, BLACK_LOAD_ERROR
        ПС  PRINT_INFO, "Blacklist loaded"

        ; Загрузка wildcard whitelist
        ПС  LOAD_DOMAIN_LIST, "wildcard.txt", WILDCARD_LIST, WILD_COUNT
        СМ   R0, RC_SUCCESS
        ПВ   R0, WILD_LOAD_ERROR
        ПС  PRINT_INFO, "Wildcard list loaded"
        
        ВЗВ  R0, 0

WHITE_LOAD_ERROR
        ПС  PRINT_WARNING, "Failed to load whitelist.txt"
        ВЗВ  R0, 0

BLACK_LOAD_ERROR
        ПС  PRINT_WARNING, "Failed to load blacklist.txt"
        ВЗВ  R0, 0

WILD_LOAD_ERROR
        ПС  PRINT_WARNING, "Failed to load wildcard.txt"
        ВЗВ  R0, 0

; ================================================================
; ЗАГРУЗКА СПИСКА ДОМЕНОВ ИЗ ФАЙЛА
; ВХОД: R0=имя_файла, R1=буфер, R2=счетчик
; ВЫХОД: R0=код_ошибки
; ================================================================
LOAD_DOMAIN_LIST
        УСТ  R3, R0        ; сохраняем имя
        УСТ  R4, R1        ; сохраняем буфер
        УСТ  R5, R2        ; сохраняем счетчик
        
        ; Проверка файла
        ВНЕШ FILE_EXISTS, R3, R0
        СМ   R0, 0
        ПВ   R0, LDL_NOT_FOUND
        
        ; Открытие файла
        ВНЕШ OPEN_FILE_READ, R3, R6
        СМ   R6, 0
        ПВ   R6, LDL_ERROR
        
        ; Чтение построчно
        УСТ  R7, 0          ; счетчик загруженных
        
LDL_LOOP
        ВНЕШ READ_LINE, R6, INPUT_BUFFER, R0
        СМ   R0, 0
        ПВ   R0, LDL_DONE
        
        ; Очистка и валидация
        ПС  CLEAN_DOMAIN, INPUT_BUFFER, TEMP_BUFFER
        СМ   R0, 0
        ПВ   R0, LDL_NEXT
        
        ; Копирование в список
        ПС  STRCOPY, TEMP_BUFFER, R4 + (R7 * DOMAIN_LEN)
        УВ   R7, 1
        
        ; Проверка переполнения
        СМ   R7, MAX_LISTS
        ПВ   R7, LDL_FULL
        
LDL_NEXT
        ПР   LDL_LOOP

LDL_DONE
        ВНЕШ CLOSE_FILE, R6
        ЗП   (R5), R7       ; сохраняем счетчик
        УСТ  R0, RC_SUCCESS
        ВЗВ  R0, 0

LDL_NOT_FOUND
        ЗП   (R5), 0
        УСТ  R0, RC_SUCCESS  ; не ошибка, просто нет файла
        ВЗВ  R0, 0

LDL_ERROR
        ЗП   (R5), 0
        УСТ  R0, RC_IO_ERROR
        ВЗВ  R0, 0

LDL_FULL
        ПС  PRINT_WARNING, "List capacity exceeded"
        ВНЕШ CLOSE_FILE, R6
        ЗП   (R5), R7
        УСТ  R0, RC_MEMORY
        ВЗВ  R0, 0

; ================================================================
; ОЧИСТКА И ВАЛИДАЦИЯ ДОМЕНА
; ВХОД: R0=входная_строка, R1=выходной_буфер
; ВЫХОД: R0=0 если невалидный, 1 если валидный
; ================================================================
CLEAN_DOMAIN
        ПС  STRIP_COMMENTS, R0, TEMP_BUFFER
        ПС  STRIP_WHITESPACE, TEMP_BUFFER, TEMP_BUFFER+1
        ПС  STRIP_PREFIXES, TEMP_BUFFER+1, TEMP_BUFFER+2
        
        ; Проверка минимальной длины
        ПС  STRLEN, TEMP_BUFFER+2
        СМ   R0, 3
        ПМ   R0, CD_INVALID
        
        ; Проверка на IP-адрес
        ПС  IS_IP_ADDRESS, TEMP_BUFFER+2
        СМ   R0, 0
        ПВ   R0, CD_INVALID
        
        ; Проверка символов
        ПС  VALIDATE_CHARS, TEMP_BUFFER+2
        СМ   R0, 0
        ПВ   R0, CD_INVALID
        
        ; Копирование результата
        ПС  TOLOWER, TEMP_BUFFER+2, R1
        УСТ  R0, 1
        ВЗВ  R0, 0

CD_INVALID
        УСТ  R0, 0
        ВЗВ  R0, 0

; ================================================================
; ПОСТРОЕНИЕ БЛОКЛИСТА
; ================================================================
BUILD_BLOCKLIST
        ПС  PRINT, "📊 Building blocklist..."
        
        ; Чтение источников
        ПС  LOAD_SOURCES
        
        ; Применение фильтров
        ПС  APPLY_WHITELIST
        ПС  APPLY_WILDCARD
        ПС  APPLY_BLACKLIST
        
        ; Обновление статистики
        ПС  UPDATE_STATS
        
        ; Вывод статистики
        ПС  PRINT_STATS
        
        ВЗВ  R0, 0

; ================================================================
; ЗАГРУЗКА ИСТОЧНИКОВ
; ================================================================
LOAD_SOURCES
        ПС  PRINT, "📥 Loading sources..."
        
        ; Открытие файла источников
        ВНЕШ FILE_EXISTS, "sources.txt", R0
        СМ   R0, 0
        ПВ   R0, LS_NO_SOURCES
        
        ВНЕШ OPEN_FILE_READ, "sources.txt", R1
        СМ   R1, 0
        ПВ   R1, LS_ERROR
        
LS_LOOP
        ВНЕШ READ_LINE, R1, INPUT_BUFFER, R0
        СМ   R0, 0
        ПВ   R0, LS_DONE
        
        ; Извлечение домена из URL
        ПС  EXTRACT_DOMAIN_FROM_URL, INPUT_BUFFER, TEMP_BUFFER
        СМ   R0, 0
        ПВ   R0, LS_SKIP
        
        ; Загрузка доменов из источника
        ПС  FETCH_SOURCE, TEMP_BUFFER
        СМ   R0, RC_SUCCESS
        ПВ   R0, LS_SKIP
        
LS_SKIP
        ПР   LS_LOOP

LS_DONE
        ВНЕШ CLOSE_FILE, R1
        ПС  PRINT_OK, "Sources loaded"
        ВЗВ  R0, 0

LS_NO_SOURCES
        ПС  PRINT_WARNING, "sources.txt not found"
        ВЗВ  R0, 0

LS_ERROR
        ПС  PRINT_ERROR, "Failed to open sources.txt"
        ВЗВ  R0, 0

; ================================================================
; ЗАГРУЗКА ДАННЫХ ИЗ ВНЕШНЕГО ИСТОЧНИКА
; ВХОД: R0=домен_источника
; ================================================================
FETCH_SOURCE
        ; Вызов внешнего модуля для загрузки
        ВНЕШ FETCH_URL, R0, INPUT_BUFFER, R1
        СМ   R1, 0
        ПВ   R1, FS_FAIL
        
        ; Парсинг загруженных данных
        ПС  PARSE_DOMAINS, INPUT_BUFFER
        СМ   R0, RC_SUCCESS
        ПВ   R0, FS_PARSE_ERROR
        
        УСТ  R0, RC_SUCCESS
        ВЗВ  R0, 0

FS_FAIL
        ПС  PRINT_WARNING, "Failed to fetch source"
        УСТ  R0, RC_IO_ERROR
        ВЗВ  R0, 0

FS_PARSE_ERROR
        ПС  PRINT_WARNING, "Failed to parse source data"
        УСТ  R0, RC_PARSE_ERROR
        ВЗВ  R0, 0

; ================================================================
; ПАРСИНГ ДОМЕНОВ ИЗ КОНТЕНТА
; ВХОД: R0=указатель_на_контент
; ================================================================
PARSE_DOMAINS
        УСТ  R1, R0        ; текущая позиция
        УСТ  R2, 0          ; счетчик добавленных
        
PD_LOOP
        ; Поиск конца строки
        ПС  FIND_LINE_END, R1
        СМ   R0, 0
        ПВ   R0, PD_DONE
        
        ; Очистка строки
        ПС  CLEAN_DOMAIN, R1, TEMP_BUFFER
        СМ   R0, 0
        ПВ   R0, PD_NEXT
        
        ; Добавление в хэш-таблицу
        ПС  HASH_ADD, TEMP_BUFFER
        СМ   R0, 0
        ПВ   R0, PD_NEXT
        УВ   R2, 1
        
PD_NEXT
        УСТ  R1, R0        ; следующий символ
        ПР   PD_LOOP

PD_DONE
        УСТ  STATS_TOTAL, DOMAIN_COUNT
        ПС  PRINT_COUNT, R2
        УСТ  R0, RC_SUCCESS
        ВЗВ  R0, 0

; ================================================================
; ХЭШ-ФУНКЦИЯ (DJB2)
; ВХОД: R0=строка
; ВЫХОД: R1=хэш
; ================================================================
HASH_FUNCTION
        УСТ  R1, 5381
        УСТ  R2, 0
HF_LOOP
        И    R3, (R0+R2)
        СМ   R3, 0
        ПВ   R3, HF_DONE
        УМ   R1, 33
        СЛ   R1, R3
        УВ   R2, 1
        ПР   HF_LOOP
HF_DONE
        ДЕЛ  R1, HASH_SIZE
        ВЗВ  R1, 0

; ================================================================
; ДОБАВЛЕНИЕ В ХЭШ-ТАБЛИЦУ
; ВХОД: R0=домен
; ВЫХОД: R0=1 если добавлен, 0 если уже есть
; ================================================================
HASH_ADD
        ПС  HASH_FUNCTION, R0
        УСТ  R2, DOMAIN_HASH
        УМ   R1, 2          ; *2 для пары (индекс, флаг)
        СЛ   R2, R1
        
        ; Проверка существования
        И    R3, (R2)       ; индекс
        СМ   R3, 0
        ПВ   R3, HA_EXISTS
        И    R3, (R2+1)     ; флаг
        СМ   R3, 0
        ПВ   R3, HA_EXISTS
        
        ; Добавление нового домена
        УСТ  R3, DOMAIN_COUNT
        ПС  STRCOPY, R0, DOMAIN_STORAGE + (R3 * DOMAIN_LEN)
        ЗП   (R2), R3       ; сохраняем индекс
        ЗП   (R2+1), 1      ; устанавливаем флаг
        УВ   DOMAIN_COUNT, 1
        УСТ  R0, 1
        ВЗВ  R0, 0

HA_EXISTS
        УСТ  R0, 0
        ВЗВ  R0, 0

; ================================================================
; ПРИМЕНЕНИЕ ФИЛЬТРОВ
; ================================================================
APPLY_WHITELIST
        ПС  PRINT, "📋 Applying whitelist..."
        УСТ  R0, WHITELIST
        УСТ  R1, WHITE_COUNT
        ПС  FILTER_DOMAINS, R0, R1, STATS_WHITELIST
        ВЗВ  R0, 0

APPLY_WILDCARD
        ПС  PRINT, "📋 Applying wildcard whitelist..."
        УСТ  R0, WILDCARD_LIST
        УСТ  R1, WILD_COUNT
        ПС  FILTER_WILDCARD, R0, R1
        ВЗВ  R0, 0

APPLY_BLACKLIST
        ПС  PRINT, "📋 Applying blacklist..."
        УСТ  R0, BLACKLIST
        УСТ  R1, BLACK_COUNT
        ПС  FILTER_DOMAINS, R0, R1, STATS_BLACKLIST
        ВЗВ  R0, 0

; ================================================================
; ФИЛЬТРАЦИЯ ПО СПИСКУ
; ВХОД: R0=список, R1=количество, R2=счетчик_статистики
; ================================================================
FILTER_DOMAINS
        УСТ  R3, R0        ; список
        УСТ  R4, R1        ; количество
        УСТ  R5, R2        ; счетчик статистики
        УСТ  R6, 0          ; индекс в списке
        УСТ  R7, 0          ; счетчик фильтров
        
FD_LOOP
        СМ   R6, R4
        ПВ   R6, FD_DONE
        
        ; Получение домена из списка
        УСТ  R8, R3 + (R6 * DOMAIN_LEN)
        
        ; Поиск в хэш-таблице
        ПС  HASH_FIND, R8
        СМ   R0, 0
        ПВ   R0, FD_NEXT   ; не найден
        
        ; Удаление из хэш-таблицы
        ПС  HASH_REMOVE, R8
        УВ   R7, 1
        УВ   R5, 1
        
FD_NEXT
        УВ   R6, 1
        ПР   FD_LOOP
        
FD_DONE
        ПС  PRINT_COUNT_FILTERED, R7
        УСТ  STATS + R5, R7
        ВЗВ  R0, 0

; ================================================================
; ПОИСК В ХЭШ-ТАБЛИЦЕ
; ВХОД: R0=домен
; ВЫХОД: R0=1 если найден
; ================================================================
HASH_FIND
        ПС  HASH_FUNCTION, R0
        УСТ  R2, DOMAIN_HASH
        УМ   R1, 2
        СЛ   R2, R1
        
        И    R3, (R2)       ; индекс
        СМ   R3, 0
        ПВ   R3, HF_NOT_FOUND
        И    R4, (R2+1)     ; флаг
        СМ   R4, 0
        ПВ   R4, HF_NOT_FOUND
        
        ; Сравнение доменов
        УСТ  R5, DOMAIN_STORAGE + (R3 * DOMAIN_LEN)
        ПС  STRCOMP, R0, R5
        СМ   R0, 0
        ПВ   R0, HF_FOUND
        
HF_NOT_FOUND
        УСТ  R0, 0
        ВЗВ  R0, 0
        
HF_FOUND
        УСТ  R0, 1
        ВЗВ  R0, 0

; ================================================================
; УДАЛЕНИЕ ИЗ ХЭШ-ТАБЛИЦЫ
; ВХОД: R0=домен
; ================================================================
HASH_REMOVE
        ПС  HASH_FUNCTION, R0
        УСТ  R2, DOMAIN_HASH
        УМ   R1, 2
        СЛ   R2, R1
        
        ; Очистка флага
        ЗП   (R2+1), 0
        УСТ  R0, 1
        ВЗВ  R0, 0

; ================================================================
; ФИЛЬТРАЦИЯ ПО WILDCARD
; ВХОД: R0=список, R1=количество
; ================================================================
FILTER_WILDCARD
        УСТ  R3, R0        ; список
        УСТ  R4, R1        ; количество
        УСТ  R5, 0          ; счетчик
        
FW_LOOP
        СМ   R5, R4
        ПВ   R5, FW_DONE
        
        ; Получение паттерна
        УСТ  R6, R3 + (R5 * DOMAIN_LEN)
        
        ; Проверка всех доменов
        УСТ  R7, 0          ; индекс в хэш-таблице
        УСТ  R8, DOMAIN_COUNT
        
FW_CHECK_LOOP
        СМ   R7, R8
        ПВ   R7, FW_NEXT
        
        ; Получение домена
        УСТ  R9, DOMAIN_STORAGE + (R7 * DOMAIN_LEN)
        
        ; Проверка соответствия
        ПС  MATCH_WILDCARD, R9, R6
        СМ   R0, 0
        ПВ   R0, FW_FOUND
        
        УВ   R7, 1
        ПР   FW_CHECK_LOOP
        
FW_FOUND
        ; Удаление домена
        ПС  HASH_REMOVE, R9
        УВ   STATS_WILDCARD, 1
        
FW_NEXT
        УВ   R5, 1
        ПР   FW_LOOP
        
FW_DONE
        ВЗВ  R0, 0

; ================================================================
; ПРОВЕРКА WILDCARD
; ВХОД: R0=домен, R1=паттерн
; ВЫХОД: R0=1 если совпадает
; ================================================================
MATCH_WILDCARD
        ; Проверка паттерна с *
        И    R2, (R1)       ; первый символ паттерна
        СМ   R2, CHAR_STAR
        ПВ   R2, MW_STAR
        
        ; Обычное сравнение
        ПС  STRCOMP, R0, R1
        СМ   R0, 0
        ПВ   R0, MW_TRUE
        УСТ  R0, 0
        ВЗВ  R0, 0
        
MW_STAR
        ; Паттерн начинается с * (суффикс)
        УВ   R1, 1
        ПС  STRENDSWITH, R0, R1
        СМ   R0, 0
        ПВ   R0, MW_TRUE
        УСТ  R0, 0
        ВЗВ  R0, 0
        
MW_TRUE
        УСТ  R0, 1
        ВЗВ  R0, 0

; ================================================================
; ГЕНЕРАЦИЯ HOSTS.TXT
; ================================================================
GENERATE_HOSTS
        ПС  PRINT, "💾 Generating hosts.txt..."
        
        ; Проверка dry-run
        ТЕСТ FLAGS, FLAG_DRY_RUN
        ПВ  0, GH_DRY_RUN
        
        ; Создание резервной копии
        ТЕСТ FLAGS, FLAG_BACKUP
        ПВ  0, GH_BACKUP
        
GH_BACKUP
        ПС  BACKUP_FILE, "hosts.txt"
        
GH_DRY_RUN
        ; Открытие файла
        ВНЕШ OPEN_FILE_WRITE, "hosts.txt", R0
        СМ   R0, 0
        ПВ   R0, GH_ERROR
        
        ; Запись заголовка
        ПС  WRITE_HOSTS_HEADER, R0
        
        ; Запись доменов
        УСТ  R1, DOMAIN_COUNT
        УСТ  R2, 0          ; индекс в хранилище
        УСТ  R3, 0          ; счетчик записанных
        
GH_LOOP
        СМ   R2, R1
        ПВ   R2, GH_DONE
        
        ; Проверка, не удален ли домен
        ПС  IS_DOMAIN_ACTIVE, R2
        СМ   R0, 0
        ПВ   R0, GH_NEXT
        
        ; Форматирование строки
        УСТ  R4, DOMAIN_STORAGE + (R2 * DOMAIN_LEN)
        ПС  FORMAT_HOSTS_LINE, R4, TEMP_BUFFER
        
        ; Запись в файл
        ВНЕШ WRITE_LINE, R0, TEMP_BUFFER
        СМ   R0, 0
        ПВ   R0, GH_WRITE_ERROR
        УВ   R3, 1
        
GH_NEXT
        УВ   R2, 1
        ПР   GH_LOOP
        
GH_DONE
        ВНЕШ CLOSE_FILE, R0
        УСТ  STATS_OUTPUT, R3
        
        ; Вывод результата
        ПС  PRINT_OK, "hosts.txt generated"
        ВЗВ  R0, 0

GH_ERROR
        ПС  PRINT_ERROR, "Failed to create hosts.txt"
        УСТ  R0, RC_WRITE_FAIL
        ВЗВ  R0, 0

GH_WRITE_ERROR
        ПС  PRINT_ERROR, "Write error"
        ВНЕШ CLOSE_FILE, R0
        УСТ  R0, RC_IO_ERROR
        ВЗВ  R0, 0

; ================================================================
; ЗАПИСЬ ЗАГОЛОВКА HOSTS.TXT
; ================================================================
WRITE_HOSTS_HEADER
        ; Запись первой строки
        ВНЕШ WRITE_LINE, R0, HOSTS_HEADER1
        ВНЕШ WRITE_LINE, R0, HOSTS_HEADER2
        ВНЕШ WRITE_LINE, R0, HOSTS_HEADER3
        ВНЕШ WRITE_LINE, R0, HOSTS_HEADER4
        ВЗВ  R0, 0

HOSTS_HEADER1  КОН  "# DNS Blocklist Manager for BESM-6 v2.0", 0
HOSTS_HEADER2  КОН  "# Generated by BESM-6 mainframe", 0
HOSTS_HEADER3  КОН  "#", 0
HOSTS_HEADER4  КОН  "", 0

; ================================================================
; ФОРМАТИРОВАНИЕ СТРОКИ HOSTS
; ВХОД: R0=домен, R1=буфер_вывода
; ================================================================
FORMAT_HOSTS_LINE
        ; "0.0.0.0 domain\n"
        ЗП   (R1), CHAR_0
        ЗП   (R1+1), CHAR_DOT
        ЗП   (R1+2), CHAR_0
        ЗП   (R1+3), CHAR_DOT
        ЗП   (R1+4), CHAR_0
        ЗП   (R1+5), CHAR_DOT
        ЗП   (R1+6), CHAR_0
        ЗП   (R1+7), CHAR_SPACE
        
        ; Копирование домена
        ПС  STRCOPY, R0, R1+8
        
        ; Добавление новой строки
        ПС  STRLEN, R1
        ЗП   (R1+R0), CHAR_LF
        ЗП   (R1+R0+1), CHAR_NUL
        ВЗВ  R0, 0

; ================================================================
; ПРОВЕРКА АКТИВНОСТИ ДОМЕНА
; ВХОД: R0=индекс_в_хранилище
; ВЫХОД: R0=1 если активен
; ================================================================
IS_DOMAIN_ACTIVE
        ; Проверка флага в хэш-таблице
        УСТ  R1, 0
IDA_LOOP
        СМ   R1, HASH_SIZE
        ПВ   R1, IDA_NOT_FOUND
        
        УСТ  R2, DOMAIN_HASH + (R1 * 2)
        И    R3, (R2)       ; индекс
        СМ   R3, R0
        ПВ   R3, IDA_CHECK_FLAG
        ПР   IDA_NEXT
        
IDA_CHECK_FLAG
        И    R4, (R2+1)     ; флаг
        СМ   R4, 0
        ПВ   R4, IDA_ACTIVE
        
IDA_NEXT
        УВ   R1, 1
        ПР   IDA_LOOP
        
IDA_NOT_FOUND
        УСТ  R0, 0
        ВЗВ  R0, 0
        
IDA_ACTIVE
        УСТ  R0, 1
        ВЗВ  R0, 0

; ================================================================
; СОХРАНЕНИЕ СТАТИСТИКИ
; ================================================================
SAVE_STATS
        ; Формирование отчета
        ПС  FORMAT_STATS, STATS_BUFFER
        
        ; Запись в файл
        ВНЕШ OPEN_FILE_WRITE, "stats.txt", R0
        СМ   R0, 0
        ПВ   R0, SS_ERROR
        
        ВНЕШ WRITE_LINE, R0, STATS_BUFFER
        ВНЕШ CLOSE_FILE, R0
        
        ПС  PRINT_OK, "Statistics saved"
        ВЗВ  R0, 0

SS_ERROR
        ПС  PRINT_WARNING, "Failed to save statistics"
        ВЗВ  R0, 0

; ================================================================
; ОЧИСТКА И ЗАВЕРШЕНИЕ
; ================================================================
CLEANUP
        ; Вывод финального сообщения
        ПС  PRINT_FOOTER
        ВЗВ  R0, 0

; ================================================================
; БАЗОВЫЕ СТРОКОВЫЕ ФУНКЦИИ
; ================================================================

; STRLEN - длина строки
; ВХОД: R0=строка
; ВЫХОД: R0=длина
STRLEN
        УСТ  R0, 0
SL_LOOP
        И    R1, (R0+???)  ; сложно, используем регистр
        ВЗВ  R0, 0

; STRCOPY - копирование строки
; ВХОД: R0=источник, R1=приемник
STRCOPY
        УСТ  R2, 0
SC_LOOP
        И    R3, (R0+R2)
        СМ   R3, 0
        ПВ   R3, SC_DONE
        ЗП   (R1+R2), R3
        УВ   R2, 1
        ПР   SC_LOOP
SC_DONE
        ЗП   (R1+R2), 0
        ВЗВ  R0, 0

; STRCOMP - сравнение строк
; ВХОД: R0, R1=строки
; ВЫХОД: R0=1 если равны
STRCOMP
        УСТ  R2, 0
SCMP_LOOP
        И    R3, (R0+R2)
        И    R4, (R1+R2)
        СМ   R3, R4
        ПВ   R3, SCMP_DIFF
        СМ   R3, 0
        ПВ   R3, SCMP_EQ
        УВ   R2, 1
        ПР   SCMP_LOOP
SCMP_EQ
        УСТ  R0, 1
        ВЗВ  R0, 0
SCMP_DIFF
        УСТ  R0, 0
        ВЗВ  R0, 0

; STRIP_COMMENTS - удаление комментариев
; ВХОД: R0=вход, R1=выход
STRIP_COMMENTS
        УСТ  R2, 0
        УСТ  R3, 0
SC_LOOP
        И    R4, (R0+R2)
        СМ   R4, 0
        ПВ   R4, SC_DONE
        СМ   R4, CHAR_HASH
        ПВ   R4, SC_DONE
        ЗП   (R1+R3), R4
        УВ   R2, 1
        УВ   R3, 1
        ПР   SC_LOOP
SC_DONE
        ЗП   (R1+R3), 0
        ВЗВ  R0, 0

; STRIP_WHITESPACE - удаление пробелов
; ВХОД: R0=вход, R1=выход
STRIP_WHITESPACE
        УСТ  R2, 0
        УСТ  R3, 0
SW_LOOP
        И    R4, (R0+R2)
        СМ   R4, 0
        ПВ   R4, SW_DONE
        СМ   R4, CHAR_SPACE
        ПВ   R4, SW_SKIP
        СМ   R4, CHAR_LF
        ПВ   R4, SW_SKIP
        СМ   R4, CHAR_CR
        ПВ   R4, SW_SKIP
        ЗП   (R1+R3), R4
        УВ   R3, 1
SW_SKIP
        УВ   R2, 1
        ПР   SW_LOOP
SW_DONE
        ЗП   (R1+R3), 0
        ВЗВ  R0, 0

; TOLOWER - перевод в нижний регистр
; ВХОД: R0=вход, R1=выход
TOLOWER
        УСТ  R2, 0
TL_LOOP
        И    R3, (R0+R2)
        СМ   R3, 0
        ПВ   R3, TL_DONE
        СМ   R3, CHAR_A
        ПМ   R3, TL_COPY
        СМ   R3, CHAR_Z
        ПБ   R3, TL_COPY
        СЛ   R3, 32        ; to lower
TL_COPY
        ЗП   (R1+R2), R3
        УВ   R2, 1
        ПР   TL_LOOP
TL_DONE
        ЗП   (R1+R2), 0
        ВЗВ  R0, 0

; ================================================================
; ВЫВОД НА ПЕЧАТЬ (С ИКОНКАМИ)
; ================================================================

PRINT
        ВНЕШ WRITE_STRING, R0
        ВНЕШ WRITE_NEWLINE
        ВЗВ  R0, 0

PRINT_OK
        ВНЕШ WRITE_STRING, "✅ "
        ВНЕШ WRITE_STRING, R0
        ВНЕШ WRITE_NEWLINE
        ВЗВ  R0, 0

PRINT_ERROR
        ВНЕШ WRITE_STRING, "❌ "
        ВНЕШ WRITE_STRING, R0
        ВНЕШ WRITE_NEWLINE
        ВЗВ  R0, 0

PRINT_WARNING
        ВНЕШ WRITE_STRING, "⚠️ "
        ВНЕШ WRITE_STRING, R0
        ВНЕШ WRITE_NEWLINE
        ВЗВ  R0, 0

PRINT_INFO
        ВНЕШ WRITE_STRING, "ℹ️ "
        ВНЕШ WRITE_STRING, R0
        ВНЕШ WRITE_NEWLINE
        ВЗВ  R0, 0

PRINT_HEADER
        ВНЕШ WRITE_STRING, HEADER
        ВНЕШ WRITE_NEWLINE
        ВЗВ  R0, 0

HEADER  КОН  "🚀 DNS Blocklist Manager for BESM-6 v2.0", 0

PRINT_STATS
        ВНЕШ WRITE_STRING, "📊 Statistics:", 0
        ВНЕШ WRITE_NEWLINE
        ВНЕШ WRITE_STRING, "   Total domains: ", 0
        ВНЕШ WRITE_NUMBER, STATS_TOTAL, 0
        ВНЕШ WRITE_NEWLINE
        ВНЕШ WRITE_STRING, "   Output: ", 0
        ВНЕШ WRITE_NUMBER, STATS_OUTPUT, 0
        ВНЕШ WRITE_NEWLINE
        ВНЕШ WRITE_STRING, "   Whitelisted: ", 0
        ВНЕШ WRITE_NUMBER, STATS_WHITELIST, 0
        ВНЕШ WRITE_NEWLINE
        ВНЕШ WRITE_STRING, "   Wildcard filtered: ", 0
        ВНЕШ WRITE_NUMBER, STATS_WILDCARD, 0
        ВНЕШ WRITE_NEWLINE
        ВНЕШ WRITE_STRING, "   Blacklisted: ", 0
        ВНЕШ WRITE_NUMBER, STATS_BLACKLIST, 0
        ВНЕШ WRITE_NEWLINE
        ВЗВ  R0, 0

PRINT_COUNT
        ВНЕШ WRITE_STRING, "📥 Loaded: ", 0
        ВНЕШ WRITE_NUMBER, R2, 0
        ВНЕШ WRITE_STRING, " domains", 0
        ВНЕШ WRITE_NEWLINE
        ВЗВ  R0, 0

PRINT_COUNT_FILTERED
        ВНЕШ WRITE_STRING, "   Filtered: ", 0
        ВНЕШ WRITE_NUMBER, R7, 0
        ВНЕШ WRITE_NEWLINE
        ВЗВ  R0, 0

PRINT_FOOTER
        ВНЕШ WRITE_STRING, "✅ Build completed successfully", 0
        ВНЕШ WRITE_NEWLINE
        ВЗВ  R0, 0

; ================================================================
; ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (ЗАГОТОВКИ)
; ================================================================

; EXTRACT_DOMAIN_FROM_URL - извлечение домена из URL
EXTRACT_DOMAIN_FROM_URL
        ; Упрощенная версия
        УСТ  R0, 1
        ВЗВ  R0, 0

; STRIP_PREFIXES - удаление префиксов
STRIP_PREFIXES
        УСТ  R0, 1
        ВЗВ  R0, 0

; FIND_LINE_END - поиск конца строки
FIND_LINE_END
        УСТ  R0, 1
        ВЗВ  R0, 0

; IS_IP_ADDRESS - проверка на IP
IS_IP_ADDRESS
        УСТ  R0, 0
        ВЗВ  R0, 0

; VALIDATE_CHARS - проверка символов
VALIDATE_CHARS
        УСТ  R0, 1
        ВЗВ  R0, 0

; STRENDSWITH - проверка окончания строки
STRENDSWITH
        УСТ  R0, 1
        ВЗВ  R0, 0

; BACKUP_FILE - создание резервной копии
BACKUP_FILE
        ВНЕШ COPY_FILE, R0, R1
        ВЗВ  R0, 0

; UPDATE_STATS - обновление статистики
UPDATE_STATS
        УСТ  STATS_TOTAL, DOMAIN_COUNT
        ВЗВ  R0, 0

; FORMAT_STATS - форматирование статистики
FORMAT_STATS
        УСТ  R0, 1
        ВЗВ  R0, 0

; ================================================================
; ТОЧКА ВЫХОДА
; ================================================================

        КОН  START
        КОН  0