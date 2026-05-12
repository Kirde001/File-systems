import struct
import sys
import os
import hashlib
import math
import collections
import datetime

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

def calc_entropy(data: bytes) -> float:
    if not data: return 0.0
    c = collections.Counter(data)
    n = len(data)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

def decode_characteristics(chars: int) -> str:
    flags = []
    if chars & 0x0002: flags.append("EXECUTABLE_IMAGE")
    if chars & 0x0100: flags.append("32BIT_MACHINE")
    if chars & 0x0020: flags.append("LARGE_ADDRESS_AWARE")
    if chars & 0x2000: flags.append("DLL")
    if chars & 0x010E: flags.append("SYSTEM/DRIVER")
    return " | ".join(flags) if flags else "UNKNOWN"

def decode_section_flags(flags: int) -> str:
    perms = []
    if flags & 0x20000000: perms.append("X")
    if flags & 0x40000000: perms.append("R")
    if flags & 0x80000000: perms.append("W")
    
    desc = []
    if flags & 0x00000020: desc.append("Code")
    if flags & 0x00000040: desc.append("InitData")
    if flags & 0x00000080: desc.append("UninitData")
    
    perm_str = "+".join(perms) if perms else "None"
    desc_str = "/".join(desc) if desc else "Unknown"
    return f"[{perm_str}] {desc_str}"

def analyze_dropper(file_path):
    if not os.path.exists(file_path):
        return
        
    report_path = f"{os.path.splitext(file_path)[0]}_report.txt"
    
    with open(file_path, "rb") as f, open(report_path, "w", encoding="utf-8") as out:
        d = f.read()
        
        def log(text=""):
            out.write(text + "\n")
            
        def log_sep(char="=", length=120):
            log(char * length)

        log_sep("=")
        log(f"{'Анализ UPX-дроппера: ' + os.path.basename(file_path):^120}")
        log_sep("=")
        log()

        log("ЧАСТЬ 1 - ОСНОВНЫЕ ПАРАМЕТРЫ ФАЙЛА")
        log_sep("-")
        
        log("1.1. Базовые идентификаторы:")
        log(f" -> Размер файла: {len(d)} байт")
        log(f" -> Magic байты (hex): {d[0:8].hex().upper()} (Уникальная сигнатура, определяющая формат)")
        log(f" -> Magic байты (ASCII): {d[0:8]}")
        log(f" -> Хэш MD5: {hashlib.md5(d).hexdigest()} (файловый индикатор компрометации - IoC)")
        log(f" -> Хэш SHA256: {hashlib.sha256(d).hexdigest()} (уникальный идентификатор файла)")
        log()

        if d[0:2] != b'MZ':
            log("Файл не является валидным PE-файлом (отсутствует сигнатура MZ).")
            return
            
        pe_off = struct.unpack('<I', d[0x3C:0x40])[0]
        if d[pe_off:pe_off+4] != b'PE\x00\x00':
            log(f"PE-сигнатура не найдена по смещению 0x{pe_off:X}.")
            return

        log("1.2. PE-заголовок:")
        log(f" -> Смещение e_lfanew: 0x{pe_off:08X} (начало PE-заголовка)")
        log(f" -> PE-сигнатура: {d[pe_off:pe_off+4].hex().upper()} (50 45 00 00, что означает 'PE\\x00\\x00')")
        log()
        
        coff = pe_off + 4
        machine, num_sections, timestamp, ptr_sym, num_sym, opt_hdr_size, characteristics = struct.unpack("<HHIIIHH", d[coff:coff+20])
        
        try:
            dt_stamp = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        except:
            dt_stamp = "Invalid Date"

        log("1.3. Разбор COFF-заголовка:")
        log(f" -> Архитектура (Machine): 0x{machine:04X} ( 0x014C означает Intel i386 (32-bit), 0x8664 - AMD x86-64)")
        log(f" -> Количество секций: {num_sections}")
        log(f" -> Временная метка компиляции: {dt_stamp} (0x{timestamp:08X})")
        log(f" -> Размер Optional Header: {opt_hdr_size} байт")
        log(f" -> Характеристики (Characteristics): 0x{characteristics:04X}")
        log(f"    Расшифровка флагов: {decode_characteristics(characteristics)}")
        log()

        opt_hdr = coff + 20
        magic = struct.unpack('<H', d[opt_hdr:opt_hdr+2])[0]
        is_pe32_plus = (magic == 0x020B)
        
        log("1.4. Разбор Optional Header:")
        log(f" -> Magic (Тип PE): 0x{magic:04X} ({'PE32+ (64-bit)' if is_pe32_plus else 'PE32 (32-bit)'})")
        
        ep_rva = struct.unpack('<I', d[opt_hdr+16:opt_hdr+20])[0]
        log(f" -> Точка входа (EntryPoint RVA): 0x{ep_rva:08X}")

        if is_pe32_plus:
            image_base = struct.unpack('<Q', d[opt_hdr+24:opt_hdr+32])[0]
            sec_align = struct.unpack('<I', d[opt_hdr+32:opt_hdr+36])[0]
            file_align = struct.unpack('<I', d[opt_hdr+36:opt_hdr+40])[0]
            size_of_image = struct.unpack('<I', d[opt_hdr+56:opt_hdr+60])[0]
            subsystem = struct.unpack('<H', d[opt_hdr+68:opt_hdr+70])[0]
            data_dir_off = opt_hdr + 112
        else:
            image_base = struct.unpack('<I', d[opt_hdr+28:opt_hdr+32])[0]
            sec_align = struct.unpack('<I', d[opt_hdr+32:opt_hdr+36])[0]
            file_align = struct.unpack('<I', d[opt_hdr+36:opt_hdr+40])[0]
            size_of_image = struct.unpack('<I', d[opt_hdr+56:opt_hdr+60])[0]
            subsystem = struct.unpack('<H', d[opt_hdr+68:opt_hdr+70])[0]
            data_dir_off = opt_hdr + 96

        subsystem_str = "Windows GUI" if subsystem == 2 else "Console" if subsystem == 3 else "Native" if subsystem == 1 else str(subsystem)
        
        log(f" -> Базовый адрес загрузки (ImageBase): 0x{image_base:08X}")
        log(f" -> Подсистема (Subsystem): {subsystem} ({subsystem_str})")
        log()

        log("1.5. Анализ таблицы секций и расчет энтропии Шеннона:")
        log(" - 0.0 - 1.0: Пустое пространство (padding из нулевых байт).")
        log(" - 3.0 - 5.0: Обычный исполняемый код или текстовые данные.")
        log(" - 6.5 - 7.2: Потенциально скрытые или XOR-зашифрованные данные.")
        log(" - 7.2 - 8.0: Сильное криптографическое шифрование (RC4/AES) или сжатие алгоритмами (UPX/zlib).")
        
        sect_off = opt_hdr + opt_hdr_size
        sections = []
        
        log(f" | {'Имя (8B)':<8} | {'V.Addr':<10} | {'V.Size':<10} | {'Raw Offset':<10} | {'Raw Size':<10} | {'Энтропия':<8} | {'Атрибуты (Flags)':<22} |")
        log("-" * 105)
        
        for i in range(num_sections):
            off = sect_off + i * 40
            name = d[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
            vsize = struct.unpack('<I', d[off+8:off+12])[0]
            rva = struct.unpack('<I', d[off+12:off+16])[0]
            rawsz = struct.unpack('<I', d[off+16:off+20])[0]
            raw = struct.unpack('<I', d[off+20:off+24])[0]
            flags = struct.unpack('<I', d[off+36:off+40])[0]
            
            sec_data = d[raw:raw+rawsz]
            ent = calc_entropy(sec_data)
            
            sections.append({
                "name": name, "vsize": vsize, "rva": rva, 
                "rawsz": rawsz, "raw": raw, "flags": flags, "entropy": ent
            })
            
            flags_decoded = decode_section_flags(flags)
            log(f" | {name:<8} | 0x{rva:<8X} | 0x{vsize:<8X} | 0x{raw:<8X} | 0x{rawsz:<8X} | {ent:<8.2f} | {flags_decoded:<22} |")
        log()

        upx0_raw = upx1_raw = upx1_size = 0
        has_upx_sections = False
        upx0_ent = 0.0
        for s in sections:
            if s['name'] == 'UPX0':
                upx0_raw = s['raw']
                upx0_ent = s['entropy']
                has_upx_sections = True
            if s['name'] == 'UPX1':
                upx1_raw = s['raw']
                upx1_size = s['rawsz']

        upx_overlay = (d[-12:-8] == b'UPX!')

        log("1.6. Обнаружение и анализ пакера")
        log(f" -> Проверка таблицы секций: {'Найдены нестандартные имена секций UPX0/UPX1' if has_upx_sections else 'Секции UPX отсутствуют'}")
        log(f" -> Проверка оверлея: {'Найден маркер UPX! (байты 55 50 58 21) в последних 12 байтах файла' if upx_overlay else 'Оверлей отсутствует'}")
        if has_upx_sections:
             log(f" -> Анализ энтропии UPX: Энтропия UPX0 составляет {upx0_ent:.2f}.")
        log(" -> ИТОГОВЫЙ ВЫВОД: " + ("Файл упакован пакером UPX." if (has_upx_sections or upx_overlay) else "Следов упаковки UPX не найдено."))
        log()

        log_sep("=")
        log("ЧАСТЬ 2 - РЕШЕНИЕ ВОПРОСОВ")
        log_sep("=")
        log()

        log("ВОПРОС 1: Определите тип файла и пакер. Задокументируйте все сигнатуры.")
        log("ОТВЕТ:")
        file_type = "DLL (Динамическая библиотека)" if (characteristics & 0x2000) else "EXE (Исполняемая программа)"
        log(f" - Тип файла: Исполняемый файл Windows {file_type} (Архитектура: {'PE32+ (64-bit)' if is_pe32_plus else 'PE32 (32-bit)'}).")
        log(" - Обоснование: Присутствует DOS-заголовок (MZ по смещению 0x00), найдена корректная PE-сигнатура (50 45 00 00),")
        log("   проверены поля Characteristics и Subsystem в заголовках COFF и Optional Header.")
        
        if has_upx_sections or upx_overlay:
            log(" - Пакер: Обнаружен UPX (Ultimate Packer for executables).")
            log(" - Задокументированные сигнатуры упаковщика:")
            if has_upx_sections:
                log("    1. Аномалия таблицы секций: Имена стандартных секций (.text, .data) заменены на UPX0 и UPX1.")
            if upx_overlay:
                log(f"    2. Сигнатура оверлея: В хвосте файла по смещению -12 (от конца) обнаружены байты 55 50 58 21, что в ASCII читается как 'UPX!'.")
        else:
            log(" - Пакер: UPX не обнаружен.")
        log()

        log("ВОПРОС 2: В файле есть зашифрованная строка C2-адрес. Найдите метод шифрования, ключ и расшифруйте адрес.")
        log("ПРИМЕЧАНИЕ!!! Ответ может захапать лишние символы - формально так и задумано программой, некоторые значения переменной длины,")
        log("иначе не получится обработать нормально (айпи и mutex сравнивать с конфигом!!!!!!) - ПАРАМЕТР длины нигде не задается, так что вот так вот")
        log("ОТВЕТ:")
        c2_ip = "НЕ НАЙДЕН"
        c2_port = "НЕ НАЙДЕН"
        xor_key_val = None
        
        if upx0_raw > 0:
            try:
                xor_key_val = d[upx0_raw + 0xFF]
                enc_ip_block = d[upx0_raw + 0x100 : upx0_raw + 0x100 + 32]
                dec_ip_block = bytes(b ^ xor_key_val for b in enc_ip_block)
                c2_ip_full = dec_ip_block.split(b'\x00')[0].decode('ascii', errors='ignore')
                
                if ":" in c2_ip_full:
                    c2_ip, c2_port = c2_ip_full.split(":", 1)
                else:
                    c2_ip = c2_ip_full
                    
                log(" - Метод шифрования: Однобайтовый XOR-шифр.")
                log(f" - Поиск ключа: Согласно структуре данного семейства вредоносного ПО, ключ был успешно извлечен")
                log(f"   по абсолютному смещению UPX0_RAW + 0xFF (0x{upx0_raw + 0xFF:X}).")
                log(f" - Извлеченный ключ: 0x{xor_key_val:02X} (В десятичной системе: {xor_key_val}).")
                log(f" - Поиск данных: Зашифрованный блок считан по смещению UPX0_RAW + 0x100 (0x{upx0_raw + 0x100:X}).")
                log(" - Механика деобфускации: Каждый байт зашифрованного блока был пропущен через операцию исключающего ИЛИ (XOR)")
                log(f"   с найденным ключом 0x{xor_key_val:02X}, после чего байты были конвертированы обратно в ASCII-символы.")
                log(f" - Результат деобфускации: Сетевой индикатор компрометации (IP-адрес): {c2_ip}, Порт: {c2_port}.")
            except Exception as e:
                log(f" - Системная ошибка при извлечении: {e}")
        else:
            log(" - Ошибка: Секция UPX0 не найдена в файле, извлечение C2-адреса данным методом невозможно.")
        log()

        log("ВОПРОС 3: Найдите и расшифруйте конфигурационный блок малвари. Извлеките все параметры конфигурации.")
        log("ОТВЕТ:")
        
        pos_cfg = d.find(b'CFG\x01')
        cfg_params = []
        if pos_cfg >= 0:
            try:
                cfg_size = struct.unpack('<I', d[pos_cfg+4:pos_cfg+8])[0]
                rc4_key = d[pos_cfg+8:pos_cfg+24]
                enc_cfg = d[pos_cfg+24:pos_cfg+24+cfg_size]
                
                dec_cfg = rc4(rc4_key, enc_cfg)
                
                log(f" - Поиск маркера: Сигнатура 'CFG\\x01' (hex-значения: 43 46 47 01) найдена в файле по абсолютному смещению 0x{pos_cfg:X}.")
                log(f" - Чтение структуры: Сразу после маркера прочитан размер блока. Из-за архитектуры x86 байты перевернуты (little-endian).")
                log(f"   Используя распаковку '<I', вычислен размер зашифрованных данных: 0x{cfg_size:X} байт.")
                log(f" - Извлечение ключа RC4: Считаны 16 байт сразу после поля размера. Ключ: {rc4_key.hex()}")
                log(" - Алгоритм расшифровки: Зашифрованные данные и ключ переданы в кастомную реализацию алгоритма RC4.")
                log("   Инициализирован S-box (массив от 0 до 255), сгенерирован ключевой поток и применен XOR к шифротексту.")
                log(" - Расшифрованные параметры конфигурации (извлеченные ASCII-строки):")
                
                strings = [s.decode('ascii', errors='ignore') for s in dec_cfg.split(b'\x00') if len(s) > 2]
                for idx, s in enumerate(strings):
                    log(f"    [{idx+1}] {s}")
                    cfg_params.append(s)
            except Exception as e:
                log(f" - Ошибка при разборе структуры RC4: {e}")
        else:
            log(" - Ошибка: Маркер 'CFG\\x01' не найден. Конфигурация отсутствует или структура малвари была изменена.")
        log()

        log("ВОПРОС 4: Обнаружьте строку-идентификатор (mutex). Для чего он используется в малвари?")
        log("ПРИМЕНИЕ!! ПОЛУЧЕННУЮ СТРОКУ СРАВНИТЬ С КОНФИГОМ, СКОРЕЕ ВСЕГО ВОЗЬМЕТ ЛИШНИЕ СИМВОЛЫ")
        log("ОТВЕТ:")
        mutex_str = "НЕ НАЙДЕН"
        if upx0_raw > 0 and xor_key_val is not None:
            try:
                enc_mutex_block = d[upx0_raw + 0x140 : upx0_raw + 0x140 + 64]
                dec_mutex_block = bytes(b ^ xor_key_val for b in enc_mutex_block)
                mutex_str = dec_mutex_block.split(b'\x00')[0].decode('ascii', errors='ignore')
                
                log(f" - Локация: Зашифрованный блок найден по предсказуемому смещению UPX0_RAW + 0x140 (0x{upx0_raw + 0x140:X}).")
                log(f" - Деобфускация: К блоку применена математическая операция XOR с ранее найденным ключом 0x{xor_key_val:02X}.")
                log(f" - Извлеченный идентификатор (Имя мьютекса): {mutex_str}")
                log(" - Назначение: Сигнализация о присутствии вируса в системе для других его копий. Исключение нестабильности.")
            except Exception as e:
                log(f" - Ошибка при извлечении мьютекса: {e}")
        else:
             log(" - Ошибка: Невозможно расшифровать мьютекс (отсутствует секция UPX0 или не был найден XOR-ключ на предыдущем этапе).")
        log()

        log("ВОПРОС 5: Вычислите SHA256 упакованной секции. Составьте полный отчёт IoC.")
        log("ОТВЕТ:")
        if upx1_raw > 0 and upx1_size > 0:
            upx1_data = d[upx1_raw : upx1_raw + upx1_size]
            upx1_sha256 = hashlib.sha256(upx1_data).hexdigest()
            log(" - Логика извлечения: Блок данных секции UPX1 был считан от смещения Raw Offset до Raw Size и пропущен")
            log("   через алгоритм криптографического хэширования SHA256. Это позволит находить этот же payload даже в других дропперах.")
            log(f" - Вычисленный SHA256 для секции UPX1: {upx1_sha256}")
        else:
            log(" - Ошибка: Секция UPX1 не найдена в таблице секций. Невозможно вычислить хэш.")
            
        full_file_sha256 = hashlib.sha256(d).hexdigest()
        
        log()
        log("ТАБЛИЦА IoC")
        log(f"| {'Тип IoC':<18} | {'Извлеченное значение':<45} | {'Способ извлечения / Обоснование'}")
        log("-" * 115)
        log(f"| {'Сетевой (IP)' :<18} | {c2_ip:<45} | Деобфусцировано (XOR-блок в пустом пространстве UPX0)")
        if c2_port != "НЕ НАЙДЕН":
            log(f"| {'Сетевой (Порт)' :<18} | {c2_port:<45} | Деобфусцировано (Извлечено вместе с IP-адресом)")
        log(f"| {'Поведенческий' :<18} | {mutex_str:<45} | Системный мьютекс (XOR-расшифровано из UPX0)")
        log(f"| {'Криптографический':<18} | 0x{xor_key_val:02X} {' ' * 41} | Однобайтовый XOR-ключ, используемый для скрытия строк" if xor_key_val else f"| {'Криптографический':<18} | Нет данных |")
        if pos_cfg >= 0:
             log(f"| {'Криптографический':<18} | {rc4_key.hex():<45} | 16-байтный ключ RC4 (найден после сигнатуры 'CFG\\x01')")
        log(f"| {'Файловый (UPX1)' :<18} | {upx1_sha256:<45} | SHA256 сжатого payload'а (устойчив к полиморфизму дроппера)" if upx1_raw > 0 else f"| {'Файловый (UPX1)':<18} | Нет данных |")
        log(f"| {'Файловый (Полный)':<18} | {full_file_sha256:<45} | SHA256 всего анализируемого бинарного файла целиком")
        log("-" * 115)

        log()
        log_sep("=")
        log("ЧАСТЬ 3 - ВЫЧИСЛЕНИЯ ДЛЯ ВОПРОСОВ 2, 3, 4")
        log_sep("=")
        log()

        log("3.1. Подробный ход расшифровки C2-адреса (XOR):")
        if upx0_raw > 0 and xor_key_val is not None:
            step = 1
            for b in enc_ip_block:
                dec_b = b ^ xor_key_val
                char_rep = chr(dec_b) if 32 <= dec_b <= 126 else f'\\x{dec_b:02x}'
                if dec_b == 0:
                    log(f"{step}.     0x{b:02X} ^ 0x{xor_key_val:02X} = 0x00 (Конец строки)")
                    break
                log(f"{step}.     0x{b:02X} ^ 0x{xor_key_val:02X} = 0x{dec_b:02X} («{char_rep}»)")
                step += 1
        else:
            log("Нет данных для расшифровки.")
        log()

        log("3.2. Подробный ход расшифровки Mutex (XOR):")
        if upx0_raw > 0 and xor_key_val is not None:
            step = 1
            for b in enc_mutex_block:
                dec_b = b ^ xor_key_val
                char_rep = chr(dec_b) if 32 <= dec_b <= 126 else f'\\x{dec_b:02x}'
                if dec_b == 0:
                    log(f"{step}.     0x{b:02X} ^ 0x{xor_key_val:02X} = 0x00 (Конец строки)")
                    break
                log(f"{step}.     0x{b:02X} ^ 0x{xor_key_val:02X} = 0x{dec_b:02X} («{char_rep}»)")
                step += 1
        else:
            log("Нет данных для расшифровки.")
        log()

        log("3.3. Подробный ход расшифровки конфигурационного блока (RC4):")
        if pos_cfg >= 0:
            log("Сигнатура «CFG\\x01» (HEX: 43 46 47 01) найдена в файле.")
            log(f"Абсолютное смещение: 0x{pos_cfg:X}")
            log(f"Длина: {struct.pack('<I', cfg_size).hex().upper()} ({cfg_size} байт)")
            log(f"Ключ RC4: {' '.join(f'{b:02X}' for b in rc4_key)}")
            log("Для расшифровки требуется повторить шаги алгоритма:")
            log()
            log("1. Этап KSA – создание S-блока от S[0] до S[255]")
            log("   В массив по порядку записываются числа от 0 до 255, затем этот массив перемешивается на основе ключа.")
            
            S = list(range(256))
            log("   Начальное состояние S-блока: " + ", ".join(str(x) for x in S[:15]) + " ... " + ", ".join(str(x) for x in S[-5:]))
            log("   Формула перемешивания: j = (j + S[i] + key[i mod L]) mod 256")
            log()
            
            j = 0
            L = len(rc4_key)
            for i in range(256):
                k = rc4_key[i % L]
                old_j = j
                old_si = S[i]
                j = (j + S[i] + k) % 256
                log(f"   Шаг i = {i} => key[{i} mod {L}] = 0x{k:02X} ({k}), j = ({old_j} + {old_si} + {k}) mod 256 = {j} => требуется поменять местами S[{i}] и S[{j}], теперь S[{i}] = {S[j]}, а S[{j}] = {old_si}.")
                S[i], S[j] = S[j], S[i]

            log()
            log("   Процесс повторяется 256 раз до i = 255, формируя финальное состояние S-блока.")
            log("   Состояние S-блока после перемешивания: " + ", ".join(str(x) for x in S[:15]) + " ...")
            log()
            log("2. Этап генерации гаммы и расшифровка (PRGA)")
            log("   После перемешивания S-блока начинается генерация байтов гаммы (K).")
            log("   Для каждого байта зашифрованного текста генерируется один байт гаммы.")
            log()

            i_prga = 0
            j_prga = 0
            full_dec_bytes = bytearray()
            for idx, cipher_byte in enumerate(enc_cfg):
                i_prga = (i_prga + 1) % 256
                j_prga = (j_prga + S[i_prga]) % 256
                S[i_prga], S[j_prga] = S[j_prga], S[i_prga]
                t = (S[i_prga] + S[j_prga]) % 256
                K = S[t]
                plain_byte = cipher_byte ^ K
                full_dec_bytes.append(plain_byte)

                char_rep = chr(plain_byte) if 32 <= plain_byte <= 126 else f'\\x{plain_byte:02x}'
                log(f"   Байт {idx+1}. Шифртекст – байт {cipher_byte:02X}, байт гаммы K{idx+1} = {K:02X}, расчет: 0x{cipher_byte:02X} ^ 0x{K:02X} = 0x{plain_byte:02X} (символ «{char_rep}»)")

            log()
            log("Результат полной расшифровки: " + full_dec_bytes.decode('ascii', errors='ignore'))
        else:
            log("Нет данных для расшифровки RC4.")

        log()

if __name__ == "__main__":
    target_file = "g1_s14.exe"
    
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
        
    analyze_dropper(target_file)