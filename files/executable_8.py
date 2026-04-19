import struct
import sys
import os
import datetime

def read_null_term_string(f, offset):
    original_pos = f.tell()
    f.seek(offset)
    chars = []
    while True:
        char = f.read(1)
        if char == b'\x00' or not char:
            break
        chars.append(char)
    f.seek(original_pos)
    try:
        return b''.join(chars).decode('ascii', errors='ignore')
    except:
        return "<ошибка>"

def rva_to_offset(rva, sections):
    for sec in sections:
        if sec['vaddr'] <= rva < sec['vaddr'] + max(sec['vsize'], sec['raw_size']):
            return rva - sec['vaddr'] + sec['raw_ptr']
    return 0

def analyze_pe(file_path):
    if not os.path.exists(file_path):
        print(f"Файл {file_path} не найден.")
        return

    report_path = f"{os.path.splitext(file_path)[0]}_lab_report_full.txt"
    
    with open(file_path, "rb") as f, open(report_path, "w", encoding="utf-8") as out:
        
        def log(text=""):
            out.write(text + "\n")
            
        def log_separator(char="=", length=110):
            log(char * length)

        log_separator("=")
        log(f"{'ЛАБОРАТОРНАЯ РАБОТА №8':^110}")
        log(f"{'Файл: ' + os.path.basename(file_path):^110}")
        log_separator("=")
        log()

        f.seek(0)
        e_magic_bytes = f.read(2)
        f.seek(0x3C)
        e_lfanew = struct.unpack("<I", f.read(4))[0]
        f.seek(e_lfanew)
        pe_signature = f.read(4)
        pe_sig_bytes = pe_signature 
        
        f.seek(e_lfanew + 4 + 16)
        size_opt_header = struct.unpack("<H", f.read(2))[0]
        opt_header_offset = e_lfanew + 24
        
        f.seek(e_lfanew + 4 + 2)
        num_sections = struct.unpack("<H", f.read(2))[0]
        
        section_table_offset = opt_header_offset + size_opt_header
        f.seek(section_table_offset)
        sections = []
        for i in range(num_sections):
            name = f.read(8).decode('utf-8', 'ignore').strip('\x00')
            vsize, vaddr, raw_size, raw_ptr, ptr_reloc, ptr_line, num_reloc, num_line, characts = struct.unpack("<IIIIIIHHI", f.read(32))
            sections.append({"name": name, "vsize": vsize, "vaddr": vaddr, "raw_size": raw_size, "raw_ptr": raw_ptr, "characts": characts})

        log("ЧАСТЬ 1: ОТВЕТЫ НА ЗАДАНИЯ ЛАБОРАТОРНОЙ РАБОТЫ")
        log_separator("-")
        
        log("1) DOS-заголовок и DOS-заглушка:")
        log(f"   -> Сигнатура MZ (e_magic): {e_magic_bytes} (Корректна: {e_magic_bytes == b'MZ'})")
        log(f"   -> Смещение до PE-заголовка (e_lfanew): 0x{e_lfanew:08X} (хранится в little-endian)")
        if e_lfanew > 0x40:
            f.seek(0x40)
            dos_stub = f.read(e_lfanew - 0x40)
            printable = ''.join(chr(b) for b in dos_stub if 32 <= b <= 126 or b in (10, 13))
            log(f"   -> DOS-заглушка (сообщение): \"{' '.join(printable.split())}\"")
            if b'Rich' in dos_stub:
                log(f"   -> Обнаружена сигнатура 'Rich' (указывает на использование линкера MSVC/индикация toolchain).")
        log()

        log("2) PE-заголовок (COFF File Header):")
        log(f"   -> Сигнатура PE: {pe_signature}")
        f.seek(e_lfanew + 4)
        machine, _, timestamp, _, _, _, characteristics = struct.unpack("<HHIIIHH", f.read(20))
        machine_str = "x86 (IMAGE_FILE_MACHINE_I386, 0x014C)" if machine == 0x014C else "x64 (IMAGE_FILE_MACHINE_AMD64, 0x8664)" if machine == 0x8664 else f"0x{machine:04X}"
        
        chars_list = []
        if characteristics & 0x0002: chars_list.append("Executable (0x0002)")
        if characteristics & 0x0100: chars_list.append("32-bit word machine (0x0100)")
        if characteristics & 0x2000: chars_list.append("DLL (0x2000)")
        if characteristics & 0x0020: chars_list.append("Large address aware (0x0020)")
        chars_str = ", ".join(chars_list) if chars_list else "Unknown"

        dt = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        log(f"   -> Архитектура (Machine): {machine_str}")
        log(f"   -> Количество секций: {num_sections}")
        log(f"   -> Дата компиляции (TimeDateStamp, UNIX формат): {dt} (0x{timestamp:08X})")
        log(f"   -> Размер опционального заголовка: 0x{size_opt_header:04X}")
        log(f"   -> Тип файла: {'DLL' if (characteristics & 0x2000) else 'EXE'} (Characteristics: 0x{characteristics:04X} [{chars_str}])")
        log()

        log("3) Optional Header:")
        f.seek(opt_header_offset)
        magic = struct.unpack("<H", f.read(2))[0]
        is_pe32_plus = (magic == 0x20B)
        log(f"   -> Формат опционального заголовка (Magic): {'PE32+ (64-bit, 0x020B)' if is_pe32_plus else 'PE32 (32-bit, 0x010B)'}")
        f.seek(opt_header_offset + 16)
        ep_rva = struct.unpack("<I", f.read(4))[0]
        
        if is_pe32_plus:
            f.seek(opt_header_offset + 24)
            image_base = struct.unpack("<Q", f.read(8))[0]
            f.seek(opt_header_offset + 32)
            sec_align, file_align = struct.unpack("<II", f.read(8))
            f.seek(opt_header_offset + 56)
            size_of_image, size_of_headers, _ = struct.unpack("<III", f.read(12))
            f.seek(opt_header_offset + 68)
            subsystem = struct.unpack("<H", f.read(2))[0]
            data_dir_offset = opt_header_offset + 112
        else:
            f.seek(opt_header_offset + 28)
            image_base = struct.unpack("<I", f.read(4))[0]
            f.seek(opt_header_offset + 32)
            sec_align, file_align = struct.unpack("<II", f.read(8))
            f.seek(opt_header_offset + 56)
            size_of_image, size_of_headers, _ = struct.unpack("<III", f.read(12))
            f.seek(opt_header_offset + 68)
            subsystem = struct.unpack("<H", f.read(2))[0]
            data_dir_offset = opt_header_offset + 96

        log(f"   -> AddressOfEntryPoint (RVA): 0x{ep_rva:08X}")
        log(f"   -> ImageBase: 0x{image_base:X}")
        log(f"   -> SectionAlignment: 0x{sec_align:X} (Выравнивание в виртуальной памяти)")
        log(f"   -> FileAlignment: 0x{file_align:X} (Выравнивание на диске)")
        log(f"   -> SizeOfImage: 0x{size_of_image:X}")
        log(f"   -> SizeOfHeaders: 0x{size_of_headers:X}")
        
        sub_str = "Windows GUI (2)" if subsystem == 2 else "Windows CUI / Console (3)" if subsystem == 3 else f"{subsystem}"
        log(f"   -> Subsystem: {sub_str}")
        
        log("   -> Массив DataDirectory (Директории данных):")
        dir_names = [
            "Export Table", "Import Table", "Resource Table", "Exception Table",
            "Certificate Table", "Base Relocation Table", "Debug", "Architecture",
            "Global Ptr", "TLS Table", "Load Config Table", "Bound Import",
            "IAT", "Delay Import", "CLR Runtime Header", "Reserved"
        ]
        f.seek(data_dir_offset)
        import_rva = import_size = 0
        for idx, dname in enumerate(dir_names):
            d_rva, d_sz = struct.unpack("<II", f.read(8))
            if dname == "Import Table":
                import_rva, import_size = d_rva, d_sz
            if d_rva != 0 or d_sz != 0:
                log(f"      [{idx:2d}] {dname:<22}: RVA 0x{d_rva:08X}, Size 0x{d_sz:08X}")
        log()

        log("4) Таблица секций (Section Table):")
        log(f"   -> Количество записей (секций): {num_sections}")
        ep_sec = "Не найдена"
        for s in sections:
            log(f"      [{s['name']:<8}] VAddr: 0x{s['vaddr']:08X}, VSize: 0x{s['vsize']:08X}, RawPtr: 0x{s['raw_ptr']:08X}, RawSize: 0x{s['raw_size']:08X}, Attr: 0x{s['characts']:08X}")
            if s['vaddr'] <= ep_rva < s['vaddr'] + max(s['vsize'], s['raw_size']):
                ep_sec = s['name']
        
        log(f"   -> Сопоставление точки входа:")
        log(f"      Точка входа (RVA 0x{ep_rva:08X}) находится в секции: {ep_sec}")
        if ep_sec != "Не найдена":
            for s in sections:
                if s['name'] == ep_sec:
                    ep_file_offset = ep_rva - s['vaddr'] + s['raw_ptr']
                    log(f"      Формула перевода RVA в физическое смещение (File Offset):")
                    log(f"      FileOffset = RVA (0x{ep_rva:0X}) - VirtualAddress (0x{s['vaddr']:0X}) + PointerToRawData (0x{s['raw_ptr']:0X}) = 0x{ep_file_offset:08X}")
        log()

        log("5) Секция импорта (Import Directory Table):")
        dlls = []
        if import_rva != 0:
            f.seek(rva_to_offset(import_rva, sections))
            while True:
                ilt_rva, ts, fc, name_rva, iat_rva = struct.unpack("<IIIII", f.read(20))
                if ilt_rva == 0 and name_rva == 0: break
                dlls.append({"ilt": ilt_rva, "name_rva": name_rva, "iat": iat_rva})
            
            log(f"   -> Найдено импортируемых библиотек: {len(dlls)}")
            for d in dlls:
                name = read_null_term_string(f, rva_to_offset(d['name_rva'], sections))
                d['name_str'] = name
                log(f"      * {name}: ILT (OriginalFirstThunk)=0x{d['ilt']:08X}, IAT (FirstThunk)=0x{d['iat']:08X}")
                
                lookup = d['ilt'] if d['ilt'] != 0 else d['iat']
                off = rva_to_offset(lookup, sections)
                if off:
                    f.seek(off)
                    ptr_sz = 8 if is_pe32_plus else 4
                    ord_flag = 0x8000000000000000 if is_pe32_plus else 0x80000000
                    fmt = "<Q" if is_pe32_plus else "<I"
                    
                    count = 0
                    while count < 100:
                        thunk = struct.unpack(fmt, f.read(ptr_sz))[0]
                        if thunk == 0: break
                        if thunk & ord_flag:
                            log(f"        - Импорт по порядковому номеру (Ordinal): {thunk & 0xFFFF}")
                        else:
                            hrva = thunk & 0x7FFFFFFF
                            hoff = rva_to_offset(hrva, sections)
                            if hoff:
                                cur = f.tell()
                                f.seek(hoff)
                                hint = struct.unpack("<H", f.read(2))[0]
                                fn = read_null_term_string(f, f.tell())
                                f.seek(cur)
                                log(f"        - Импорт по имени: {fn} (Hint: 0x{hint:04X})")
                        count += 1
        else:
            log("   -> Импорт отсутствует.")
        log()


        log()
        log_separator("=")
        log("ЧАСТЬ 2: ДЕТАЛЬНЫЙ РАЗБОР В ВИДЕ 9 ТАБЛИЦ (по методичке)")
        log_separator("=")
        log()

        def print_table_header(title, cols):
            log(title)
            header_str = "| " + " | ".join(f"{c[0]:<{c[1]}}" for c in cols) + " |"
            log("-" * len(header_str))
            log(header_str)
            log("-" * len(header_str))
            return cols

        def print_table_row(cols, row_data):
            row_str = "| " + " | ".join(f"{str(d):<{c[1]}}" for c, d in zip(cols, row_data)) + " |"
            log(row_str)

        cols = [("Смещение", 10), ("Размер (байт)", 15), ("Поле", 15), ("Значение", 30)]
        print_table_header("Таблица 1. Структура DOS-заголовка", cols)
        
        f.seek(0)
        dos_data = f.read(64)
        dos_fields = [
            ("0x00", 2, "e_magic", f"{dos_data[0:2]}"),
            ("0x02", 2, "e_cblp", f"0x{struct.unpack('<H', dos_data[2:4])[0]:04X}"),
            ("0x04", 2, "e_cp", f"0x{struct.unpack('<H', dos_data[4:6])[0]:04X}"),
            ("0x06", 2, "e_crlc", f"0x{struct.unpack('<H', dos_data[6:8])[0]:04X}"),
            ("0x08", 2, "e_cparhdr", f"0x{struct.unpack('<H', dos_data[8:10])[0]:04X}"),
            ("0x0A", 2, "e_minalloc", f"0x{struct.unpack('<H', dos_data[10:12])[0]:04X}"),
            ("0x0C", 2, "e_maxalloc", f"0x{struct.unpack('<H', dos_data[12:14])[0]:04X}"),
            ("0x0E", 2, "e_ss", f"0x{struct.unpack('<H', dos_data[14:16])[0]:04X}"),
            ("0x10", 2, "e_sp", f"0x{struct.unpack('<H', dos_data[16:18])[0]:04X}"),
            ("0x12", 2, "e_csum", f"0x{struct.unpack('<H', dos_data[18:20])[0]:04X}"),
            ("0x14", 2, "e_ip", f"0x{struct.unpack('<H', dos_data[20:22])[0]:04X}"),
            ("0x16", 2, "e_cs", f"0x{struct.unpack('<H', dos_data[22:24])[0]:04X}"),
            ("0x18", 2, "e_lfarlc", f"0x{struct.unpack('<H', dos_data[24:26])[0]:04X}"),
            ("0x1A", 2, "e_ovno", f"0x{struct.unpack('<H', dos_data[26:28])[0]:04X}"),
            ("0x1C", 8, "e_res[4]", f"{dos_data[28:36].hex().upper()}"),
            ("0x24", 2, "e_oemid", f"0x{struct.unpack('<H', dos_data[36:38])[0]:04X}"),
            ("0x26", 2, "e_oeminfo", f"0x{struct.unpack('<H', dos_data[38:40])[0]:04X}"),
            ("0x28", 20, "e_res2[10]", f"{dos_data[40:60].hex()[:15]}..."),
            ("0x3C", 4, "e_lfanew", f"0x{e_lfanew:08X}")
        ]
        for r in dos_fields: print_table_row(cols, r)
        log()

        print_table_header("Таблица 2. Структура сигнатуры и заголовка файла", cols)
        print_table_row(cols, ("0x00", 4, "Signature", str(pe_sig_bytes)))
        
        f.seek(e_lfanew + 4)
        coff_data = f.read(20)
        u = struct.unpack("<HHIIIHH", coff_data)
        coff_fields = [
            ("0x00", 2, "Machine", f"0x{u[0]:04X}"),
            ("0x02", 2, "NumberOfSections", f"0x{u[1]:04X} ({u[1]})"),
            ("0x04", 4, "TimeDateStamp", f"0x{u[2]:08X}"),
            ("0x08", 4, "PointerToSymbolTable", f"0x{u[3]:08X}"),
            ("0x0C", 4, "NumberOfSymbols", f"0x{u[4]:08X}"),
            ("0x10", 2, "SizeOfOptionalHeader", f"0x{u[5]:04X} ({u[5]})"),
            ("0x12", 2, "Characteristics", f"0x{u[6]:04X}")
        ]
        for r in coff_fields: print_table_row(cols, r)
        log()

        print_table_header("Таблица 3. Структура опционального заголовка", cols)
        f.seek(opt_header_offset)
        
        def read_opt(fmt, size, name, offset):
            val = struct.unpack(fmt, f.read(size))[0]
            hex_fmt = f"0x{{:0{size*2}X}}"
            print_table_row(cols, (f"0x{offset:02X}", size, name, hex_fmt.format(val)))
            return val

        read_opt("<H", 2, "Magic", 0x00)
        read_opt("<B", 1, "MajorLinkerVersion", 0x02)
        read_opt("<B", 1, "MinorLinkerVersion", 0x03)
        read_opt("<I", 4, "SizeOfCode", 0x04)
        read_opt("<I", 4, "SizeOfInitData", 0x08)
        read_opt("<I", 4, "SizeOfUninitData", 0x0C)
        read_opt("<I", 4, "AddressOfEntryPoint", 0x10)
        read_opt("<I", 4, "BaseOfCode", 0x14)
        
        offset_counter = 0x18
        if not is_pe32_plus:
            read_opt("<I", 4, "BaseOfData", offset_counter)
            offset_counter += 4
            
        fmt_base = "<Q" if is_pe32_plus else "<I"
        sz_base = 8 if is_pe32_plus else 4
        
        read_opt(fmt_base, sz_base, "ImageBase", offset_counter); offset_counter += sz_base
        read_opt("<I", 4, "SectionAlignment", offset_counter); offset_counter += 4
        read_opt("<I", 4, "FileAlignment", offset_counter); offset_counter += 4
        read_opt("<H", 2, "MajorOperatingSystem", offset_counter); offset_counter += 2
        read_opt("<H", 2, "MinorOperatingSystem", offset_counter); offset_counter += 2
        read_opt("<H", 2, "MajorImageVersion", offset_counter); offset_counter += 2
        read_opt("<H", 2, "MinorImageVersion", offset_counter); offset_counter += 2
        read_opt("<H", 2, "MajorSubsystemVer", offset_counter); offset_counter += 2
        read_opt("<H", 2, "MinorSubsystemVer", offset_counter); offset_counter += 2
        read_opt("<I", 4, "Win32VersionValue", offset_counter); offset_counter += 4
        read_opt("<I", 4, "SizeOfImage", offset_counter); offset_counter += 4
        read_opt("<I", 4, "SizeOfHeaders", offset_counter); offset_counter += 4
        read_opt("<I", 4, "CheckSum", offset_counter); offset_counter += 4
        read_opt("<H", 2, "Subsystem", offset_counter); offset_counter += 2
        read_opt("<H", 2, "DllCharacteristics", offset_counter); offset_counter += 2
        read_opt(fmt_base, sz_base, "SizeOfStackReserve", offset_counter); offset_counter += sz_base
        read_opt(fmt_base, sz_base, "SizeOfStackCommit", offset_counter); offset_counter += sz_base
        read_opt(fmt_base, sz_base, "SizeOfHeapReserve", offset_counter); offset_counter += sz_base
        read_opt(fmt_base, sz_base, "SizeOfHeapCommit", offset_counter); offset_counter += sz_base
        read_opt("<I", 4, "LoaderFlags", offset_counter); offset_counter += 4
        read_opt("<I", 4, "NumberOfRvaAndSizes", offset_counter)
        log()
        
        cols_dir = [("Индекс/Смещ.", 15), ("Размер", 10), ("Поле", 25), ("RVA", 15), ("Size", 15)]
        print_table_header("Таблица 4. Структура директории данных", cols_dir)
        
        f.seek(data_dir_offset)
        for i, name in enumerate(dir_names):
            rva, sz = struct.unpack("<II", f.read(8))
            print_table_row(cols_dir, (f"[{i}] 0x{i*8:02X}", 8, name, f"0x{rva:08X}", f"0x{sz:08X}"))
        log()

        cols_attr = [("Секция", 10), ("ФЛАГ", 35), ("ЗНАЧЕНИЕ", 15), ("ОПИСАНИЕ", 40)]
        print_table_header("Таблица 5. Атрибуты секций (согласно файлу)", cols_attr)
        
        flag_map = {
            0x00000020: ("IMAGE_SCN_CNT_CODE", "Исполняемый код"),
            0x00000040: ("IMAGE_SCN_CNT_INITIALIZED_DATA", "Инициализированные данные"),
            0x00000080: ("IMAGE_SCN_CNT_UNINITIALIZED_DATA", "Неинициализированные данные"),
            0x20000000: ("IMAGE_SCN_MEM_EXECUTE", "Разрешено к выполнению"),
            0x40000000: ("IMAGE_SCN_MEM_READ", "Разрешено к чтению"),
            0x80000000: ("IMAGE_SCN_MEM_WRITE", "Разрешено к записи")
        }

        for s in sections:
            characts = s['characts']
            for val, (fname, desc) in flag_map.items():
                if characts & val:
                    print_table_row(cols_attr, (s['name'], fname, f"0x{val:08X}", desc))
        log()

        cols_sec = [("NAME", 8), ("VIRT.SIZE", 10), ("VIRT.ADDR", 10), ("RAW DATA", 10), ("RAW PTR", 10), ("RELOC PTR", 10), ("CHARACTERS", 12)]
        print_table_header("Таблица 6. Таблица секций", cols_sec)
        
        f.seek(section_table_offset)
        for i in range(num_sections):
            name = f.read(8).decode('utf-8', 'ignore').strip('\x00')
            vs, va, rs, rp, pr, pl, nr, nl, ch = struct.unpack("<IIIIIIHHI", f.read(32))
            print_table_row(cols_sec, (name, f"0x{vs:X}", f"0x{va:X}", f"0x{rs:X}", f"0x{rp:X}", f"0x{pr:X}", f"0x{ch:08X}"))
        log()

        cols_idt = [("ILT RVA", 15), ("TIME/DATE", 15), ("FORWARDER", 15), ("NAME RVA", 15), ("IAT RVA", 15)]
        print_table_header("Таблица 7. Import Directory Table", cols_idt)
        
        if dlls:
            for d in dlls:
                print_table_row(cols_idt, (f"0x{d['ilt']:08X}", "0", "0", f"0x{d['name_rva']:08X}", f"0x{d['iat']:08X}"))
        else:
            print_table_row(cols_idt, ("-", "-", "Пусто", "-", "-"))
        log()

        cols_ilt = [("RVA (Смещение)", 20), ("ЗНАЧЕНИЕ (Thunk/Hint)", 60)]
        
        for i in range(2):
            table_num = 8 + i
            if i < len(dlls):
                d = dlls[i]
                print_table_header(f"Таблица {table_num}. {d['name_str']} (Import Lookup Table)", cols_ilt)
                
                lookup = d['ilt'] if d['ilt'] != 0 else d['iat']
                off = rva_to_offset(lookup, sections)
                if off:
                    f.seek(off)
                    ptr_sz = 8 if is_pe32_plus else 4
                    fmt = "<Q" if is_pe32_plus else "<I"
                    current_rva = lookup
                    
                    count = 0
                    while count < 100:
                        thunk = struct.unpack(fmt, f.read(ptr_sz))[0]
                        if thunk == 0:
                            print_table_row(cols_ilt, (f"0x{current_rva:08X}", "0x0 (Конец таблицы)"))
                            break
                        print_table_row(cols_ilt, (f"0x{current_rva:08X}", f"0x{thunk:016X}" if is_pe32_plus else f"0x{thunk:08X}"))
                        current_rva += ptr_sz
                        count += 1
            else:
                print_table_header(f"Таблица {table_num}. Отсутствует (в файле меньше {i+1} DLL)", cols_ilt)
                print_table_row(cols_ilt, ("-", "-"))
            log()


        log()
        log_separator("=")
        log("ЧАСТЬ 3: ОТВЕТЫ НА ВОПРОСЫ ПРАКТИЧЕСКОГО ЗАДАНИЯ")
        log_separator("=")
        log()

        pe_sig_hex = ' '.join(f'{b:02X}' for b in pe_sig_bytes)
        ans1 = f"e_lfanew: 0x{e_lfanew:08X}, байты по смещению e_lfanew: {pe_sig_hex}"
        log("Вопрос 1: \"В hex-редакторе найдите поле e_lfanew структуры IMAGE_DOS_HEADER. Запишите значение в hex со всеми нулями. Запишите байты по смещению e_lfanew в файле.\"")
        log(f"Ответ: \"{ans1}\"")
        log()

        va = image_base + ep_rva
        if is_pe32_plus:
            ans2 = f"ImageBase: 0x{image_base:016X}, EP RVA: 0x{ep_rva:08X}, VA: 0x{va:016X}"
        else:
            ans2 = f"ImageBase: 0x{image_base:08X}, EP RVA: 0x{ep_rva:08X}, VA: 0x{va:08X}"
        log("Вопрос 2: \"В Optional Header PE32+ найдите: ImageBase. AddressOfEntryPoint. VA. Запишите ImageBase, EP RVA и VA в hex. Со всеми нулями.\"")
        log(f"Ответ: \"{ans2}\"")
        log()

        total_raw_size = sum(s['raw_size'] for s in sections)
        sec_sizes = ", ".join([f"{s['name']}: 0x{s['raw_size']:08X}" for s in sections])
        ans3 = f"SizeOfRawData по секциям -> {sec_sizes}. Суммарный размер: 0x{total_raw_size:08X} ({total_raw_size} байт)"
        log("Вопрос 3: \"В таблице секций (следует после Optional Header) у каждой секции есть поле SizeOfRawData. Найдите SizeOfRawData для каждой секции. Вычислите суммарный размер всех секций на диске (сумма SizeOfRawData). Ответ в байтах: hex и десятичное.\"")
        log(f"Ответ: \"{ans3}\"")
        log()

        size_kb = size_of_image / 1024
        ans4 = f"SizeOfImage: 0x{size_of_image:08X}, {size_kb:g} КБ"
        log("Вопрос 4: \"В Optional Header найдите поле SizeOfImage. Это размер образа в виртуальной памяти (в байтах), выровненный по SectionAlignment. Запишите значение в hex и в килобайтах (десятичное).\"")
        log(f"Ответ: \"{ans4}\"")
        log()

        f.seek(data_dir_offset + 12 * 8)
        iat_rva, iat_size = struct.unpack("<II", f.read(8))
        iat_file_offset = rva_to_offset(iat_rva, sections)
        ans5 = f"RVA IAT: 0x{iat_rva:08X}, FileOffset IAT: 0x{iat_file_offset:08X}"
        log("Вопрос 5: \"Прочитайте RVA из DataDirectory[12] и вычислите файловое смещение IAT (используйте таблицу секций). Запишите: RVA IAT и FileOffset IAT в hex.\"")
        log(f"Ответ: \"{ans5}\"")
        log()


if __name__ == "__main__":
    target_file = "variant_8.exe" 
    
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
        
    analyze_pe(target_file)