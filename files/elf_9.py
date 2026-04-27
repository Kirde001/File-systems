import struct
import sys
import os

def decode_flags(flags):
    r = 'R' if flags & 4 else '-'
    w = 'W' if flags & 2 else '-'
    x = 'X' if flags & 1 else '-'
    return f"{r}{w}{x}"

def p_type_to_str(ptype):
    types = {0: "PT_NULL", 1: "PT_LOAD", 2: "PT_DYNAMIC", 3: "PT_INTERP", 
             4: "PT_NOTE", 5: "PT_SHLIB", 6: "PT_PHDR", 7: "PT_TLS"}
    return types.get(ptype, f"UNKNOWN ({ptype})")

def analyze_elf(file_path):
    if not os.path.exists(file_path):
        print(f"Файл {file_path} не найден.")
        return

    report_path = f"{os.path.splitext(file_path)[0]}_report.txt"
    
    with open(file_path, "rb") as f, open(report_path, "w", encoding="utf-8") as out:
        def log(text=""):
            out.write(text + "\n")

        f.seek(0)
        e_ident = f.read(16)
        if e_ident[:4] != b'\x7fELF':
            log("Ошибка: Это не ELF файл.")
            return
            
        f.seek(28)
        e_phoff = struct.unpack("<I", f.read(4))[0]
        f.seek(32)
        e_shoff = struct.unpack("<I", f.read(4))[0]
        f.seek(42)
        e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack("<HHHHH", f.read(10))

        f.seek(e_shoff + e_shstrndx * e_shentsize)
        shstrtab_hdr = f.read(e_shentsize)
        shstrtab_offset, shstrtab_size = struct.unpack("<II", shstrtab_hdr[16:24])
        f.seek(shstrtab_offset)
        shstrtab = f.read(shstrtab_size)

        def get_string(offset):
            end = shstrtab.find(b'\x00', offset)
            return shstrtab[offset:end].decode('utf-8', errors='ignore')

        log("=====================================================================")
        log(f"ЛАБОРАТОРНАЯ РАБОТА №9. Отчет по файлу: {os.path.basename(file_path)}")
        log("=====================================================================\n")

        log("Вопрос 1 - ответы:")
        phdr0_offset = e_phoff
        log(f"1. Смещение первого программного заголовка (Phdr[0]): 0x{phdr0_offset:08X}")
        
        f.seek(phdr0_offset)
        phdr0_bytes = f.read(32)
        hex_dump0 = " ".join(f"{b:02X}" for b in phdr0_bytes)
        log(f"2. Hex-дамп (32 байта): {hex_dump0}")
        
        p_type0, p_offset0, p_vaddr0, p_paddr0, p_filesz0, p_memsz0, p_flags0, p_align0 = struct.unpack("<IIIIIIII", phdr0_bytes)
        log("3. Разбор полей Elf32_Phdr (LE, 4 байта каждое):")
        log(f"   p_type:   0x{p_type0:08X}")
        log(f"   p_offset: 0x{p_offset0:08X}")
        log(f"   p_vaddr:  0x{p_vaddr0:08X}")
        log(f"   p_paddr:  0x{p_paddr0:08X}")
        log(f"   p_filesz: 0x{p_filesz0:08X}")
        log(f"   p_memsz:  0x{p_memsz0:08X}")
        log(f"   p_flags:  0x{p_flags0:08X}")
        log(f"   p_align:  0x{p_align0:08X}")
        
        log(f"4. Словесная декодировка p_type: {p_type_to_str(p_type0)}")
        log(f"5. Права доступа (p_flags): '{decode_flags(p_flags0)}'\n")

        log("Вопрос 2 - ответы:")
        phdr1_offset = e_phoff + e_phentsize
        log(f"1. Смещение второго программного заголовка (Phdr[1]): 0x{phdr1_offset:08X}")
        
        f.seek(phdr1_offset)
        phdr1_bytes = f.read(32)
        hex_dump1 = " ".join(f"{b:02X}" for b in phdr1_bytes)
        log(f"2. Hex-дамп (32 байта): {hex_dump1}")
        
        p_type1, p_offset1, p_vaddr1, p_paddr1, p_filesz1, p_memsz1, p_flags1, p_align1 = struct.unpack("<IIIIIIII", phdr1_bytes)
        log("3. Разбор полей Elf32_Phdr:")
        log(f"   p_type: {p_type_to_str(p_type1)}, p_offset: 0x{p_offset1:08X}, p_vaddr: 0x{p_vaddr1:08X}, p_paddr: 0x{p_paddr1:08X}")
        log(f"   p_filesz: 0x{p_filesz1:08X} ({p_filesz1}), p_memsz: 0x{p_memsz1:08X} ({p_memsz1}), p_flags: 0x{p_flags1:08X}, p_align: 0x{p_align1:08X}")
        
        log(f"4. Разница p_filesz и p_memsz: p_filesz ({p_filesz1}) - это размер сегмента на диске, а p_memsz ({p_memsz1}) - размер в оперативной памяти.")
        log("   p_memsz > p_filesz из-за неинициализированных глобальных переменных. Эта разница объясняется наличием секции .bss, которая не занимает места в файле (хранятся только метаданные), но под нее выделяется нулевая память при загрузке.")
        
        nobits_size = 0
        nobits_name = ""
        for i in range(e_shnum):
            f.seek(e_shoff + i * e_shentsize)
            sh_name_idx, sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack("<IIIIII", f.read(24))
            if sh_type == 8: 
                nobits_size = sh_size
                nobits_name = get_string(sh_name_idx)
                break
                
        diff = p_memsz1 - p_filesz1
        log(f"5. Секция типа SHT_NOBITS найдена: '{nobits_name}'. Ее размер (sh_size): 0x{nobits_size:08X} ({nobits_size} байт).")
        log(f"   Проверка: p_memsz - p_filesz = {p_memsz1} - {p_filesz1} = {diff}. Условие sh_size == p_memsz - p_filesz -> {nobits_size == diff}\n")

        log("Вопрос 3 - ответы:")
        end_vaddr0 = p_vaddr0 + p_memsz0
        log(f"Диапазон Phdr[0] (PT_LOAD): 0x{p_vaddr0:08X} - 0x{end_vaddr0:08X}")
        log("| Индекс | Имя             | sh_addr    | Входит? |")
        log("|--------|-----------------|------------|---------|")
        
        for i in range(1, min(9, e_shnum)): 
            f.seek(e_shoff + i * e_shentsize)
            sh_name_idx, sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack("<IIIIII", f.read(24))
            s_name = get_string(sh_name_idx)
            if not s_name: s_name = "<null>"
            
            end_addr = sh_addr + sh_size
            is_inside = "Да" if (sh_addr >= p_vaddr0 and end_addr <= end_vaddr0) else "Нет"
            log(f"| {i:<6} | {s_name:<15} | 0x{sh_addr:08X} | {is_inside:<7} |")
        log()

        log("Вопрос 4 - ответы:")
        log(f"1. p_flags сегмента 1 (Phdr[0]): 0x{p_flags0:08X}")
        log(f"   p_flags сегмента 2 (Phdr[1]): 0x{p_flags1:08X}")
        
        log(f"2. Декодированные флаги:")
        log(f"   - Phdr[0] (Код): '{decode_flags(p_flags0)}'. W (запись) отсутствует, чтобы предотвратить случайное или злонамеренное изменение исполняемого кода в памяти.")
        log(f"   - Phdr[1] (Данные): '{decode_flags(p_flags1)}'. X (исполнение) отсутствует для защиты от атак типа переполнения буфера (предотвращает выполнение внедренного кода).")
        log("   Установка W для .text приведет к уязвимости: процесс сможет сам модифицировать свои инструкции во время выполнения, что нарушает безопасность (W^X / DEP).")
        
        log(f"3. Выравнивание (p_align): Phdr[0]=0x{p_align0:X}, Phdr[1]=0x{p_align1:X}. Это означает, что загрузчик ОС (например, mmap) будет отображать эти сегменты в память блоками, кратными размеру страницы памяти (обычно 4096 байт).")
        
        calc0 = (p_vaddr0 - p_offset0) % p_align0
        calc1 = (p_vaddr1 - p_offset1) % p_align1
        log(f"4. Проверка условия выравнивания (p_vaddr - p_offset) mod p_align == 0:")
        log(f"   Phdr[0]: (0x{p_vaddr0:X} - 0x{p_offset0:X}) mod 0x{p_align0:X} = {calc0} (Условие: {calc0 == 0})")
        log(f"   Phdr[1]: (0x{p_vaddr1:X} - 0x{p_offset1:X}) mod 0x{p_align1:X} = {calc1} (Условие: {calc1 == 0})\n")

        log("Вопрос 5 - ответы:")
        end0 = p_vaddr0 + p_memsz0
        end1 = p_vaddr1 + p_memsz1
        log(f"1. Сегмент 1: p_vaddr = 0x{p_vaddr0:08X}, p_memsz = 0x{p_memsz0:08X}")
        log(f"   Сегмент 2: p_vaddr = 0x{p_vaddr1:08X}, p_memsz = 0x{p_memsz1:08X}")
        log(f"2. Виртуальный конец 1: 0x{end0:08X}")
        log(f"   Виртуальный конец 2: 0x{end1:08X}")
        
        min_vaddr = min(p_vaddr0, p_vaddr1)
        max_end = max(end0, end1)
        log(f"3. Минимальный p_vaddr: 0x{min_vaddr:08X}, Максимальный виртуальный конец: 0x{max_end:08X}")
        
        vm_total = max_end - min_vaddr
        vm_total_kb = vm_total / 1024
        log(f"4. Полный виртуальный диапазон процесса (vm_total): {vm_total} байт (0x{vm_total:X})")
        log(f"5. Диапазон в КБ: {vm_total_kb:.2f} KB. Для ОС это означает непрерывный блок виртуального адресного пространства, который необходимо зарезервировать для безопасной загрузки всего образа процесса.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python elf_analyzer.py <путь_к_elf_файлу>")
    else:
        analyze_elf(sys.argv[1])