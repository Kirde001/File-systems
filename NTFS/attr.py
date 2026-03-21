import struct
import os
import sys
import datetime

FILENAME = "disk_17.vhd"
OUTFILE = "LR4_attrs.txt"

def ntfs_time_to_str(ntfs_time):
    if ntfs_time == 0:
        return "Нет данных"
    try:
        dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ntfs_time / 10)
        dt_local = dt + datetime.timedelta(hours=3)
        return dt_local.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "Недопустимая дата"

def parse_dos_attrs(attr_val):
    attrs = []
    if attr_val & 0x0001: attrs.append("ReadOnly")
    if attr_val & 0x0002: attrs.append("Hidden")
    if attr_val & 0x0004: attrs.append("System")
    if attr_val & 0x0020: attrs.append("Archive")
    if attr_val & 0x0040: attrs.append("Device")
    if attr_val & 0x0080: attrs.append("Normal")
    if attr_val & 0x0100: attrs.append("Temporary")
    if attr_val & 0x0200: attrs.append("Sparse File")
    if attr_val & 0x0400: attrs.append("Reparse Point")
    if attr_val & 0x0800: attrs.append("Compressed")
    if attr_val & 0x1000: attrs.append("Offline")
    if attr_val & 0x2000: attrs.append("Not Content Indexed")
    if attr_val & 0x4000: attrs.append("Encrypted")
    return " | ".join(attrs) if attrs else "Normal"

def get_attr_name(val):
    mapping = {
        0x10: "$STANDARD_INFORMATION",
        0x20: "$ATTRIBUTE_LIST",
        0x30: "$FILE_NAME",
        0x40: "$OBJECT_ID",
        0x50: "$SECURITY_DESCRIPTOR",
        0x60: "$VOLUME_NAME",
        0x70: "$VOLUME_INFORMATION",
        0x80: "$DATA",
        0x90: "$INDEX_ROOT",
        0xA0: "$INDEX_ALLOCATION",
        0xB0: "$BITMAP",
        0xC0: "$REPARSE_POINT"
    }
    return mapping.get(val, f"UNKNOWN (0x{val:X})")

def find_ntfs_partition(filepath, max_scan_mb=100):
    chunk_size = 1024 * 1024
    overlap = 16
    with open(filepath, 'rb') as f:
        offset = 0
        max_bytes = max_scan_mb * 1024 * 1024
        while offset < max_bytes:
            f.seek(offset)
            chunk = f.read(chunk_size + overlap)
            if not chunk: break
            idx = chunk.find(b'NTFS    ')
            if idx != -1 and idx >= 3:
                start_pos = offset + idx - 3
                f.seek(start_pos)
                if f.read(1) == b'\xeb': 
                    return start_pos
            offset += chunk_size
    return None

def apply_fixups(record_data, bps):
    upd_off = struct.unpack('<H', record_data[0x04:0x06])[0]
    upd_size = struct.unpack('<H', record_data[0x06:0x08])[0]
    if upd_off == 0 or upd_size == 0 or upd_off + 2 * upd_size > len(record_data):
        return record_data
    usn = record_data[upd_off:upd_off+2]
    usa = record_data[upd_off+2 : upd_off + 2*upd_size]
    fixed_data = bytearray(record_data)
    for i in range(1, upd_size):
        sector_offset = i * bps
        if sector_offset > len(fixed_data): break
        fixed_data[sector_offset-2:sector_offset] = usa[(i-1)*2 : i*2]
    return bytes(fixed_data)

def parse_data_runs(run_data):
    runs = []
    i = 0
    current_lcn = 0
    while i < len(run_data):
        header = run_data[i]
        if header == 0x00: break
        len_size = header & 0x0F
        off_size = header >> 4
        i += 1
        run_len = int.from_bytes(run_data[i:i+len_size], 'little')
        i += len_size
        if off_size > 0:
            run_off_bytes = run_data[i:i+off_size]
            run_off = int.from_bytes(run_off_bytes, 'little', signed=True)
            i += off_size
            current_lcn += run_off
            runs.append((current_lcn, run_len))
        else:
            runs.append((-1, run_len))
    return runs

def main():
    if not os.path.exists(FILENAME):
        sys.exit(1)
        
    offset = find_ntfs_partition(FILENAME)
    if offset is None:
        sys.exit(1)
        
    with open(FILENAME, 'rb') as f:
        f.seek(offset)
        bpb = f.read(512)
        bps = struct.unpack('<H', bpb[0x0B:0x0D])[0]
        spc = bpb[0x0D]
        bpc = bps * spc
        mft_cluster = struct.unpack('<Q', bpb[0x30:0x38])[0]
        raw_mft_size = bpb[0x40]
        
        if raw_mft_size >= 128:
            mft_record_size = 1 << (256 - raw_mft_size)
        else:
            mft_record_size = raw_mft_size * bpc
            
        mft_absolute_offset = offset + (mft_cluster * bpc)
        
        f.seek(mft_absolute_offset)
        mft0_raw = f.read(mft_record_size)
        mft0 = apply_fixups(mft0_raw, bps)
        
        attr_offset = struct.unpack('<H', mft0[0x14:0x16])[0]
        curr = attr_offset
        mft_runs = []
        
        while curr < mft_record_size - 8:
            attr_type = struct.unpack('<I', mft0[curr:curr+4])[0]
            if attr_type == 0xFFFFFFFF: break
            attr_len = struct.unpack('<I', mft0[curr+4:curr+8])[0]
            if attr_len == 0: break
            non_resident = mft0[curr+8]
            if attr_type == 0x80 and non_resident:
                run_offset = struct.unpack('<H', mft0[curr+0x20:curr+0x22])[0]
                run_data = mft0[curr+run_offset : curr+attr_len]
                mft_runs = parse_data_runs(run_data)
                break
            curr += attr_len
            
        if not mft_runs:
            mft_runs = [(mft_cluster, 100 * (mft_record_size // bpc))]
            
        with open(OUTFILE, 'w', encoding='utf-8') as out:
            record_count = 0
            max_records = 250
            
            for run_lcn, run_len in mft_runs:
                if run_lcn == -1: continue
                abs_lcn_offset = offset + (run_lcn * bpc)
                f.seek(abs_lcn_offset)
                
                records_in_run = (run_len * bpc) // mft_record_size
                for _ in range(records_in_run):
                    if record_count >= max_records: break
                    raw_record = f.read(mft_record_size)
                    if not raw_record or len(raw_record) < mft_record_size: break
                    
                    magic = raw_record[0:4]
                    if magic in (b'FILE', b'BAAD'):
                        record = apply_fixups(raw_record, bps)
                        abs_rec_addr = abs_lcn_offset + (_ * mft_record_size)
                        out.write(f"Атрибуты записи MFT #{record_count}:\n")
                        
                        curr_offset = struct.unpack('<H', record[0x14:0x16])[0]
                        while curr_offset < mft_record_size:
                            if curr_offset + 8 > mft_record_size: break
                            attr_type_bytes = record[curr_offset:curr_offset+4]
                            attr_len_bytes = record[curr_offset+4:curr_offset+8]
                            attr_type = struct.unpack('<I', attr_type_bytes)[0]
                            if attr_type == 0xFFFFFFFF: break
                            
                            attr_len = struct.unpack('<I', attr_len_bytes)[0]
                            if attr_len == 0 or curr_offset + attr_len > mft_record_size: break
                            
                            type_hex = " ".join(f"{b:02X}" for b in attr_type_bytes)
                            len_hex = " ".join(f"{b:02X}" for b in attr_len_bytes)
                            attr_name = get_attr_name(attr_type)
                            abs_attr_addr = abs_rec_addr + curr_offset
                            next_attr_addr = abs_attr_addr + attr_len
                            
                            out.write(f"         По адресу 0x{abs_attr_addr:X} находятся байты {type_hex}, это атрибут {attr_name}, длина – {len_hex}, адрес следующего атрибута – 0x{next_attr_addr:X}.\n")
                            
                            non_res = record[curr_offset+8]
                            
                            name_len = record[curr_offset+0x09]
                            stream_name = ""
                            if name_len > 0:
                                name_off = struct.unpack('<H', record[curr_offset+0x0A:curr_offset+0x0C])[0]
                                stream_name = record[curr_offset+name_off : curr_offset+name_off+name_len*2].decode('utf-16le', errors='ignore')
                            
                            if attr_type == 0x10 and non_res == 0:
                                res_off = struct.unpack('<H', record[curr_offset+0x14:curr_offset+0x16])[0]
                                si_data = record[curr_offset+res_off : curr_offset+attr_len]
                                if len(si_data) >= 36:
                                    c_time = ntfs_time_to_str(struct.unpack('<Q', si_data[0:8])[0])
                                    a_time = ntfs_time_to_str(struct.unpack('<Q', si_data[8:16])[0])
                                    m_time = ntfs_time_to_str(struct.unpack('<Q', si_data[16:24])[0])
                                    r_time = ntfs_time_to_str(struct.unpack('<Q', si_data[24:32])[0])
                                    dos_attr = parse_dos_attrs(struct.unpack('<I', si_data[32:36])[0])
                                    out.write(f"         Время создания: {c_time}, изменение: {a_time}, MFT: {m_time}, доступ: {r_time}.\n")
                                    out.write(f"         DOS атрибуты: {dos_attr}.\n")
                                    
                            elif attr_type == 0x30 and non_res == 0:
                                res_off = struct.unpack('<H', record[curr_offset+0x14:curr_offset+0x16])[0]
                                fn_data = record[curr_offset+res_off : curr_offset+attr_len]
                                if len(fn_data) >= 66:
                                    fn_len = fn_data[0x40]
                                    fn_name = fn_data[0x42:0x42+fn_len*2].decode('utf-16le', errors='ignore')
                                    fn_name_hex = fn_data[0x42:0x42+fn_len*2].hex(' ').upper()
                                    fn_c_time = ntfs_time_to_str(struct.unpack('<Q', fn_data[8:16])[0])
                                    root_str = ", то есть корень." if fn_name == "." else "."
                                    out.write(f"         Имя файла длиной в {fn_len} символов, само имя (HEX) – {fn_name_hex}, это «{fn_name}»{root_str}\n")
                                    out.write(f"         Время создания в пространстве имен: {fn_c_time}.\n")
                                    
                            elif attr_type == 0x50:
                                out.write("         Данный атрибут отвечает за безопасность и доступ к файлу/папке (содержит SID, ACL).\n")
                                
                            elif attr_type == 0x80:
                                if stream_name:
                                    out.write(f"         Имя потока данных (ADS): {stream_name}.\n")
                                if non_res:
                                    out.write("         Атрибут нерезидентный. Данные хранятся в кластерах.\n")
                                    run_off = struct.unpack('<H', record[curr_offset+0x20:curr_offset+0x22])[0]
                                    run_data = record[curr_offset+run_off : curr_offset+attr_len]
                                    runs = parse_data_runs(run_data)
                                    runs_str = ", ".join([f"LCN: {r[0]} (Кластеров: {r[1]})" for r in runs])
                                    out.write(f"         Data Runs: {runs_str}\n")
                                else:
                                    out.write("         Атрибут резидентный. Содержимое хранится непосредственно в MFT записи.\n")
                                    
                            elif attr_type == 0x90:
                                out.write("         По документации этот атрибут всегда резидентный, это корень ноды дерева B+ (основа NTFS).\n")
                                if stream_name:
                                    out.write(f"         По документации имя – {stream_name}.\n")
                                    
                            elif attr_type == 0xA0:
                                out.write("         Атрибут всегда нерезидентный. Является хранилищем размещения всех суб-нод для B+ дерева.\n")
                                if stream_name:
                                    out.write(f"         По документации имя – {stream_name}.\n")
                                run_off = struct.unpack('<H', record[curr_offset+0x20:curr_offset+0x22])[0]
                                run_data = record[curr_offset+run_off : curr_offset+attr_len]
                                runs = parse_data_runs(run_data)
                                runs_str = ", ".join([f"LCN: {r[0]} (Кластеров: {r[1]})" for r in runs])
                                out.write(f"         Атрибут состоит только из Data Runs: {runs_str}\n")
                                
                            out.write("\n")
                            curr_offset += attr_len
                        out.write("\n")
                    record_count += 1

if __name__ == '__main__':
    main()