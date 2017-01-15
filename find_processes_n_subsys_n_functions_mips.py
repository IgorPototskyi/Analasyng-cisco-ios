from idaapi import *
from idautils import *
from idc import *
from time import time as get_time


PROCESS_CREATE_NAME = 'process_create'
TOKEN_1 = 'Netclock Background Proccess'
TOKEN_2 = 'Default Priority Background Proccess'

CISCOSYS = 'C1 5C 05 15 C1 5C 05 15'
SYBSYSTYPE = 'subsystype'


def rename_function(ea):
    """
    Rename the "process_create" function
    :param ea: address of "process_create" function
    :return: true/false
    """
    for i in range(1, 10):
        ea = NextHead(ea)
        if GetMnem(ea) == 'jal':
            func_addr = int(GetOpnd(ea, 0).split('_')[1], 16)
            set_name(func_addr, PROCESS_CREATE_NAME)
            print('\n[!!!!!] Function "{0}" was found at {1:#x}\n'.format(PROCESS_CREATE_NAME, func_addr))
            return True

    return False


def find_process_create():
    """
    Find the "process_create" function by two tokens
    :return: true/false
    """
    if get_name_ea(BADADDR, PROCESS_CREATE_NAME) != BADADDR:
        return True

    ea = FindText(FirstSeg(), SEARCH_DOWN, 0, 0, TOKEN_1)
    if ea != BADADDR:
        if rename_function(ea):
            return True

    ea = FindText(FirstSeg(), SEARCH_DOWN, 0, 0, TOKEN_2)
    if ea != BADADDR:
        if rename_function(ea):
            return True

    print('{0} function does not found'.format(PROCESS_CREATE_NAME))
    return False


def get_hi_bytes(addr, operand_2):
    """
    Get a part of the address from mnemonic "lui"
    :param addr: current address in ios
    :param operand_2: 2nd operand
    :return: first four bytes of the address
    """
    prev_addr = PrevHead(addr, minea=0)
    for i in range(1, 7):
        if GetMnem(prev_addr) == 'lui' and GetOpnd(prev_addr, 0) == operand_2:
            return int(GetOpnd(prev_addr, 1), 16)
        else:
            prev_addr = PrevHead(prev_addr, minea=0)

    return BADADDR


def get_full_addr(addr, operand_2, operand_3):
    """
    Return a full address of a part (lui/ori or lui/addiu)
    :param addr: current address in ios
    :param operand_2: 2nd operand
    :param operand_3: 3rd operand
    :return: the full address
    """

    if len(operand_3) <= 7:
        low_bytes = int(operand_3, 16)

    else:
        if operand_3.startswith('(') and operand_3.endswith(')'):
            operand_3 = operand_3[1:-1]
            operand_3_list = operand_3.split(' - ')

            if len(operand_3_list) != 2:
                return BADADDR
            else:
                part_1 = operand_3_list[0]
                part_2 = operand_3_list[1]

                if part_1[:len('byte_')] == 'byte_' or part_1[:len('dword_')] == 'dword_' or \
                        part_1[:len('sub_')] == 'sub_' or part_1[:len('loc_')] == 'loc_' or \
                        part_1[:len('unk_')] == 'unk_' or part_1[:len('ask_')] == 'ask_':

                    low_bytes = int(part_1.split('_')[1], 16) - int(part_2, 16)
                else:
                    low_bytes = get_name_ea(BADADDR, part_1) - int(part_2, 16)

        else:
            return BADADDR

    hi_bytes = get_hi_bytes(addr, operand_2)
    if hi_bytes != BADADDR:
        return (hi_bytes << 16) + low_bytes
    else:
        return BADADDR


def get_process(ref):
    """
    Return process entry point and process name by "process_create" call.
    :param ref: reference to jal "process_create"
    :return: proc_entry_point - the address of the process,
             proc_name_addr - the name of the process
    """

    # get addr of previous command
    prev_addr = PrevHead(ref + 12, minea=0)

    proc_entry_point = BADADDR
    proc_name_addr = BADADDR
    low_bytes = 0

    # 10 operators up
    for i in range(1, 12):

        # next previous command
        prev_addr = PrevHead(prev_addr, minea=0)

        operand_1 = GetOpnd(prev_addr, 0)
        operand_2 = GetOpnd(prev_addr, 1)
        operand_3 = GetOpnd(prev_addr, 2)

        operand_2_type = GetOpType(prev_addr, 1)

        mnem = GetMnem(prev_addr)

        # find proc_entry_point by register $a0
        if operand_1 == '$a0' and proc_entry_point == BADADDR:

            if operand_2_type == o_mem or operand_2_type == o_imm:

                if mnem == 'la':
                    proc_entry_point = get_name_ea(BADADDR, operand_2)
                elif mnem == 'addiu':
                    if len(operand_2) <= 7:
                        low_bytes = int(operand_2, 16)
                elif low_bytes and mnem == 'lui':
                    hi_bytes = int(operand_2, 16)
                    proc_entry_point = (hi_bytes << 16) + low_bytes

            elif operand_2_type == o_reg and mnem == 'addiu':
                proc_entry_point = get_full_addr(prev_addr, operand_2, operand_3)

        # find proc_name_addr by register $a1
        elif operand_1 == '$a1' and proc_name_addr == BADADDR:

            if operand_2_type == o_mem or operand_2_type == o_imm:

                # check command mnemonic. $a1 may contain either *str or **str
                mnem = GetMnem(prev_addr)

                if mnem == 'la':
                    proc_name_addr = get_name_ea(BADADDR, operand_2)

                elif mnem == 'lw':
                    name_pointer = operand_2

                    if '+0x' in name_pointer:
                        continue

                    if '_' in name_pointer:
                        name_pointer = name_pointer.split('_')[1]

                    proc_name_addr = Dword(int(name_pointer, 16))

            elif mnem == 'addiu' and operand_2_type == o_reg:
                proc_name_addr = get_full_addr(prev_addr, operand_2, operand_3)

        # when all addresses are found
        if proc_entry_point != BADADDR and proc_name_addr != BADADDR:
            break

    return proc_entry_point, proc_name_addr


def process_create_main():
    """
    Find a "process_create" function and rename all entry points.
    :return: None
    """
    if find_process_create():

        # .text segment bounds
        seg = get_first_seg()
        end_addr = seg.endEA

        # find process_create addr
        pr_cr_addr = get_name_ea(BADADDR, PROCESS_CREATE_NAME)

        renamed_processes_counter = 0

        # get all references
        for i, ref in enumerate(CodeRefsTo(pr_cr_addr, True)):
            proc_entry_point, proc_name_addr = get_process(ref)

            if proc_name_addr != BADADDR and proc_entry_point != BADADDR:

                if proc_entry_point > end_addr:
                    continue

                # get process_name by address
                proc_name = GetString(proc_name_addr)

                if not proc_name:
                    print("[!] Error: Bad Name at {0:#x}".format(ref))
                    continue

                # check if code is disassembled
                if not has_dummy_name(GetFlags(proc_entry_point)):
                    MakeCode(proc_entry_point)

                # try to change process_name
                MakeFunction(start=proc_entry_point, end=BADADDR)    # IDA's key 'p'

                if set_name(proc_entry_point, 'proc_' + proc_name, SN_NOCHECK):
                    renamed_processes_counter += 1
                else:
                    print('Warning: MakeName failed ref={0:#x}: {1:#x}, {2:s}'.format(ref, proc_entry_point,
                                                                                      'proc_' + proc_name))
            else:
                # print("[!] Error: Bad signature at {0:#x}".format(ref))
                pass

        print('\n[!!!!!] {0} processes have been renamed\n'.format(renamed_processes_counter))
    else:
        print("[!] Cannot find {0}".format(PROCESS_CREATE_NAME))


def create_subsystype_struct():
    """
    Create the sybsystype struct

    struct subsystype_:
    magic1:         .long ?                 # base 16
    magic2:         .long ?                 # base 16
    header_version: .long ?                 # base 10
    kernel_majversion:.long ?               # base 10
    kernel_minversion:.long ?               # base 1
    namestring:     .long ?                 # offset (00000000)
    subsys_majversion:.long ?               # base 10
    subsys_minversion:.long ?               # base 10
    subsys_editversion:.long ?              # base 10
    init_address:   .long ?                 # offset (00000000)
    class:          .short ?                # base 10
    status:         .short ?                # base 10
    ID:             .long ?                 # base 1
    properties:     .long ?                 # offset (00000000)
    """

    sid = AddStrucEx(index=-1, name=SYBSYSTYPE, is_union=0)
    AddStrucMember(sid, name='magic1', offset=-1, flag=FF_DWRD | FF_DATA | FF_0NUMH, typeid=-1,
                   nbytes=4, target=-1, tdelta=0, reftype=REF_OFF32)
    AddStrucMember(sid, name='magic2', offset=-1, flag=FF_DWRD | FF_DATA | FF_0NUMH, typeid=-1,
                   nbytes=4, target=-1, tdelta=0, reftype=REF_OFF32)
    AddStrucMember(sid, name='header_version', offset=-1, flag=FF_DWRD | FF_DATA | FF_0NUMD, typeid=-1,
                   nbytes=4, target=-1, tdelta=0, reftype=REF_OFF32)
    AddStrucMember(sid, name='kernel_majversion', offset=-1, flag=FF_DWRD | FF_DATA | FF_0NUMD, typeid=-1,
                   nbytes=4, target=-1, tdelta=0, reftype=REF_OFF32)
    AddStrucMember(sid, name='kernel_minversion', offset=-1, flag=FF_DWRD | FF_DATA | FF_0NUMD, typeid=-1,
                   nbytes=4, target=-1, tdelta=0, reftype=REF_OFF32)
    AddStrucMember(sid, name='namestring', offset=-1, flag=FF_0OFF | FF_DWRD | FF_DATA, typeid=0,
                   nbytes=4, target=-1, tdelta=0, reftype=REF_OFF32)
    AddStrucMember(sid, name='subsys_majversion', offset=-1, flag=FF_DWRD | FF_DATA | FF_0NUMD, typeid=-1,
                   nbytes=4, target=-1, tdelta=0, reftype=REF_OFF32)
    AddStrucMember(sid, name='subsys_minversion', offset=-1, flag=FF_DWRD | FF_DATA | FF_0NUMD, typeid=-1,
                   nbytes=4, target=-1, tdelta=0, reftype=REF_OFF32)
    AddStrucMember(sid, name='subsys_editversion', offset=-1, flag=FF_DWRD | FF_DATA | FF_0NUMD, typeid=-1,
                   nbytes=4, target=-1, tdelta=0, reftype=REF_OFF32)
    AddStrucMember(sid, name='init_address', offset=-1, flag=FF_0OFF | FF_DWRD | FF_DATA, typeid=0,
                   nbytes=4, target=-1, tdelta=0, reftype=REF_OFF32)
    AddStrucMember(sid, name='class', offset=-1, flag=FF_WORD | FF_DATA | FF_0NUMD, typeid=-1,
                   nbytes=2, target=-1, tdelta=0, reftype=REF_OFF32)
    AddStrucMember(sid, name='status', offset=-1, flag=FF_WORD | FF_DATA | FF_0NUMD, typeid=-1,
                   nbytes=2, target=-1, tdelta=0, reftype=REF_OFF32)
    AddStrucMember(sid, name='ID', offset=-1, flag=FF_DWRD | FF_DATA | FF_0NUMH, typeid=-1,
                   nbytes=4, target=-1, tdelta=0, reftype=REF_OFF32)
    AddStrucMember(sid, name='properties', offset=-1, flag=FF_0OFF | FF_DWRD | FF_DATA, typeid=0,
                   nbytes=4, target=-1, tdelta=0, reftype=REF_OFF32)


def get_data_seg_bounds():
    """
    Return the bounds of "data" segment or first segment of IOS
    :return: data_seg_start - start address of the segment,
             data_seg_end - end address of the segment
    """
    seg = get_segm_by_name('.data')

    if not seg:
        seg = get_first_seg()

    data_seg_start = seg.startEA
    data_seg_end = seg.endEA

    # print('start = {0:#x}, end = {1:#x}'.format(data_seg_start, data_seg_end))
    return data_seg_start, data_seg_end


def create_all_subsystems():
    """
    Create and rename sybsystems
    :return: None
    """
    create_subsystype_struct()

    start_addr, end_addr = get_data_seg_bounds()
    current_addr = start_addr
    counter = 0

    struct_id = get_struc_id(SYBSYSTYPE)
    struct_size = get_struc_size(struct_id)

    while current_addr < end_addr:
        ea = find_binary(current_addr, end_addr, CISCOSYS, 16, SEARCH_DOWN)
        if ea == BADADDR:
            print('\n[!!!!!] {0} subsystype structs were found\n'.format(counter))
            break

        p_name, p_func, sysclass = Dword(ea + 0x14), Dword(ea + 0x24), Dword(ea + 0x28)

        do_unknown_range(ea, struct_size, DOUNK_DELNAMES | DOUNK_SIMPLE)

        if not doStruct(ea, struct_size, struct_id):
            print('DoStruct failed at {0:#x}'.format(ea))

        func_name = GetString(p_name)
        set_name(ea, SYBSYSTYPE + '_' + func_name, SN_NOCHECK | SN_NOWARN)

        if func_name != '' and not has_user_name(getFlags(p_func)):
            set_name(p_func, func_name + '_subsys_init', SN_NOCHECK)
            MakeFunction(start=p_func, end=idaapi.BADADDR)

        current_addr = ea + 4
        counter += 1


def rename_functions(strings=None, pattern=None):
    """
    Rename functions, that contains strings with certain pattern
    :param strings: all strings in ios
    :param pattern: pattern for necessary strings selection
    :return: None
    """
    names = [s for s in strings if re.search(pattern, str(s)) is not None]
    counter = 0

    for name in names:
        name_str = str(name)
        if '%' in name_str or '-' in name_str or ' ' in name_str or ':' in name_str or \
                              '(' in name_str or ')' in name_str or '\n' in name_str or\
                              '\\' in name_str or '/' in name_str or ',' in name_str:
            continue

        for ref in DataRefsTo(name.ea):
            old_name = GetFunctionName(ref)
            func_addr = LocByNameEx(ref, old_name)

            if func_addr == BADADDR or has_user_name(getFlags(func_addr)):
                break

            if MakeName(func_addr, name_str):
                counter += 1
            break

    print('\n[!!!!!] Renamed {0} functions\n'.format(counter))


def main():
    """
    The launch of three major functions
    :return: None
    """
    start_time = get_time()

    process_create_main()
    create_all_subsystems()
    rename_functions(strings=Strings(), pattern=r'^[a-z]{3,}_[a-z]+_')

    print('Time : {0} sec'.format(get_time() - start_time))


if __name__ == '__main__':
    main()

