import idc
import idaapi
import ida_search
import ida_segment
import ida_bytes
import ida_funcs

def accept_file(fd, fname):
  ret = 0
  global segbit
  global base_addr

  if type(fname) == str:
    fd.seek(0xc00)
    search = fd.read(0x17)

    if search[:17] == "private_build...(":
      segbit = 2
      base_addr = 0x240000000 # 64bit (A11+)
      ret = { "format" : "SEPROM (AArch64)", "processor" : "arm" }

    fd.seek(0x800)
    search = fd.read(0x10)

    if search[:11] == "AppleSEPROM":
      segbit = 1
      base_addr = 0x10000000 # 32bit (up to A10X)
      ret = { "format" : "SEPROM (AArch32)", "processor" : "arm" }

  return ret

def load_file(fd, flags, format):
  ea = 0
  size = 0

  fd.seek(0x200)
  search = fd.read(0x10)

  print("[sephelper]: starting...")

  if segbit == 1:
    print("[sephelper]: detected a 32bit SEPROM !")
    idaapi.set_processor_type('ARM:ARMv7-A', idaapi.SETPROC_LOADER_NON_FATAL)
    idaapi.get_inf_structure().lflags |= idaapi.LFLG_PC_FLAT
  else:
    print("[sephelper]: detected a 64bit SEPROM !")
    idaapi.set_processor_type("arm", idaapi.SETPROC_LOADER_NON_FATAL)
    idaapi.get_inf_structure().lflags |= idaapi.LFLG_64BIT

  if (flags & idaapi.NEF_RELOAD) != 0: return 1

  fd.seek(0x0, idaapi.SEEK_END)

  size = fd.tell()

  segm = idaapi.segment_t()

  segm.bitness = segbit
  segm.start_ea = 0x0
  segm.end_ea = size

  idaapi.add_segm_ex(segm, "SEPROM", "CODE", idaapi.ADDSEG_OR_DIE)

  fd.seek(0x0)

  fd.file2base(0x0, 0x0, size, False)

  print("[sephelper]: adding entry point...")

  idaapi.add_entry(0x0, 0x0, "_start", 1)

  ida_funcs.add_func(ea)

  print("[sephelper]: base_addr = 0x%x" % base_addr)

  idaapi.rebase_program(base_addr, idc.MSF_NOFIX)

  print("[sephelper]: analyzing...")

  ea = base_addr
  segment_end = idc.get_segm_attr(base_addr, idc.SEGATTR_END)

  hexcode = ["BF A9", "BD A9"] # there is not PAC on SEPROM

  if segbit == 1:
    hexcode = ["03 AF", "02 AF", "01 AF"]

  for prologue in hexcode:
    while ea != idc.BADADDR:
      ea = ida_search.find_binary(ea, segment_end, prologue, 0x10, ida_search.SEARCH_DOWN)

      if ea != idc.BADADDR:
        ea = ea - 0x2

        if (ea % 0x4) == 0 and ida_bytes.get_full_flags(ea) < 0x200:
          print("[sephelper]: function found = 0x%x" % ea)
          ida_funcs.add_func(ea)

        ea = ea + 0x4

  # TODO : find functions...

  idc.plan_and_wait(base_addr, segment_end)

  print('[sephelper]: done !')
    
  return 1
