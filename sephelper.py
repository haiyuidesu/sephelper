import idc
import idaapi
import ida_search
import ida_segment
import ida_bytes
import ida_funcs

def function64(base_ea, base_end_ea, name, sequence):
  seq_ea = ida_search.find_binary(base_ea, base_end_ea, sequence, 0x10, ida_search.SEARCH_DOWN)

  if seq_ea != ida_idaapi.BADADDR:
    func = idaapi.get_func(seq_ea)
    print("  [sephelper]: %s = 0x%x" % (name, func.start_ea))
    idc.set_name(func.start_ea, name, idc.SN_CHECK)
    return func.start_ea

  print("  [sephelper]: %s = NULL" % name)
  return ida_idaapi.BADADDR

def find_function(seg_start, seg_end):
  function64(seg_start, seg_end, "_bzero", "63 e4 7a 92  42 00 00 8b")
  function64(seg_start, seg_end, "_memcpy", "63 80 00 91  63 e8 7b 92")
  function64(seg_start, seg_end, "_reload_cache", "1f 87 08 d5")
  function64(seg_start, seg_end, "_DERParseInteger", "00 01 00 35  e8 07 40 f9")
  function64(seg_start, seg_end, "_DERDecodeSeqNext", "e8 03 00 f9  28 01 08 cb")
  function64(seg_start, seg_end, "_verify_pkcs1_sig", "68 0e 00 54  a1 12 40 f9")
  function64(seg_start, seg_end, "_DERParseSequence", "e0 01 00 35  e8 07 40 f9")
  function64(seg_start, seg_end, "_boot_check_panic", "49 00 c0 d2  09 21 a8 f2")
  function64(seg_start, seg_end, "_DERImg4DecodePayload", "33 03 00 b4  09 01 40 f9")
  function64(seg_start, seg_end, "_Img4DecodeGetPayload", "00 81 c9 3c  20 00 80 3d")
  function64(seg_start, seg_end, "_verify_chain_signatures", "?? 09 00 b4  68 12 40 f9")
  function64(seg_start, seg_end, "_DERImg4DecodeFindInSequence", "60 02 80 3d  fd 7b 44 a9")

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
    idaapi.set_processor_type("arm:armv7-m", idaapi.SETPROC_LOADER_NON_FATAL)
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
          # print("[sephelper]: function added = 0x%x" % ea)
          ida_funcs.add_func(ea)

        ea = ea + 0x4

  idc.plan_and_wait(base_addr, segment_end)

  print('[sephelper]: finding some functions...')

  # TODO : find functions (I am not good with armv7 so don't expect it now...)

  find_function64(segm.start_ea, segment_end)

  print('[sephelper]: done !')
    
  return 1
