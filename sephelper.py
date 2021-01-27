import idc
import idaapi
import ida_search
import ida_segment
import ida_bytes
import ida_funcs

def func64(base_ea, base_end_ea, name, sequence):
  seq_ea = ida_search.find_binary(base_ea, base_end_ea, sequence, 0x10, ida_search.SEARCH_DOWN)

  if seq_ea != ida_idaapi.BADADDR:
    func = idaapi.get_func(seq_ea)
    print("  [sephelper]: %s = 0x%x" % (name, func.start_ea))
    idc.set_name(func.start_ea, name, idc.SN_CHECK)
    return func.start_ea

  print("  [sephelper]: %s = NULL" % name)
  return ida_idaapi.BADADDR

# Registers.
# https://siguza.github.io/APRR/
# https://gist.github.com/bazad/42054285391c6e0dcd0ede4b5f969ad2

def find_function(seg_start, seg_end):
  func64(seg_start, seg_end, "_DEROidCompare", "a1 01 00 b4  02 05 40 f9")
  func64(seg_start, seg_end, "_DERImg4Decode", "61 03 00 54  88 26 40 a9")
  func64(seg_start, seg_end, "_DERParseBoolean", "08 01 40 39  1f fd 03 71")
  func64(seg_start, seg_end, "_DERParseInteger", "00 01 00 35  e8 07 40 f9")
  func64(seg_start, seg_end, "_DERParseSequence", "e0 01 00 35  e8 07 40 f9")
  func64(seg_start, seg_end, "_DERDecodeSeqNext", "e8 03 00 f9  28 01 08 cb")
  func64(seg_start, seg_end, "_DERParseInteger64", "0b 15 40 38  4b dd 78 b3")
  func64(seg_start, seg_end, "_DERParseBitString", "08 00 80 d2  5f 00 00 39")
  func64(seg_start, seg_end, "_DERImg4DecodePayload", "33 03 00 b4  09 01 40 f9")
  func64(seg_start, seg_end, "_DERImg4DecodeProperty", "e8 07 40 b9  08 09 43 b2")
  func64(seg_start, seg_end, "_DERParseSequenceContent", "ec 03 8c 1a  2d 69 bc 9b")
  func64(seg_start, seg_end, "_DERDecodeSeqContentInit", "09 04 40 f9  08 01 09 8b")
  func64(seg_start, seg_end, "_DERImg4DecodeTagCompare", "f3 03 01 aa  08 04 40 f9")
  func64(seg_start, seg_end, "_DERImg4DecodeRestoreInfo", "a1 29 a9 52  41 8a 86 72")
  func64(seg_start, seg_end, "_DERImg4DecodeFindProperty", "00 00 80 52  a8 0a 43 b2")
  func64(seg_start, seg_end, "_DERImg4DecodeFindInSequence", "60 02 80 3d  fd 7b 44 a9")
  func64(seg_start, seg_end, "_DERDecodeItemPartialBufferGetLength", "09 04 40 f9  3f 09 00 f1")
  func64(seg_start, seg_end, "_DERImg4DecodeParseManifestProperties", "80 02 80 3d  a1 3a 00 91")

  func64(seg_start, seg_end, "_Img4DecodeEvaluateDictionaryProperties", "e0 03 1f 32  0a fd 7e d3")
  func64(seg_start, seg_end, "_Img4DecodeGetPropertyBoolean", "21 08 43 b2  e0 03 00 91")
  func64(seg_start, seg_end, "_Img4DecodeCopyPayloadDigest", "?? ?? 02 91  e0 03 15 aa")
  func64(seg_start, seg_end, "_Img4DecodeGetPropertyData", "00 00 80 52  e8 17 40 f9")
  func64(seg_start, seg_end, "_Img4DecodeGetPayload", "00 81 c9 3c  20 00 80 3d")
  func64(seg_start, seg_end, "_Img4DecodeInit", "20 01 00 35  c0 c2 00 91")

  func64(seg_start, seg_end, "_ccn_n", "63 04 00 91  5f 00 00 f1")
  func64(seg_start, seg_end, "_ccn_cmp", "7f 00 05 eb  c0 80 80 9a")
  func64(seg_start, seg_end, "_ccn_sub", "84 00 04 eb  40 00 00 b5")
  func64(seg_start, seg_end, "_ccn_add", "84 00 00 b1  40 00 00 b5")
  func64(seg_start, seg_end, "_cc_muxp", "08 c1 20 cb  28 00 08 8a")
  func64(seg_start, seg_end, "_cchmac_init", "69 22 00 91  8a 0b 80 52")
  func64(seg_start, seg_end, "_ccdigest_init", "f4 03 00 aa  60 22 00 91")
  func64(seg_start, seg_end, "_ccdigest_update", "e1 00 00 54  81 fe 46 d3")

  func64(seg_start, seg_end, "_verify_chain_signatures", "?? 09 00 b4  68 12 40 f9")
  func64(seg_start, seg_end, "_read_counter_py_reg_el0", "20 e0 3b d5")
  func64(seg_start, seg_end, "_write_ktrr_unknown_el1", "a0 f2 1c d5")
  func64(seg_start, seg_end, "_boot_check_panic", "49 00 c0 d2  09 21 a8 f2")
  func64(seg_start, seg_end, "_verify_pkcs1_sig", "68 0e 00 54  a1 12 40 f9")
  func64(seg_start, seg_end, "_parse_extensions", "e9 23 00 91  35 81 00 91")
  func64(seg_start, seg_end, "_read_ctrr_lock", "40 f2 3c d5")
  func64(seg_start, seg_end, "_reload_cache", "1f 87 08 d5")
  func64(seg_start, seg_end, "_parse_chain", "5a 3d 00 12  77 3d 00 12")
  func64(seg_start, seg_end, "_memset", "21 1c 40 92  e3 c3 00 b2")
  func64(seg_start, seg_end, "_memcpy", "63 80 00 91  63 e8 7b 92")
  func64(seg_start, seg_end, "_bzero", "63 e4 7a 92  42 00 00 8b")
  func64(seg_start, seg_end, "_panic", "e8 03 00 91  16 81 00 91") # doubt

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
          ida_funcs.add_func(ea)

        ea = ea + 0x4

  idc.plan_and_wait(base_addr, segment_end)

  print('[sephelper]: finding some functions...')

  find_function(segm.start_ea, segment_end)

  print('[sephelper]: done !')
    
  return 1
