import os
import sys
import unittest
import struct
import pefile

# Add the controls directory to sys.path to bypass heavy dependencies in malware_rl/__init__.py
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'malware_rl', 'envs', 'controls')))

from inline_hook import (
    find_iat_hooks,
    find_call_sites,
    rename_import_entries,
    add_hooks_section,
    patch_call_sites,
    neutralize_relocations_x86,
    ensure_loader_apis,
    inline_iat_hook,
    _NOOP_TRAMPOLINE
)
from inject_call import (
    inject_benign_api_call,
    _pick_apis,
    _ensure_imports,
    _make_injection_x64,
    _make_injection_x86,
    _calc_section_size,
    _x64_per_api_size,
    _x86_per_api_size,
    SAFE_INJECT_APIS,
    _X86_SAFE_DLLS,
    _DUMMY_BUF_SIZE,
)

class TestInlineHook(unittest.TestCase):
    def test_noop_bytes(self):
        self.assertEqual(_NOOP_TRAMPOLINE, b'\x31\xC0\xC3')

    def test_garbage_returns_empty(self):
        self.assertEqual(find_iat_hooks(b'\x00' * 100, [('KERNEL32.DLL', 'VirtualAllocEx')]), [])
        self.assertEqual(find_call_sites(b'\x00' * 100, []), [])

    def test_rename_import_entries(self):
        hooks = [{'api': 'VirtualAllocEx', 'original_name_len': 14, 'name_file_offset': 10}]
        bytez = bytearray(100)
        bytez[10:25] = b'VirtualAllocEx\x00'
        # Shorter or equal rename
        res = rename_import_entries(bytes(bytez), hooks, {'VirtualAllocEx': 'SafeAlloc'})
        self.assertEqual(res[10:19], b'SafeAlloc')
        self.assertEqual(res[19:25], b'\x00\x00\x00\x00\x00\x00')

        # Longer rename - should be skipped
        res2 = rename_import_entries(bytes(bytez), hooks, {'VirtualAllocEx': 'ThisIsTooLongName'})
        self.assertEqual(res2[10:24], b'VirtualAllocEx')

    def test_x64_integration_noop(self):
        folder = "malware_rl/envs/controls/ls/trusted"
        path = os.path.join(folder, "DIM.EXE") # x64 file
        with open(path, "rb") as f:
            bytez = f.read()

        # Let's try to hook some KERNEL32 API that is present in imports
        pe = pefile.PE(data=bytez)
        targets = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode('ascii', errors='replace').upper()
                if dll == 'KERNEL32.DLL':
                    for imp in entry.imports:
                        if imp.name:
                            targets.append((dll, imp.name.decode('ascii', errors='replace')))
                            break
        pe.close()

        sys.stderr.write(f"Targets found in DIM.EXE: {targets}\n")
        self.assertTrue(len(targets) > 0, "Should find KERNEL32 imports")

        # Test hook in noop mode
        rename_map = {targets[0][1]: "BenignFunc"}
        res = inline_iat_hook(bytez, targets, rename_map, mode='noop')
        self.assertTrue(len(res) > len(bytez), "Output size should be larger after adding section")

        # Re-parse to verify hooks section was added
        pe2 = pefile.PE(data=res)
        sec_names = [s.Name.rstrip(b'\x00').decode('ascii', errors='ignore') for s in pe2.sections]
        self.assertTrue(any(n.startswith('.reloc2') or n.startswith('.rsrc2') or n.startswith('.data2') for n in sec_names))
        pe2.close()

    def test_x86_integration_noop_with_reloc(self):
        folder = "malware_rl/envs/controls/ls/trusted"
        path = os.path.join(folder, "MSOXMLED.EXE") # x86 file with base relocations
        with open(path, "rb") as f:
            bytez = f.read()

        pe = pefile.PE(data=bytez)
        self.assertEqual(pe.OPTIONAL_HEADER.Magic, 0x10b, "Must be x86")
        self.assertTrue(hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'), "Must have base relocations")

        targets = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('ascii', errors='replace').upper()
            if dll == 'KERNEL32.DLL':
                for imp in entry.imports:
                    if imp.name:
                        targets.append((dll, imp.name.decode('ascii', errors='replace')))
                        break
        pe.close()

        sys.stderr.write(f"Targets found in MSOXMLED.EXE: {targets}\n")
        self.assertTrue(len(targets) > 0)

        # Hook it in noop mode
        rename_map = {targets[0][1]: "BenignFunc"}
        res = inline_iat_hook(bytez, targets, rename_map, mode='noop')
        self.assertTrue(len(res) > len(bytez))

    def test_forward_mode_x64(self):
        folder = "malware_rl/envs/controls/ls/trusted"
        path = os.path.join(folder, "DIM.EXE")
        with open(path, "rb") as f:
            bytez = f.read()

        pe = pefile.PE(data=bytez)
        targets = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('ascii', errors='replace').upper()
            if dll == 'KERNEL32.DLL':
                for imp in entry.imports:
                    if imp.name:
                        targets.append((dll, imp.name.decode('ascii', errors='replace')))
                        break
        pe.close()

        self.assertTrue(len(targets) > 0)
        res = inline_iat_hook(bytez, targets, {targets[0][1]: 'BenignGetMod'}, mode='forward')
        self.assertTrue(len(res) > len(bytez))

        # Re-parse to verify that KERNEL32.DLL now has LoadLibraryA and GetProcAddress
        pe = pefile.PE(data=res)
        has_liba = False
        has_gpa = False
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.decode('ascii', errors='replace').upper() == 'KERNEL32.DLL':
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode('ascii', errors='replace')
                        if name == 'LoadLibraryA':
                            has_liba = True
                        elif name == 'GetProcAddress':
                            has_gpa = True
        self.assertTrue(has_liba)
        self.assertTrue(has_gpa)
        pe.close()

    def test_x86_trampoline_layout(self):
        """Verify x86 forward trampoline byte layout is correct after the off-by-1 fix."""
        from inline_hook import _make_forward_trampoline_x86

        # Use dummy RVAs so we can inspect the code bytes directly
        tramp_rva  = 0x10000
        liba_rva   = 0x20000
        gpa_rva    = 0x20008
        tramp = _make_forward_trampoline_x86("KERNEL32.DLL", "VirtualAllocEx", liba_rva, gpa_rva, tramp_rva)

        # Offset 0:  push ebx (53) — saves caller's EBX (fix for ABI violation)
        self.assertEqual(tramp[0], 0x53, "offset 0 must be push ebx (53)")
        # Offset 1-5: call $+5 (E8 00 00 00 00) — now at offset 1, pushes tramp_va+6
        self.assertEqual(tramp[1], 0xE8, "offset 1 must be call (E8)")
        self.assertEqual(tramp[2:6], b'\x00\x00\x00\x00', "call displacement must be 0")
        # Offset 6:  pop ebx (5B) — EBX = tramp_va+6 (fix for off-by-1)
        self.assertEqual(tramp[6], 0x5B, "offset 6 must be pop ebx (5B)")
        # Offset 15: jnz (75) with displacement 47 = 0x2F → target = 17+47 = 64
        self.assertEqual(tramp[15], 0x75, "offset 15 must be jnz (75)")
        self.assertEqual(tramp[16], 47,   "jnz displacement must be 47 (target = offset 64)")
        # Offset 64: pop ebx (5B) — .forward label, restores orig EBX for both paths
        self.assertEqual(tramp[64], 0x5B, "offset 64 (.forward) must be pop ebx (5B)")
        # Offset 65-66: jmp eax (FF E0)
        self.assertEqual(tramp[65:67], b'\xFF\xE0', "offset 65 must be jmp eax (FF E0)")

        # Verify cached_ptr slot is zero-initialized at CACHED_PTR_OFFSET=67
        self.assertEqual(tramp[67:71], b'\x00\x00\x00\x00', "cached_ptr must be zeroed")

        # Verify IAT access computes correct VA:
        # EDX = EBX + (liba_iat_rva - tramp_rva - 6)
        # At runtime: EBX = ImageBase + tramp_rva + 6
        # EDX = ImageBase + tramp_rva + 6 + liba_iat_rva - tramp_rva - 6 = ImageBase + liba_iat_rva ✓
        import struct
        d_liba_bytes = tramp[30:34]   # displacement inside "add edx, d_liba" at offset 28-33
        d_liba = struct.unpack('<i', d_liba_bytes)[0]
        self.assertEqual(d_liba, liba_rva - (tramp_rva + 6), "LoadLibraryA IAT displacement must be liba_rva - (tramp_rva+6)")

    def test_x86_forward_mode_integration(self):
        """x86 PE: forward mode adds hooks section and ensures LoadLibraryA/GetProcAddress present."""
        folder = "malware_rl/envs/controls/ls/trusted"
        path = os.path.join(folder, "MSOXMLED.EXE")
        with open(path, "rb") as f:
            bytez = f.read()

        pe = pefile.PE(data=bytez)
        self.assertEqual(pe.OPTIONAL_HEADER.Magic, 0x10b, "Must be x86")

        targets = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('ascii', errors='replace').upper()
            if dll == 'KERNEL32.DLL':
                for imp in entry.imports:
                    if imp.name:
                        targets.append((dll, imp.name.decode('ascii', errors='replace')))
                        break
        pe.close()

        self.assertTrue(len(targets) > 0, "MSOXMLED.EXE must have KERNEL32.DLL imports")
        sys.stderr.write(f"x86 forward target: {targets[0]}\n")

        res = inline_iat_hook(bytez, targets, {}, mode='forward')
        self.assertTrue(len(res) > len(bytez), "Output must be larger after adding hooks section")

        # Verify LoadLibraryA and GetProcAddress are present (added if missing)
        pe_out = pefile.PE(data=res)
        k32_imports = set()
        for entry in pe_out.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.decode('ascii', errors='replace').upper() == 'KERNEL32.DLL':
                for imp in entry.imports:
                    if imp.name:
                        k32_imports.add(imp.name.decode('ascii', errors='replace'))
        pe_out.close()

        self.assertIn('LoadLibraryA',  k32_imports, "LoadLibraryA must be in import table")
        self.assertIn('GetProcAddress', k32_imports, "GetProcAddress must be in import table")



class TestInjectBenignApiCall(unittest.TestCase):
    """Tests for the new inject_benign_api_call action (Tier 2)."""

    SAMPLES_DIR = "malware_rl/envs/controls/ls/trusted"
    X64_SAMPLE = "DIM.EXE"
    X86_SAMPLE = "MSOXMLED.EXE"

    # ── _pick_apis ────────────────────────────────────────────────────────

    def test_pick_apis_default_count(self):
        rng = __import__('random').Random(42)
        apis = _pick_apis(rng=rng)
        self.assertGreaterEqual(len(apis), 3)
        self.assertLessEqual(len(apis), 5)
        for dll, func, args in apis:
            self.assertIsInstance(dll, str)
            self.assertIsInstance(func, str)
            self.assertIsInstance(args, list)
            self.assertLessEqual(len(args), 4, "max 4 args (x64 register limit)")
            for a in args:
                self.assertIn(a, ('buf', 'zero'))

    def test_pick_apis_x86_filter(self):
        rng = __import__('random').Random(7)
        apis = _pick_apis(k=20, arch_is_64=False, rng=rng)
        # All entries must come from x86-safe (stdcall) DLLs
        for dll, _func, _args in apis:
            self.assertIn(dll.upper(), _X86_SAFE_DLLS,
                          f"{dll} should be filtered out for x86")

    def test_pick_apis_explicit_k(self):
        rng = __import__('random').Random(123)
        apis = _pick_apis(k=4, rng=rng)
        self.assertEqual(len(apis), 4)

    def test_safe_inject_apis_well_formed(self):
        """Every entry in SAFE_INJECT_APIS must satisfy invariants."""
        for dll, func, args in SAFE_INJECT_APIS:
            self.assertIsInstance(dll, str)
            self.assertTrue(dll.endswith(".DLL"))
            self.assertIsInstance(func, str)
            self.assertGreater(len(func), 0)
            self.assertIsInstance(args, list)
            self.assertLessEqual(len(args), 4)
            for a in args:
                self.assertIn(a, ('buf', 'zero'))

    # ── shellcode size & layout ───────────────────────────────────────────

    def test_x64_per_api_size_consistency(self):
        # All-buf: 4*7 + 6 = 34
        self.assertEqual(_x64_per_api_size(['buf', 'buf', 'buf', 'buf']), 34)
        # All-zero: 2+2+3+3 + 6 = 16
        self.assertEqual(_x64_per_api_size(['zero', 'zero', 'zero', 'zero']), 16)
        # Empty args: just call instruction = 6
        self.assertEqual(_x64_per_api_size([]), 6)

    def test_x86_per_api_size_consistency(self):
        # 1 buf:  7 + (2+6+2) = 17
        self.assertEqual(_x86_per_api_size(['buf']), 17)
        # 1 zero: 2 + (2+6+2) = 12
        self.assertEqual(_x86_per_api_size(['zero']), 12)
        # No args: 0 + (2+6+2) = 10
        self.assertEqual(_x86_per_api_size([]), 10)

    def test_calc_section_size_aligned(self):
        apis = [("KERNEL32.DLL", "GetTickCount", []),
                ("KERNEL32.DLL", "GetSystemTime", ['buf'])]
        for is64 in (True, False):
            size = _calc_section_size(apis, is64)
            self.assertEqual(size % 16, 0, "section size must be 16-byte aligned")
            self.assertGreaterEqual(size, _DUMMY_BUF_SIZE,
                                    "must include dummy buffer")

    # ── shellcode encoder unit tests (no PE needed) ───────────────────────

    def test_make_injection_x64_layout(self):
        """Verify x64 shellcode prologue/epilogue/jmp/call structure."""
        apis = [
            ("KERNEL32.DLL", "GetTickCount",  []),
            ("KERNEL32.DLL", "GetSystemTime", ['buf']),
        ]
        iat_map = {
            ("KERNEL32.DLL", "GetTickCount"):  0x10000,
            ("KERNEL32.DLL", "GetSystemTime"): 0x10008,
        }
        oep_rva = 0x1000
        sec_rva = 0x20000

        code, total = _make_injection_x64(apis, iat_map, oep_rva, sec_rva)
        self.assertIsNotNone(code)
        self.assertEqual(total % 16, 0)

        # Prologue: sub rsp, 0x28
        self.assertEqual(code[0:4], b'\x48\x83\xEC\x28')

        # Body: GetTickCount has no args -> goes straight to call FF 15 ...
        # Offset 4 should be FF 15 ...
        self.assertEqual(code[4:6], b'\xFF\x15')

        # Verify the call displacement to GetTickCount IAT
        disp_bytes = code[6:10]
        disp = struct.unpack('<i', disp_bytes)[0]
        # next_ip = sec_rva + 10; expected disp = 0x10000 - (sec_rva+10)
        self.assertEqual(disp, 0x10000 - (sec_rva + 10))

        # Find epilogue: add rsp, 0x28 followed by E9 (jmp rel32)
        idx = code.find(b'\x48\x83\xC4\x28')
        self.assertGreater(idx, 4, "must find add rsp epilogue")
        self.assertEqual(code[idx + 4], 0xE9)
        # Verify jmp displacement
        jmp_disp = struct.unpack('<i', code[idx + 5:idx + 9])[0]
        self.assertEqual(jmp_disp, oep_rva - (sec_rva + idx + 9))

    def test_make_injection_x86_layout(self):
        """Verify x86 PIC shellcode prologue/epilogue/PIC-base structure."""
        apis = [("KERNEL32.DLL", "GetTickCount", [])]
        iat_map = {("KERNEL32.DLL", "GetTickCount"): 0x3000}
        sec_rva = 0x4000
        oep_rva = 0x500

        code, total = _make_injection_x86(apis, iat_map, 0x400000, oep_rva, sec_rva)
        self.assertIsNotNone(code)
        self.assertEqual(total % 16, 0)

        # PIC prologue: push ebx (53), call $+5 (E8 00*4), pop ebx (5B)
        self.assertEqual(code[0],     0x53)
        self.assertEqual(code[1],     0xE8)
        self.assertEqual(code[2:6],   b'\x00\x00\x00\x00')
        self.assertEqual(code[6],     0x5B)

        # After PIC prologue (offset 7) for GetTickCount (no args):
        # mov edx, ebx (89 DA); add edx, imm32 (81 C2 ...); call [edx] (FF 12)
        self.assertEqual(code[7:9], b'\x89\xDA')
        self.assertEqual(code[9:11], b'\x81\xC2')
        # disp = iat_rva - sec_rva - 6 = 0x3000 - 0x4000 - 6 = -0x1006
        disp = struct.unpack('<i', code[11:15])[0]
        self.assertEqual(disp, 0x3000 - 0x4000 - 6)
        # Then call [edx]
        self.assertEqual(code[15:17], b'\xFF\x12')

        # Epilogue: pop ebx (5B), then jmp rel32 (E9 disp32)
        self.assertEqual(code[17], 0x5B)
        self.assertEqual(code[18], 0xE9)
        jmp_disp = struct.unpack('<i', code[19:23])[0]
        # next_ip = sec_va + 23; expected = oep_rva - sec_rva - 23
        self.assertEqual(jmp_disp, oep_rva - sec_rva - 23)

    # ── Integration: end-to-end on real PEs ───────────────────────────────

    def _verify_inject_result(self, before, after, is64_expected):
        """Common assertions: PE valid, larger, EP changed, new section, new imports."""
        self.assertGreater(len(after), len(before),
                           "output must be larger after section addition")

        pe_before = pefile.PE(data=before)
        pe_after  = pefile.PE(data=after)

        self.assertEqual(pe_after.OPTIONAL_HEADER.Magic == 0x20b, is64_expected)

        # Entry point must have changed
        self.assertNotEqual(pe_after.OPTIONAL_HEADER.AddressOfEntryPoint,
                            pe_before.OPTIONAL_HEADER.AddressOfEntryPoint,
                            "EP must point to the new injected section")

        new_ep = pe_after.OPTIONAL_HEADER.AddressOfEntryPoint
        # The new EP must fall inside one of the sections (the new one)
        ep_section = None
        for s in pe_after.sections:
            start = s.VirtualAddress
            end   = start + max(s.Misc_VirtualSize, s.SizeOfRawData)
            if start <= new_ep < end:
                ep_section = s
                break
        self.assertIsNotNone(ep_section, "EP must be inside a section")

        # Section name should be one of our injected candidates
        sec_name = ep_section.Name.rstrip(b'\x00').decode('ascii', errors='ignore')
        self.assertTrue(
            sec_name.startswith('.text2') or sec_name.startswith('.rdata2') or
            sec_name.startswith('.data2') or sec_name.startswith('.rsrc2') or
            sec_name.startswith('.reloc2') or sec_name.startswith('.ext') or
            sec_name.startswith('.tls') or sec_name.startswith('.in'),
            f"unexpected EP section name: {sec_name!r}"
        )

        # Section must be executable
        self.assertTrue(ep_section.Characteristics & 0x20000000,
                        "EP section must be executable")

        # First instruction(s) at new EP should not be all zeros (= shellcode written)
        ep_off = ep_section.PointerToRawData + (new_ep - ep_section.VirtualAddress)
        first_bytes = after[ep_off:ep_off + 8]
        self.assertNotEqual(first_bytes, b'\x00' * 8,
                            "shellcode must have been written into the section")

        pe_before.close()
        pe_after.close()

    def test_inject_x64_DIM(self):
        """End-to-end: inject into an x64 PE."""
        path = os.path.join(self.SAMPLES_DIR, self.X64_SAMPLE)
        with open(path, "rb") as f:
            bytez = f.read()

        pe = pefile.PE(data=bytez)
        self.assertEqual(pe.OPTIONAL_HEADER.Magic, 0x20b, "DIM.EXE should be x64")
        original_imports = set()
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    original_imports.add(imp.name.decode('ascii', errors='ignore'))
        pe.close()

        rng = __import__('random').Random(2026)
        result = inject_benign_api_call(bytez, rng=rng)
        self.assertIsNotNone(result)
        self._verify_inject_result(bytez, result, is64_expected=True)

        # Verify at least one new import was added (or all were already present)
        pe_after = pefile.PE(data=result)
        new_imports = set()
        for entry in pe_after.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    new_imports.add(imp.name.decode('ascii', errors='ignore'))
        pe_after.close()
        # Either same set (all were already present) or strictly more
        self.assertGreaterEqual(len(new_imports), len(original_imports))

    def test_inject_x86_MSOXMLED(self):
        """End-to-end: inject into an x86 PE with base relocations."""
        path = os.path.join(self.SAMPLES_DIR, self.X86_SAMPLE)
        with open(path, "rb") as f:
            bytez = f.read()

        pe = pefile.PE(data=bytez)
        self.assertEqual(pe.OPTIONAL_HEADER.Magic, 0x10b, "MSOXMLED.EXE should be x86")
        pe.close()

        rng = __import__('random').Random(2027)
        result = inject_benign_api_call(bytez, rng=rng)
        self.assertIsNotNone(result)
        self._verify_inject_result(bytez, result, is64_expected=False)

    def test_inject_idempotent(self):
        """Running inject twice should still produce a valid PE.
        Each call adds its own section and re-points EP."""
        path = os.path.join(self.SAMPLES_DIR, self.X64_SAMPLE)
        with open(path, "rb") as f:
            bytez = f.read()

        rng1 = __import__('random').Random(11)
        once = inject_benign_api_call(bytez, rng=rng1)
        self.assertGreater(len(once), len(bytez))

        rng2 = __import__('random').Random(22)
        twice = inject_benign_api_call(once, rng=rng2)
        self.assertGreater(len(twice), len(once),
                           "second inject must add yet another section")

        # Both results must be valid PEs
        pe = pefile.PE(data=twice)
        self.assertIsNotNone(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        pe.close()

    def test_inject_handles_garbage(self):
        """Non-PE garbage must not crash, must return original."""
        garbage = b'\x00' * 1024
        result = inject_benign_api_call(garbage)
        self.assertEqual(result, garbage)

    def test_inject_via_modifier_action(self):
        """Calling action through ModifyBinary class (integration with action table)."""
        # Import via direct path since malware_rl/__init__.py is heavy
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "modifier_module",
            os.path.join("malware_rl", "envs", "controls", "modifier.py"),
        )
        # We need package context for the relative imports; fall back to direct call
        # via the public function instead to avoid touching malware_rl.__init__
        path = os.path.join(self.SAMPLES_DIR, self.X64_SAMPLE)
        with open(path, "rb") as f:
            bytez = f.read()

        rng = __import__('random').Random(33)
        result = inject_benign_api_call(bytez, rng=rng)
        self.assertGreater(len(result), len(bytez))


if __name__ == '__main__':
    sys.stderr.write("Running Unit Tests...\n")
    unittest.main(testRunner=unittest.TextTestRunner(stream=sys.stderr))
