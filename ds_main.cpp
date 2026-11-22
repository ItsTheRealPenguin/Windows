// main.cpp
// Single-file PE / DLL / BIN analyzer + basic linear x86 disassembler
// Pure C++17, zero external dependencies. Compile: g++ -std=c++17 -O2 -o retool main.cpp
// Usage: ./retool <file.exe|.dll|.bin>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <algorithm>
#include <map>

#pragma pack(push, 1)

struct IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
};

struct IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_NT_HEADERS32 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

struct IMAGE_NT_HEADERS64 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

struct IMAGE_SECTION_HEADER {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct IMAGE_IMPORT_DESCRIPTOR {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
};

struct IMAGE_EXPORT_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
};

#pragma pack(pop)

constexpr uint16_t IMAGE_DOS_SIGNATURE = 0x5A4D;
constexpr uint32_t IMAGE_NT_SIGNATURE  = 0x00004550;
constexpr uint16_t IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B;
constexpr uint16_t IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B;
constexpr uint16_t IMAGE_FILE_MACHINE_I386  = 0x014C;
constexpr uint16_t IMAGE_FILE_MACHINE_AMD64 = 0x8664;

constexpr size_t IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
constexpr size_t IMAGE_DIRECTORY_ENTRY_IMPORT = 1;

class Binary {
public:
    std::vector<uint8_t> data;
    size_t size() const { return data.size(); }
    const uint8_t* ptr(size_t off = 0) const { return data.data() + off; }
    bool valid(size_t off, size_t len) const { return off + len <= data.size(); }

    template<typename T>
    bool read(size_t off, T& out) const {
        if (!valid(off, sizeof(T))) return false;
        std::memcpy(&out, ptr(off), sizeof(T));
        return true;
    }

    std::string read_string(size_t off, size_t max = 512) const {
        if (off >= data.size()) return "";
        size_t end = off;
        while (end < data.size() && end - off < max && data[end] != 0) ++end;
        return std::string(reinterpret_cast<const char*>(ptr(off)), end - off);
    }
};

uint32_t rva_to_offset(const std::vector<IMAGE_SECTION_HEADER>& sections, uint32_t rva, uint32_t image_base = 0) {
    for (const auto& s : sections) {
        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + std::max(s.VirtualSize, s.SizeOfRawData)) {
            return s.PointerToRawData + (rva - s.VirtualAddress);
        }
    }
    return 0;
}

void hex_dump(const Binary& bin, size_t offset, size_t length, size_t base_addr = 0) {
    const size_t end = std::min(offset + length, bin.size());
    for (size_t i = offset; i < end; i += 16) {
        printf("%08zX  ", base_addr + (i - offset));
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < end) printf("%02X ", bin.data[i + j]);
            else printf("   ");
        }
        printf(" ");
        for (size_t j = 0; j < 16 && i + j < end; ++j) {
            uint8_t c = bin.data[i + j];
            putchar((c >= 32 && c < 127) ? c : '.');
        }
        putchar('\n');
    }
}

// Minimal linear x86/x64 disassembler (common opcodes only, educational)
struct DisasmResult {
    size_t length;
    std::string text;
};

DisasmResult disassemble_one(const uint8_t* code, size_t max_len, bool is64) {
    if (max_len == 0) return {0, "???"};

    // Very small table of common single-byte / simple instructions
    static const char* const one_byte[] = {
        /*00*/ "add [rm], r", "add [rm], r", "add r, [rm]", "add r, [rm]", "add al, imm8", "add eax, imm32", "push es", "pop es",
        /*08*/ "or [rm], r", "or [rm], r", "or r, [rm]", "or r, [rm]", "or al, imm8", "or eax, imm32", "push cs", "???",
        /*10*/ "adc [rm], r", "adc [rm], r", "adc r, [rm]", "adc r, [rm]", "adc al, imm8", "adc eax, imm32", "push ss", "pop ss",
        /*18*/ "sbb [rm], r", "sbb [rm], r", "sbb r, [rm]", "sbb r, [rm]", "sbb al, imm8", "sbb eax, imm32", "push ds", "pop ds",
        /*20*/ "and [rm], r", "and [rm], r", "and r, [rm]", "and r, [rm]", "and al, imm8", "and eax, imm32", "es:", "daa",
        /*28*/ "sub [rm], r", "sub [rm], r", "sub r, [rm]", "sub r, [rm]", "sub al, imm8", "sub eax, imm32", "cs:", "das",
        /*30*/ "xor [rm], r", "xor [rm], r", "xor r, [rm]", "xor r, [rm]", "xor al, imm8", "xor eax, imm32", "ss:", "aaa",
        /*38*/ "cmp [rm], r", "cmp [rm], r", "cmp r, [rm]", "cmp r, [rm]", "cmp al, imm8", "cmp eax, imm32", "ds:", "aas",
        /*40*/ "inc eax", "inc ecx", "inc edx", "inc ebx", "inc esp", "inc ebp", "inc esi", "inc edi",
        /*48*/ "dec eax", "dec ecx", "dec edx", "dec ebx", "dec esp", "dec ebp", "dec esi", "dec edi",
        /*50*/ "push eax", "push ecx", "push edx", "push ebx", "push esp", "push ebp", "push esi", "push edi",
        /*58*/ "pop eax", "pop ecx", "pop edx", "pop ebx", "pop esp", "pop ebp", "pop esi", "pop edi",
        /*60*/ "pusha", "popa", "bound", "arpl", "fs:", "gs:", "opsize", "adsize",
        /*68*/ "push imm32", "imul r, [rm], imm32", "push imm8", "imul r, [rm], imm8", "insb", "insd", "outsb", "outsd",
        /*70*/ "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
        /*78*/ "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg",
        /*80*/ "alu [rm], imm8", "alu [rm], imm32", "alu [rm], imm8", "alu [rm], imm8", "test [rm], r", "test [rm], r", "xchg [rm], r", "xchg [rm], r",
        /*88*/ "mov [rm], r", "mov [rm], r", "mov r, [rm]", "mov r, [rm]", "mov [rm], sreg", "lea r, [rm]", "mov sreg, [rm]", "pop [rm]",
        /*90*/ "nop", "xchg ecx, eax", "xchg edx, eax", "xchg ebx, eax", "xchg esp, eax", "xchg ebp, eax", "xchg esi, eax", "xchg edi, eax",
        /*98*/ "cwde", "cdq", "call far", "wait", "pushf", "popf", "sahf", "lahf",
        /*A0*/ "mov al, [imm]", "mov eax, [imm]", "mov [imm], al", "mov [imm], eax", "movsb", "movsd", "cmpsb", "cmpsd",
        /*A8*/ "test al, imm8", "test eax, imm32", "stosb", "stosd", "lodsb", "lodsd", "scasb", "scasd",
        /*B0*/ "mov al, imm8", "mov cl, imm8", "mov dl, imm8", "mov bl, imm8", "mov ah, imm8", "mov ch, imm8", "mov dh, imm8", "mov bh, imm8",
        /*B8*/ "mov eax, imm32", "mov ecx, imm32", "mov edx, imm32", "mov ebx, imm32", "mov esp, imm32", "mov ebp, imm32", "mov esi, imm32", "mov edi, imm32",
        /*C0*/ "shift [rm], imm8", "shift [rm], imm8", "ret imm16", "ret", "les", "lds", "mov [rm], imm8", "mov [rm], imm32",
        /*C8*/ "enter", "leave", "retf imm16", "retf", "int3", "int imm8", "into", "iret",
        /*D0*/ "shift [rm], 1", "shift [rm], 1", "shift [rm], cl", "shift [rm], cl", "aam", "aad", "salc", "xlat",
        /*D8*/ "fpu", "fpu", "fpu", "fpu", "fpu", "fpu", "fpu", "fpu",
        /*E0*/ "loopne", "loope", "loop", "jcxz", "in al, imm8", "in eax, imm8", "out imm8, al", "out imm8, eax",
        /*E8*/ "call rel32", "jmp rel32", "jmp far", "jmp rel8", "in al, dx", "in eax, dx", "out dx, al", "out dx, eax",
        /*F0*/ "lock", "int1", "repne", "rep", "hlt", "cmc", "alu [rm]", "alu [rm]",
        /*F8*/ "clc", "stc", "cli", "sti", "cld", "std", "inc/dec [rm]", "push/pop/call/jmp [rm]"
    };

    uint8_t op = code[0];
    size_t len = 1;
    std::string text;

    // REX prefix (64-bit)
    if (is64 && (op >= 0x40 && op <= 0x4F)) {
        text = "rex ";
        if (max_len < 2) return {1, text + "???"};
        op = code[1];
        len = 2;
    }

    // Simple one-byte
    if (op < 0x100) {
        text += one_byte[op];
        // Estimate extra bytes for immediates / ModRM (very rough)
        if (op == 0xE8 || op == 0xE9) len += 4;          // call/jmp rel32
        else if (op == 0xEB || (op >= 0x70 && op <= 0x7F)) len += 1; // jmp/jcc rel8
        else if (op == 0x68) len += 4;                   // push imm32
        else if (op == 0x6A) len += 1;                   // push imm8
        else if (op >= 0xB0 && op <= 0xB7) len += 1;     // mov r8, imm8
        else if (op >= 0xB8 && op <= 0xBF) len += is64 ? 8 : 4; // mov r32/64, imm
        else if (op == 0xC2 || op == 0xCA) len += 2;     // ret imm16
        else if (op == 0xCD) len += 1;                   // int imm8
        else if ((op & 0xFC) == 0x80) len += 1 + 1;      // alu rm, imm (ModRM + imm)
        else if (op == 0xFF || op == 0xFE || (op >= 0x80 && op <= 0x8F)) len += 1; // ModRM
    } else {
        text = "db";
    }

    if (len > max_len) len = max_len;
    return {len, text};
}

void disassemble_linear(const Binary& bin, size_t offset, size_t length, uint64_t base_va, bool is64) {
    size_t end = std::min(offset + length, bin.size());
    size_t pos = offset;
    while (pos < end) {
        auto res = disassemble_one(bin.ptr(pos), end - pos, is64);
        printf("%016llX  ", (unsigned long long)(base_va + (pos - offset)));
        for (size_t i = 0; i < res.length; ++i) printf("%02X", bin.data[pos + i]);
        for (size_t i = res.length; i < 8; ++i) printf("  ");
        printf("  %s\n", res.text.c_str());
        pos += res.length ? res.length : 1;
    }
}

void analyze_pe(const Binary& bin) {
    IMAGE_DOS_HEADER dos;
    if (!bin.read(0, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Not a valid PE (bad MZ)\n");
        return;
    }
    printf("[+] DOS Header OK, e_lfanew = 0x%X\n", dos.e_lfanew);

    if (!bin.valid(dos.e_lfanew, 4)) {
        printf("[!] Invalid e_lfanew\n");
        return;
    }

    uint32_t sig = 0;
    bin.read(dos.e_lfanew, sig);
    if (sig != IMAGE_NT_SIGNATURE) {
        printf("[!] Bad PE signature\n");
        return;
    }

    IMAGE_FILE_HEADER fh;
    if (!bin.read(dos.e_lfanew + 4, fh)) {
        printf("[!] Cannot read FileHeader\n");
        return;
    }

    printf("\n=== COFF File Header ===\n");
    printf("Machine            : 0x%04X ", fh.Machine);
    if (fh.Machine == IMAGE_FILE_MACHINE_I386) printf("(i386)\n");
    else if (fh.Machine == IMAGE_FILE_MACHINE_AMD64) printf("(AMD64)\n");
    else printf("(unknown)\n");
    printf("NumberOfSections   : %u\n", fh.NumberOfSections);
    printf("TimeDateStamp      : 0x%08X\n", fh.TimeDateStamp);
    printf("Characteristics    : 0x%04X\n", fh.Characteristics);
    printf("SizeOfOptionalHeader: %u\n", fh.SizeOfOptionalHeader);

    bool is64 = false;
    uint16_t opt_magic = 0;
    bin.read(dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER), opt_magic);
    is64 = (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    uint32_t entry = 0;
    uint64_t image_base = 0;
    uint32_t size_of_image = 0;
    uint32_t size_of_headers = 0;
    IMAGE_DATA_DIRECTORY data_dir[16] = {};
    uint32_t num_rva = 0;

    if (is64) {
        IMAGE_NT_HEADERS64 nt;
        if (!bin.read(dos.e_lfanew, nt)) return;
        printf("\n=== Optional Header (PE32+) ===\n");
        printf("Magic              : 0x%04X (PE32+)\n", nt.OptionalHeader.Magic);
        printf("AddressOfEntryPoint: 0x%08X\n", nt.OptionalHeader.AddressOfEntryPoint);
        printf("ImageBase          : 0x%016llX\n", (unsigned long long)nt.OptionalHeader.ImageBase);
        printf("SectionAlignment   : 0x%X\n", nt.OptionalHeader.SectionAlignment);
        printf("FileAlignment      : 0x%X\n", nt.OptionalHeader.FileAlignment);
        printf("SizeOfImage        : 0x%X\n", nt.OptionalHeader.SizeOfImage);
        printf("SizeOfHeaders      : 0x%X\n", nt.OptionalHeader.SizeOfHeaders);
        printf("Subsystem          : %u\n", nt.OptionalHeader.Subsystem);
        printf("DllCharacteristics : 0x%04X\n", nt.OptionalHeader.DllCharacteristics);
        entry = nt.OptionalHeader.AddressOfEntryPoint;
        image_base = nt.OptionalHeader.ImageBase;
        size_of_image = nt.OptionalHeader.SizeOfImage;
        size_of_headers = nt.OptionalHeader.SizeOfHeaders;
        num_rva = nt.OptionalHeader.NumberOfRvaAndSizes;
        std::memcpy(data_dir, nt.OptionalHeader.DataDirectory, sizeof(data_dir));
    } else {
        IMAGE_NT_HEADERS32 nt;
        if (!bin.read(dos.e_lfanew, nt)) return;
        printf("\n=== Optional Header (PE32) ===\n");
        printf("Magic              : 0x%04X (PE32)\n", nt.OptionalHeader.Magic);
        printf("AddressOfEntryPoint: 0x%08X\n", nt.OptionalHeader.AddressOfEntryPoint);
        printf("ImageBase          : 0x%08X\n", nt.OptionalHeader.ImageBase);
        printf("SectionAlignment   : 0x%X\n", nt.OptionalHeader.SectionAlignment);
        printf("FileAlignment      : 0x%X\n", nt.OptionalHeader.FileAlignment);
        printf("SizeOfImage        : 0x%X\n", nt.OptionalHeader.SizeOfImage);
        printf("SizeOfHeaders      : 0x%X\n", nt.OptionalHeader.SizeOfHeaders);
        printf("Subsystem          : %u\n", nt.OptionalHeader.Subsystem);
        printf("DllCharacteristics : 0x%04X\n", nt.OptionalHeader.DllCharacteristics);
        entry = nt.OptionalHeader.AddressOfEntryPoint;
        image_base = nt.OptionalHeader.ImageBase;
        size_of_image = nt.OptionalHeader.SizeOfImage;
        size_of_headers = nt.OptionalHeader.SizeOfHeaders;
        num_rva = nt.OptionalHeader.NumberOfRvaAndSizes;
        std::memcpy(data_dir, nt.OptionalHeader.DataDirectory, sizeof(data_dir));
    }

    // Sections
    size_t section_off = dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + fh.SizeOfOptionalHeader;
    std::vector<IMAGE_SECTION_HEADER> sections(fh.NumberOfSections);
    printf("\n=== Sections ===\n");
    printf("%-8s %10s %10s %10s %10s %10s\n", "Name", "VirtSize", "VirtAddr", "RawSize", "RawPtr", "Characteristics");
    for (uint16_t i = 0; i < fh.NumberOfSections; ++i) {
        if (!bin.read(section_off + i * sizeof(IMAGE_SECTION_HEADER), sections[i])) break;
        char name[9] = {};
        std::memcpy(name, sections[i].Name, 8);
        printf("%-8s 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X\n",
               name, sections[i].VirtualSize, sections[i].VirtualAddress,
               sections[i].SizeOfRawData, sections[i].PointerToRawData, sections[i].Characteristics);
    }

    // Imports
    if (num_rva > IMAGE_DIRECTORY_ENTRY_IMPORT && data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
        uint32_t import_rva = data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        uint32_t import_off = rva_to_offset(sections, import_rva);
        printf("\n=== Imports ===\n");
        if (import_off) {
            for (int i = 0; ; ++i) {
                IMAGE_IMPORT_DESCRIPTOR desc;
                if (!bin.read(import_off + i * sizeof(desc), desc) || desc.Name == 0) break;
                uint32_t name_off = rva_to_offset(sections, desc.Name);
                std::string dll = bin.read_string(name_off);
                printf("  %s\n", dll.c_str());
            }
        }
    }

    // Exports
    if (num_rva > IMAGE_DIRECTORY_ENTRY_EXPORT && data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
        uint32_t export_rva = data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        uint32_t export_off = rva_to_offset(sections, export_rva);
        printf("\n=== Exports ===\n");
        if (export_off) {
            IMAGE_EXPORT_DIRECTORY exp;
            if (bin.read(export_off, exp)) {
                uint32_t name_off = rva_to_offset(sections, exp.Name);
                printf("  Module: %s\n", bin.read_string(name_off).c_str());
                printf("  NumberOfFunctions: %u\n", exp.NumberOfFunctions);
                printf("  NumberOfNames    : %u\n", exp.NumberOfNames);
                uint32_t names_off = rva_to_offset(sections, exp.AddressOfNames);
                for (uint32_t i = 0; i < exp.NumberOfNames && i < 64; ++i) {
                    uint32_t name_rva = 0;
                    if (bin.read(names_off + i * 4, name_rva)) {
                        uint32_t no = rva_to_offset(sections, name_rva);
                        printf("    %s\n", bin.read_string(no).c_str());
                    }
                }
                if (exp.NumberOfNames > 64) printf("    ... (%u more)\n", exp.NumberOfNames - 64);
            }
        }
    }

    // Entry point disassembly
    if (entry) {
        uint32_t ep_off = rva_to_offset(sections, entry);
        if (ep_off && bin.valid(ep_off, 64)) {
            printf("\n=== Entry Point Disassembly (first 64 bytes) ===\n");
            disassemble_linear(bin, ep_off, 64, image_base + entry, is64);
        }
    }

    // .text section dump + disasm if present
    for (const auto& s : sections) {
        char name[9] = {};
        std::memcpy(name, s.Name, 8);
        if (std::string(name).find(".text") != std::string::npos || std::string(name).find("CODE") != std::string::npos) {
            printf("\n=== .text / CODE section (first 128 bytes hex) ===\n");
            hex_dump(bin, s.PointerToRawData, std::min<size_t>(128, s.SizeOfRawData), image_base + s.VirtualAddress);
            printf("\n=== Linear disassembly of start of .text ===\n");
            disassemble_linear(bin, s.PointerToRawData, std::min<size_t>(128, s.SizeOfRawData),
                               image_base + s.VirtualAddress, is64);
            break;
        }
    }
}

void analyze_raw(const Binary& bin) {
    printf("[*] Treating as raw binary\n");
    printf("Size: %zu bytes\n\n", bin.size());
    printf("=== Hex dump (first 256 bytes) ===\n");
    hex_dump(bin, 0, std::min<size_t>(256, bin.size()));
    printf("\n=== Linear x86 disassembly attempt (first 128 bytes) ===\n");
    disassemble_linear(bin, 0, std::min<size_t>(128, bin.size()), 0, true);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <file.exe|file.dll|file.bin>\n", argv[0]);
        return 1;
    }

    std::ifstream f(argv[1], std::ios::binary);
    if (!f) {
        printf("Cannot open %s\n", argv[1]);
        return 1;
    }

    Binary bin;
    f.seekg(0, std::ios::end);
    size_t sz = f.tellg();
    f.seekg(0, std::ios::beg);
    bin.data.resize(sz);
    f.read(reinterpret_cast<char*>(bin.data.data()), sz);
    f.close();

    printf("=== RE Tool (single-file) ===\n");
    printf("File: %s  Size: %zu\n\n", argv[1], bin.size());

    if (bin.size() >= 2 && bin.data[0] == 'M' && bin.data[1] == 'Z') {
        analyze_pe(bin);
    } else {
        analyze_raw(bin);
    }

    return 0;
}
