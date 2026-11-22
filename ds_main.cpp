// main.cpp — single-file x86-64 reverse-engineering tool.
// Build: g++ -std=c++17 -O2 -o reforge main.cpp
// No external libraries.

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// ------------------------------------------------------------
// byte helpers
// ------------------------------------------------------------
static uint16_t r16(const std::vector<uint8_t>& b, size_t o) {
  if (o + 2 > b.size()) return 0;
  return static_cast<uint16_t>(b[o]) |
         (static_cast<uint16_t>(b[o + 1]) << 8);
}
static uint32_t r32(const std::vector<uint8_t>& b, size_t o) {
  if (o + 4 > b.size()) return 0;
  return static_cast<uint32_t>(b[o]) |
         (static_cast<uint32_t>(b[o + 1]) << 8) |
         (static_cast<uint32_t>(b[o + 2]) << 16) |
         (static_cast<uint32_t>(b[o + 3]) << 24);
}
static uint64_t r64(const std::vector<uint8_t>& b, size_t o) {
  if (o + 8 > b.size()) return 0;
  uint64_t v = 0;
  for (int i = 7; i >= 0; --i)
    v = (v << 8) | static_cast<uint64_t>(b[o + static_cast<size_t>(i)]);
  return v;
}
static std::string cstr(const std::vector<uint8_t>& b, size_t off,
                        size_t maxlen = 4096) {
  std::string s;
  if (off >= b.size()) return s;
  const size_t end = std::min(b.size(), off + maxlen);
  for (size_t i = off; i < end; ++i) {
    const char c = static_cast<char>(b[i]);
    if (c == '\0') break;
    s.push_back(c);
  }
  return s;
}
static std::vector<uint8_t> read_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return {};
  in.seekg(0, std::ios::end);
  const std::streamoff n = in.tellg();
  if (n <= 0) return {};
  in.seekg(0, std::ios::beg);
  std::vector<char> tmp(static_cast<size_t>(n));
  in.read(tmp.data(), n);
  return std::vector<uint8_t>(tmp.begin(), tmp.end());
}

// ------------------------------------------------------------
// domain model
// ------------------------------------------------------------
struct Section {
  std::string name;
  uint64_t vaddr = 0;
  uint64_t offset = 0;
  uint64_t size = 0;
  uint64_t flags = 0;
  std::vector<uint8_t> data;
  double entropy = 0.0;
  bool executable() const { return (flags & 0x4ULL) != 0; }
};

struct Import {
  std::string library;
  std::string name;
  uint64_t iat = 0;
};

struct Export {
  std::string name;
  uint64_t addr = 0;
};

struct BinaryInfo {
  std::string path;
  std::string format;
  std::string arch;
  uint64_t entry = 0;
  uint64_t image_base = 0;
  std::vector<Section> sections;
  std::vector<Import> imports;
  std::vector<Export> exports;
};

static double entropy_bytes(const std::vector<uint8_t>& d) {
  if (d.empty()) return 0.0;
  std::array<size_t, 256> cnt{};
  for (uint8_t x : d) ++cnt[x];
  const double n = static_cast<double>(d.size());
  double e = 0.0;
  for (size_t c : cnt) {
    if (!c) continue;
    const double p = static_cast<double>(c) / n;
    e -= p * std::log2(p);
  }
  return e;
}

// ------------------------------------------------------------
// ELF64 parser
// ------------------------------------------------------------
static bool parse_elf(const std::vector<uint8_t>& b, BinaryInfo& bi) {
  if (b.size() < 64) return false;
  if (!(b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F')) return false;
  if (b[4] != 2 || b[5] != 1) return false;  // ELF64 little-endian

  const uint64_t entry = r64(b, 24);
  const uint64_t shoff = r64(b, 40);
  const uint16_t shentsize = r16(b, 58);
  const uint16_t shnum = r16(b, 60);
  const uint16_t shstrndx = r16(b, 62);

  if (shentsize < 64 || shnum == 0) return false;
  if (shoff > b.size() || shnum > (b.size() - shoff) / 64) return false;

  struct SH {
    uint32_t name = 0;
    uint32_t type = 0;
    uint64_t flags = 0;
    uint64_t addr = 0;
    uint64_t off = 0;
    uint64_t size = 0;
    uint32_t link = 0;
  };
  std::vector<SH> shs;
  shs.reserve(shnum);
  for (uint16_t i = 0; i < shnum; ++i) {
    const size_t o = static_cast<size_t>(shoff) + static_cast<size_t>(i) * 64;
    SH s;
    s.name = r32(b, o + 0);
    s.type = r32(b, o + 4);
    s.flags = r64(b, o + 8);
    s.addr = r64(b, o + 16);
    s.off = r64(b, o + 24);
    s.size = r64(b, o + 32);
    s.link = r32(b, o + 40);
    shs.push_back(s);
  }

  uint64_t shstr_off = 0, shstr_size = 0;
  if (shstrndx < shs.size()) {
    shstr_off = shs[shstrndx].off;
    shstr_size = shs[shstrndx].size;
  }

  for (const SH& sh : shs) {
    Section sec;
    sec.name = cstr(b, static_cast<size_t>(shstr_off + sh.name),
                    static_cast<size_t>(shstr_size));
    sec.vaddr = sh.addr;
    sec.offset = sh.off;
    sec.size = sh.size;
    sec.flags = sh.flags;
    if (sh.off <= b.size() && sh.size <= b.size() - sh.off) {
      sec.data.assign(b.begin() + static_cast<std::ptrdiff_t>(sh.off),
                      b.begin() + static_cast<std::ptrdiff_t>(sh.off + sh.size));
      sec.entropy = entropy_bytes(sec.data);
    }
    bi.sections.push_back(std::move(sec));
  }

  // imports / exports from .symtab and .dynsym
  for (const SH& sh : shs) {
    if (sh.type != 2 && sh.type != 11) continue;  // SHT_SYMTAB / SHT_DYNSYM
    if (sh.link >= shs.size()) continue;
    const SH& str = shs[sh.link];
    if (sh.off > b.size() || sh.size > b.size() - sh.off) continue;
    const size_t count = static_cast<size_t>(sh.size / 24);
    for (size_t i = 0; i < count; ++i) {
      const size_t o = static_cast<size_t>(sh.off) + i * 24;
      if (o + 24 > b.size()) break;
      const uint32_t nameoff = r32(b, o);
      const uint8_t info = b[o + 4];
      const uint16_t shndx = r16(b, o + 6);
      const uint64_t value = r64(b, o + 8);
      if (nameoff == 0) continue;
      std::string name = cstr(b, static_cast<size_t>(str.off + nameoff),
                              static_cast<size_t>(str.size));
      if (name.empty()) continue;
      if (shndx == 0) {
        bi.imports.push_back(Import{"", std::move(name), 0});
      } else if ((info & 0x0f) == 2 && value != 0) {
        bi.exports.push_back(Export{std::move(name), value});
      }
    }
  }

  bi.format = "ELF64";
  bi.entry = entry;
  bi.arch = "unknown";
  const uint16_t machine = r16(b, 18);
  if (machine == 62) bi.arch = "x86_64";
  else if (machine == 3) bi.arch = "x86";
  else if (machine == 183) bi.arch = "aarch64";
  else if (machine == 40) bi.arch = "arm";
  else if (machine == 8) bi.arch = "mips";
  else if (machine == 20) bi.arch = "ppc";
  else if (machine == 21) bi.arch = "ppc64";
  return true;
}

// ------------------------------------------------------------
// PE32 / PE32+ parser
// ------------------------------------------------------------
static bool parse_pe(const std::vector<uint8_t>& b, BinaryInfo& bi) {
  if (b.size() < 0x40 || b[0] != 'M' || b[1] != 'Z') return false;
  const uint32_t peoff = r32(b, 0x3c);
  if (peoff > b.size() || peoff + 24 > b.size()) return false;
  if (!(b[peoff] == 'P' && b[peoff + 1] == 'E' && b[peoff + 2] == 0 &&
        b[peoff + 3] == 0))
    return false;

  const uint16_t machine = r16(b, peoff + 4);
  const uint16_t nsec = r16(b, peoff + 6);
  const uint16_t optsize = r16(b, peoff + 20);
  const size_t opt = static_cast<size_t>(peoff) + 24;
  if (opt + 2 > b.size()) return false;
  const uint16_t magic = r16(b, opt);
  const bool pe64 = magic == 0x20b;
  if (!pe64 && magic != 0x10b) return false;
  if (opt + optsize > b.size()) return false;

  const uint32_t entry_rva = r32(b, opt + 16);
  const uint64_t image_base =
      pe64 ? r64(b, opt + 24) : static_cast<uint64_t>(r32(b, opt + 28));

  const size_t dd_off = opt + (pe64 ? 112 : 96);
  const uint32_t ndirs = r32(b, opt + (pe64 ? 108 : 92));

  struct PESec {
    std::string name;
    uint32_t va = 0;
    uint32_t vsize = 0;
    uint32_t raw = 0;
    uint32_t rawsize = 0;
    uint32_t chars = 0;
  };
  std::vector<PESec> psecs;
  const size_t sec_table = opt + optsize;
  for (uint16_t i = 0; i < nsec; ++i) {
    const size_t o = sec_table + static_cast<size_t>(i) * 40;
    if (o + 40 > b.size()) break;
    PESec s;
    s.name = cstr(b, o, 8);
    s.vsize = r32(b, o + 8);
    s.va = r32(b, o + 12);
    s.rawsize = r32(b, o + 16);
    s.raw = r32(b, o + 20);
    s.chars = r32(b, o + 36);
    psecs.push_back(s);
  }

  auto rva2off = [&](uint32_t rva) -> std::optional<uint32_t> {
    for (const PESec& s : psecs) {
      const uint32_t span = std::max(s.vsize, s.rawsize);
      if (rva >= s.va && rva < s.va + span && s.raw < b.size()) {
        const uint64_t off = static_cast<uint64_t>(s.raw) + (rva - s.va);
        if (off < b.size()) return static_cast<uint32_t>(off);
      }
    }
    if (rva < b.size()) return rva;  // headers
    return std::nullopt;
  };

  auto dir = [&](size_t idx) -> std::pair<uint32_t, uint32_t> {
    if (idx >= ndirs || dd_off + idx * 8 + 8 > b.size()) return {0, 0};
    return {r32(b, dd_off + idx * 8), r32(b, dd_off + idx * 8 + 4)};
  };

  for (const PESec& s : psecs) {
    Section sec;
    sec.name = s.name;
    sec.vaddr = image_base + s.va;
    sec.offset = s.raw;
    sec.size = s.rawsize;
    sec.flags = (s.chars & 0x20000000u) ? 0x4ULL : 0ULL;
    if (s.raw <= b.size() && s.rawsize <= b.size() - s.raw) {
      sec.data.assign(b.begin() + static_cast<std::ptrdiff_t>(s.raw),
                      b.begin() + static_cast<std::ptrdiff_t>(s.raw + s.rawsize));
      sec.entropy = entropy_bytes(sec.data);
    }
    bi.sections.push_back(std::move(sec));
  }

  // imports
  auto impdir = dir(1);
  if (impdir.first && impdir.second) {
    auto impoff = rva2off(impdir.first);
    if (impoff) {
      size_t o = *impoff;
      for (int guard = 0; guard < 4096 && o + 20 <= b.size(); ++guard, o += 20) {
        const uint32_t orig_thunk = r32(b, o + 0);
        const uint32_t name_rva = r32(b, o + 12);
        const uint32_t first_thunk = r32(b, o + 16);
        if (!name_rva) break;
        auto liboff = rva2off(name_rva);
        std::string lib = liboff ? cstr(b, *liboff) : std::string();
        const uint32_t thunk_rva = orig_thunk ? orig_thunk : first_thunk;
        auto thunkoff = rva2off(thunk_rva);
        if (!thunkoff) continue;
        size_t t = *thunkoff;
        for (int tguard = 0; tguard < 65536; ++tguard) {
          const uint64_t val = pe64 ? r64(b, t) : r32(b, t);
          if (!val) break;
          const uint64_t flag = pe64 ? 0x8000000000000000ULL : 0x80000000ULL;
          std::string name;
          if (val & flag) {
            name = "#" + std::to_string(val & 0xffff);
          } else {
            const uint32_t hint_rva = static_cast<uint32_t>(val & 0x7fffffffULL);
            auto hintoff = rva2off(hint_rva + 2);
            if (hintoff) name = cstr(b, *hintoff);
          }
          bi.imports.push_back(
              Import{lib, std::move(name), image_base + first_thunk});
          t += pe64 ? 8 : 4;
        }
      }
    }
  }

  // exports
  auto expdir = dir(0);
  if (expdir.first && expdir.second) {
    auto expoff = rva2off(expdir.first);
    if (expoff && *expoff + 40 <= b.size()) {
      const size_t e = *expoff;
      const uint32_t nfuncs = r32(b, e + 20);
      const uint32_t nnames = r32(b, e + 24);
      const uint32_t funcs_rva = r32(b, e + 28);
      const uint32_t names_rva = r32(b, e + 32);
      const uint32_t ords_rva = r32(b, e + 36);
      auto funcs_off = rva2off(funcs_rva);
      auto names_off = rva2off(names_rva);
      auto ords_off = rva2off(ords_rva);
      if (funcs_off && names_off && ords_off) {
        for (uint32_t i = 0; i < nnames && i < nfuncs; ++i) {
          const size_t no = *names_off + i * 4;
          const size_t oo = *ords_off + i * 2;
          if (no + 4 > b.size() || oo + 2 > b.size()) break;
          const uint32_t name_rva = r32(b, no);
          const uint16_t ord = r16(b, oo);
          auto nameoff = rva2off(name_rva);
          if (!nameoff) continue;
          const size_t fo = *funcs_off + static_cast<size_t>(ord) * 4;
          if (fo + 4 > b.size()) continue;
          const uint32_t func_rva = r32(b, fo);
          if (!func_rva) continue;
          std::string name = cstr(b, *nameoff);
          if (!name.empty())
            bi.exports.push_back(Export{std::move(name), image_base + func_rva});
        }
      }
    }
  }

  bi.format = pe64 ? "PE32+" : "PE32";
  bi.image_base = image_base;
  bi.entry = image_base + entry_rva;
  if (machine == 0x8664) bi.arch = "x86_64";
  else if (machine == 0x14c) bi.arch = "x86";
  else if (machine == 0xaa64) bi.arch = "aarch64";
  else if (machine == 0x1c0) bi.arch = "arm";
  return true;
}

// ------------------------------------------------------------
// x86 / x86-64 length decoder
// Conservative: unknown or unsupported encodings return length 0.
// ------------------------------------------------------------
struct Decoded {
  uint64_t addr = 0;
  size_t len = 0;
  bool call = false;
  bool jump = false;
  bool ret = false;
  bool uncond = false;
  bool has_target = false;
  int64_t target = 0;
};

static int32_t s32(const uint8_t* p) {
  return static_cast<int32_t>(static_cast<uint32_t>(p[0]) |
                              (static_cast<uint32_t>(p[1]) << 8) |
                              (static_cast<uint32_t>(p[2]) << 16) |
                              (static_cast<uint32_t>(p[3]) << 24));
}

static Decoded decode_one(const uint8_t* p, size_t n, uint64_t addr) {
  Decoded d;
  d.addr = addr;
  size_t i = 0;
  bool opsz = false;
  bool addrsz = false;
  bool rexw = false;

  while (i < n && i < 15) {
    const uint8_t b = p[i];
    if (b == 0x66) { opsz = true; ++i; continue; }
    if (b == 0x67) { addrsz = true; ++i; continue; }
    if (b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x36 ||
        b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) {
      ++i;
      continue;
    }
    if (b >= 0x40 && b <= 0x4F) {
      rexw = (b & 8) != 0;
      ++i;
      continue;
    }
    break;
  }
  if (i >= n) return {};

  const size_t op_pos = i;
  const uint8_t op = p[i++];

  if (op == 0xC4 || op == 0xC5 || op == 0x62) return {};  // VEX/EVEX

  auto imm_size = [&](int kind) -> int {
    if (kind == 1) return 1;
    if (kind == 4) return 4;
    if (kind == 8) return 8;
    if (kind == 2) return opsz ? 2 : 4;
    return 0;
  };

  auto modrm = [&]() -> int {
    if (i >= n) return -1;
    const uint8_t m = p[i++];
    const int mod = m >> 6;
    const int rm = m & 7;
    int disp = 0;
    if (mod != 3) {
      if (rm == 4) {
        if (i >= n) return -1;
        const uint8_t sib = p[i++];
        const int base = sib & 7;
        if (mod == 0 && base == 5) disp = 4;
        else if (mod == 1) disp = 1;
        else if (mod == 2) disp = 4;
      } else {
        if (mod == 0 && rm == 5) disp = 4;
        else if (mod == 1) disp = 1;
        else if (mod == 2) disp = 4;
      }
    }
    if (i + static_cast<size_t>(disp) > n) return -1;
    i += static_cast<size_t>(disp);
    return 0;
  };

  auto alu = [&](int off) -> bool {
    if (off < 4) {
      if (modrm() < 0) return false;
      d.len = i;
      return true;
    }
    if (off == 4) {
      if (i + 1 > n) return false;
      i += 1;
      d.len = i;
      return true;
    }
    const int k = opsz ? 2 : 4;
    if (i + static_cast<size_t>(k) > n) return false;
    i += static_cast<size_t>(k);
    d.len = i;
    return true;
  };

  if ((op <= 0x05) || (op >= 0x08 && op <= 0x0D) ||
      (op >= 0x10 && op <= 0x15) || (op >= 0x18 && op <= 0x1D) ||
      (op >= 0x20 && op <= 0x25) || (op >= 0x28 && op <= 0x2D) ||
      (op >= 0x30 && op <= 0x35) || (op >= 0x38 && op <= 0x3D)) {
    int off = 0;
    if (op <= 0x05) off = op - 0x00;
    else if (op <= 0x0D) off = op - 0x08;
    else if (op <= 0x15) off = op - 0x10;
    else if (op <= 0x1D) off = op - 0x18;
    else if (op <= 0x25) off = op - 0x20;
    else if (op <= 0x2D) off = op - 0x28;
    else if (op <= 0x35) off = op - 0x30;
    else off = op - 0x38;
    if (!alu(off)) return {};
    return d;
  }

  switch (op) {
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57:
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
    case 0x90: case 0x91: case 0x92: case 0x93:
    case 0x94: case 0x95: case 0x96: case 0x97:
    case 0x98: case 0x99: case 0x9A: case 0x9B:
    case 0x9C: case 0x9D: case 0x9E: case 0x9F:
    case 0xA4: case 0xA5: case 0xA6: case 0xA7:
    case 0xAA: case 0xAB: case 0xAC: case 0xAD:
    case 0xAE: case 0xAF:
      d.len = i;
      return d;

    case 0x63:
      if (modrm() < 0) return {};
      d.len = i;
      return d;

    case 0x68:
      if (i + 4 > n) return {};
      i += 4;
      d.len = i;
      return d;
    case 0x69:
      if (modrm() < 0) return {};
      if (i + static_cast<size_t>(opsz ? 2 : 4) > n) return {};
      i += static_cast<size_t>(opsz ? 2 : 4);
      d.len = i;
      return d;
    case 0x6A:
      if (i + 1 > n) return {};
      i += 1;
      d.len = i;
      return d;
    case 0x6B:
      if (modrm() < 0) return {};
      if (i + 1 > n) return {};
      i += 1;
      d.len = i;
      return d;

    case 0x70: case 0x71: case 0x72: case 0x73:
    case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F:
    case 0xEB: {
      if (i + 1 > n) return {};
      const int8_t rel = static_cast<int8_t>(p[i]);
      i += 1;
      d.len = i;
      d.jump = true;
      d.uncond = (op == 0xEB);
      d.has_target = true;
      d.target = static_cast<int64_t>(addr) + static_cast<int64_t>(d.len) + rel;
      return d;
    }

    case 0x80:
      if (modrm() < 0 || i + 1 > n) return {};
      i += 1;
      d.len = i;
      return d;
    case 0x81:
      if (modrm() < 0) return {};
      if (i + static_cast<size_t>(opsz ? 2 : 4) > n) return {};
      i += static_cast<size_t>(opsz ? 2 : 4);
      d.len = i;
      return d;
    case 0x83:
      if (modrm() < 0 || i + 1 > n) return {};
      i += 1;
      d.len = i;
      return d;

    case 0x84: case 0x85: case 0x86: case 0x87:
    case 0x88: case 0x89: case 0x8A: case 0x8B:
    case 0x8C: case 0x8D: case 0x8E: case 0x8F:
      if (modrm() < 0) return {};
      d.len = i;
      return d;

    case 0xA0: case 0xA1: case 0xA2: case 0xA3: {
      const int k = addrsz ? 4 : 8;
      if (i + static_cast<size_t>(k) > n) return {};
      i += static_cast<size_t>(k);
      d.len = i;
      return d;
    }
    case 0xA8:
      if (i + 1 > n) return {};
      i += 1;
      d.len = i;
      return d;
    case 0xA9:
      if (i + static_cast<size_t>(opsz ? 2 : 4) > n) return {};
      i += static_cast<size_t>(opsz ? 2 : 4);
      d.len = i;
      return d;

    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
      if (i + 1 > n) return {};
      i += 1;
      d.len = i;
      return d;
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
      const int k = rexw ? 8 : (opsz ? 2 : 4);
      if (i + static_cast<size_t>(k) > n) return {};
      i += static_cast<size_t>(k);
      d.len = i;
      return d;
    }

    case 0xC0: case 0xC1:
      if (modrm() < 0 || i + 1 > n) return {};
      i += 1;
      d.len = i;
      return d;
    case 0xC2: case 0xCA:
      if (i + 2 > n) return {};
      i += 2;
      d.len = i;
      d.ret = true;
      return d;
    case 0xC3: case 0xCB:
      d.len = i;
      d.ret = true;
      return d;
    case 0xC6:
      if (modrm() < 0 || i + 1 > n) return {};
      i += 1;
      d.len = i;
      return d;
    case 0xC7:
      if (modrm() < 0) return {};
      if (i + static_cast<size_t>(opsz ? 2 : 4) > n) return {};
      i += static_cast<size_t>(opsz ? 2 : 4);
      d.len = i;
      return d;
    case 0xC8:
      if (i + 3 > n) return {};
      i += 3;
      d.len = i;
      return d;
    case 0xCC:
      d.len = i;
      return d;
    case 0xCD:
      if (i + 1 > n) return {};
      i += 1;
      d.len = i;
      return d;

    case 0xD0: case 0xD1: case 0xD2: case 0xD3:
    case 0xD8: case 0xD9: case 0xDA: case 0xDB:
    case 0xDC: case 0xDD: case 0xDE: case 0xDF:
      if (modrm() < 0) return {};
      d.len = i;
      return d;

    case 0xE0: case 0xE1: case 0xE2: case 0xE3:
    case 0xE4: case 0xE5: case 0xE6: case 0xE7:
      if (i + 1 > n) return {};
      i += 1;
      d.len = i;
      return d;
    case 0xE8: case 0xE9: {
      if (i + 4 > n) return {};
      const int32_t rel = s32(p + i);
      i += 4;
      d.len = i;
      d.has_target = true;
      d.target = static_cast<int64_t>(addr) + static_cast<int64_t>(d.len) + rel;
      d.call = (op == 0xE8);
      d.jump = (op == 0xE9);
      d.uncond = d.jump;
      return d;
    }

    case 0xF1: case 0xF4: case 0xF5:
    case 0xF8: case 0xF9: case 0xFA: case 0xFB:
    case 0xFC: case 0xFD:
      d.len = i;
      return d;

    case 0xF6: case 0xF7: {
      const size_t mp = i;
      if (modrm() < 0) return {};
      const uint8_t m = p[mp];
      const int reg = (m >> 3) & 7;
      if (reg <= 1) {
        const int k = (op == 0xF6) ? 1 : (opsz ? 2 : 4);
        if (i + static_cast<size_t>(k) > n) return {};
        i += static_cast<size_t>(k);
      }
      d.len = i;
      return d;
    }

    case 0xFE:
      if (modrm() < 0) return {};
      d.len = i;
      return d;

    case 0xFF: {
      const size_t mp = i;
      if (modrm() < 0) return {};
      const uint8_t m = p[mp];
      const int reg = (m >> 3) & 7;
      if (reg == 2 || reg == 3) d.call = true;
      if (reg == 4 || reg == 5) {
        d.jump = true;
        d.uncond = (reg == 4);
      }
      d.len = i;
      return d;
    }

    default:
      break;
  }

  if (op == 0x0F) {
    if (i >= n) return {};
    const uint8_t op2 = p[i++];

    if (op2 >= 0x80 && op2 <= 0x8F) {
      if (i + 4 > n) return {};
      const int32_t rel = s32(p + i);
      i += 4;
      d.len = i;
      d.jump = true;
      d.uncond = false;
      d.has_target = true;
      d.target = static_cast<int64_t>(addr) + static_cast<int64_t>(d.len) + rel;
      return d;
    }

    const bool no_operand =
        op2 == 0x05 || op2 == 0x06 || op2 == 0x07 || op2 == 0x08 ||
        op2 == 0x09 || op2 == 0x0B || op2 == 0x0E || op2 == 0x30 ||
        op2 == 0x31 || op2 == 0x32 || op2 == 0x33 || op2 == 0x34 ||
        op2 == 0x35 || op2 == 0x37 || op2 == 0x77 || op2 == 0xA2 ||
        op2 == 0xAA;
    if (no_operand) {
      d.len = i;
      return d;
    }

    if (op2 == 0x0F) {
      if (modrm() < 0 || i + 1 > n) return {};
      i += 1;
      d.len = i;
      return d;
    }
    if (op2 == 0x38) {
      if (modrm() < 0) return {};
      d.len = i;
      return d;
    }
    if (op2 == 0x3A) {
      if (modrm() < 0 || i + 1 > n) return {};
      i += 1;
      d.len = i;
      return d;
    }
    if (op2 == 0xBA || op2 == 0xA4 || op2 == 0xAC) {
      if (modrm() < 0 || i + 1 > n) return {};
      i += 1;
      d.len = i;
      return d;
    }

    const bool has_modrm =
        (op2 >= 0x10 && op2 <= 0x1F) || (op2 >= 0x28 && op2 <= 0x2F) ||
        (op2 >= 0x40 && op2 <= 0x4F) || (op2 >= 0x50 && op2 <= 0x7F) ||
        (op2 >= 0x90 && op2 <= 0x9F) || op2 == 0x01 || op2 == 0xAE ||
        op2 == 0xAF || op2 == 0xB0 || op2 == 0xB1 || op2 == 0xB6 ||
        op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF || op2 == 0xA3 ||
        op2 == 0xAB || op2 == 0xB3 || op2 == 0xBB || op2 == 0xC0 ||
        op2 == 0xC1 || op2 == 0xC7;
    if (has_modrm) {
      if (modrm() < 0) return {};
      d.len = i;
      return d;
    }

    return {};
  }

  return {};
}

// ------------------------------------------------------------
// analysis
// ------------------------------------------------------------
struct Xref {
  uint64_t from = 0;
  uint64_t to = 0;
  bool call = false;
};

struct BlockOut {
  uint64_t start = 0;
  uint64_t end = 0;
  std::vector<uint64_t> succ;
};

struct FuncOut {
  uint64_t start = 0;
  std::string name;
  std::vector<BlockOut> blocks;
};

struct Analysis {
  std::set<uint64_t> functions;
  std::vector<Xref> xrefs;
  std::vector<FuncOut> funcs;
};

static const Section* find_exec_section(const BinaryInfo& bi, uint64_t addr) {
  for (const Section& s : bi.sections) {
    if (!s.executable() || s.data.empty()) continue;
    if (addr >= s.vaddr && addr < s.vaddr + s.data.size()) return &s;
  }
  return nullptr;
}

static Analysis analyze(const BinaryInfo& bi) {
  Analysis a;
  if (bi.entry) a.functions.insert(bi.entry);
  for (const Export& e : bi.exports) a.functions.insert(e.addr);

  // linear sweep: collect direct xrefs and call targets
  for (const Section& sec : bi.sections) {
    if (!sec.executable() || sec.data.empty()) continue;
    size_t pos = 0;
    while (pos < sec.data.size()) {
      Decoded d = decode_one(sec.data.data() + pos, sec.data.size() - pos,
                             sec.vaddr + pos);
      if (d.len == 0 || pos + d.len > sec.data.size()) {
        ++pos;
        continue;
      }
      if (d.has_target) {
        const uint64_t target = static_cast<uint64_t>(d.target);
        if (d.call) {
          a.xrefs.push_back(Xref{sec.vaddr + pos, target, true});
          a.functions.insert(target);
        } else if (d.jump) {
          a.xrefs.push_back(Xref{sec.vaddr + pos, target, false});
        }
      }
      pos += d.len;
    }
  }

  std::map<uint64_t, std::string> names;
  for (const Export& e : bi.exports) names[e.addr] = e.name;

  size_t emitted = 0;
  for (uint64_t start : a.functions) {
    if (emitted++ >= 4096) break;
    const Section* sec = find_exec_section(bi, start);
    if (!sec) continue;

    std::vector<Decoded> ins;
    size_t off = static_cast<size_t>(start - sec->vaddr);
    const size_t limit = std::min(sec->data.size(), off + 0x100000);
    while (off < limit && ins.size() < 8192) {
      Decoded d = decode_one(sec->data.data() + off, limit - off,
                             sec->vaddr + off);
      if (d.len == 0 || off + d.len > limit) break;
      ins.push_back(d);
      off += d.len;
      if (d.ret || d.uncond) break;
    }
    if (ins.empty()) continue;

    std::set<size_t> leaders{0};
    std::unordered_map<uint64_t, size_t> by_addr;
    for (size_t i = 0; i < ins.size(); ++i) by_addr[ins[i].addr] = i;

    for (size_t i = 0; i < ins.size(); ++i) {
      if (ins[i].has_target) {
        auto it = by_addr.find(static_cast<uint64_t>(ins[i].target));
        if (it != by_addr.end() && it->second > i) leaders.insert(it->second);
      }
      if ((ins[i].jump || ins[i].ret) && i + 1 < ins.size())
        leaders.insert(i + 1);
    }

    std::vector<size_t> ls(leaders.begin(), leaders.end());
    FuncOut fo;
    fo.start = start;
    auto nit = names.find(start);
    fo.name = (nit != names.end()) ? nit->second : "";

    for (size_t k = 0; k < ls.size(); ++k) {
      const size_t begin = ls[k];
      const size_t end = (k + 1 < ls.size()) ? ls[k + 1] : ins.size();
      if (begin >= end) continue;
      BlockOut bo;
      bo.start = ins[begin].addr;
      bo.end = ins[end - 1].addr + ins[end - 1].len;

      const Decoded& last = ins[end - 1];
      if (!last.ret) {
        if (last.uncond && last.has_target) {
          bo.succ.push_back(static_cast<uint64_t>(last.target));
        } else if (last.jump) {
          if (last.has_target) bo.succ.push_back(static_cast<uint64_t>(last.target));
          if (end < ins.size()) bo.succ.push_back(ins[end].addr);
        } else if (end < ins.size()) {
          bo.succ.push_back(ins[end].addr);
        }
      }
      fo.blocks.push_back(std::move(bo));
    }
    if (!fo.blocks.empty()) a.funcs.push_back(std::move(fo));
  }

  return a;
}

// ------------------------------------------------------------
// strings
// ------------------------------------------------------------
static std::vector<std::string> extract_strings(const BinaryInfo& bi,
                                                size_t minlen = 4,
                                                size_t max_items = 20000) {
  std::vector<std::string> out;
  std::unordered_set<std::string> seen;
  for (const Section& sec : bi.sections) {
    if (sec.data.empty()) continue;
    size_t i = 0;
    while (i < sec.data.size() && out.size() < max_items) {
      const unsigned char c = sec.data[i];
      if (!std::isprint(c)) {
        ++i;
        continue;
      }
      const size_t start = i;
      while (i < sec.data.size() && std::isprint(sec.data[i]) &&
             i - start < 4096)
        ++i;
      if (i - start >= minlen) {
        std::string s(reinterpret_cast<const char*>(sec.data.data() + start),
                      i - start);
        if (seen.insert(s).second) out.push_back(std::move(s));
      }
    }
  }
  return out;
}

// ------------------------------------------------------------
// output
// ------------------------------------------------------------
static void hex(std::ostream& os, uint64_t v) {
  os << "0x" << std::hex << v << std::dec;
}

static void print_summary(const BinaryInfo& bi) {
  std::cout << "format: " << bi.format << "\n";
  std::cout << "arch:   " << bi.arch << "\n";
  std::cout << "entry:  "; hex(std::cout, bi.entry); std::cout << "\n";
  if (bi.image_base) {
    std::cout << "image:  "; hex(std::cout, bi.image_base); std::cout << "\n";
  }
  std::cout << "\nsections:\n";
  for (const Section& s : bi.sections) {
    std::cout << "  " << std::left << std::setw(22) << s.name << " ";
    hex(std::cout, s.vaddr);
    std::cout << " size=";
    hex(std::cout, s.size);
    std::cout << " entropy=" << std::fixed << std::setprecision(3) << s.entropy;
    if (s.executable()) std::cout << " [exec]";
    std::cout << "\n";
  }
  if (!bi.imports.empty()) {
    std::cout << "\nimports:\n";
    for (const Import& im : bi.imports) {
      std::cout << "  ";
      if (!im.library.empty()) std::cout << im.library << "!";
      std::cout << im.name << "\n";
    }
  }
  if (!bi.exports.empty()) {
    std::cout << "\nexports:\n";
    for (const Export& ex : bi.exports) {
      std::cout << "  "; hex(std::cout, ex.addr);
      std::cout << " " << ex.name << "\n";
    }
  }
}

static void print_disasm(const BinaryInfo& bi) {
  for (const Section& sec : bi.sections) {
    if (!sec.executable() || sec.data.empty()) continue;
    std::cout << "\n; " << sec.name << " @ ";
    hex(std::cout, sec.vaddr);
    std::cout << "\n";
    size_t pos = 0;
    size_t count = 0;
    while (pos < sec.data.size() && count++ < 500000) {
      const Decoded d = decode_one(sec.data.data() + pos,
                                   sec.data.size() - pos, sec.vaddr + pos);
      if (d.len == 0) {
        std::cout << "  "; hex(std::cout, sec.vaddr + pos);
        std::cout << "  db 0x" << std::hex
                  << static_cast<unsigned>(sec.data[pos]) << std::dec << "\n";
        ++pos;
        continue;
      }
      std::cout << "  "; hex(std::cout, d.addr);
      std::cout << "  ";
      for (size_t i = 0; i < d.len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned>(sec.data[pos + i]) << std::dec
                  << std::setfill(' ');
      }
      for (size_t i = d.len; i < 12; ++i) std::cout << "   ";
      if (d.call) std::cout << " call";
      else if (d.ret) std::cout << " ret";
      else if (d.jump) std::cout << (d.uncond ? " jmp" : " jcc");
      if (d.has_target) {
        std::cout << " -> ";
        hex(std::cout, static_cast<uint64_t>(d.target));
      }
      std::cout << "\n";
      pos += d.len;
    }
  }
}

static void print_cfg(const Analysis& a) {
  std::cout << "\nfunctions/blocks:\n";
  for (const FuncOut& f : a.funcs) {
    std::cout << "\nfunction "; hex(std::cout, f.start);
    if (!f.name.empty()) std::cout << " " << f.name;
    std::cout << "\n";
    for (const BlockOut& b : f.blocks) {
      std::cout << "  block "; hex(std::cout, b.start);
      std::cout << " - "; hex(std::cout, b.end);
      if (b.succ.empty()) {
        std::cout << " (exit)\n";
      } else {
        std::cout << " ->";
        for (uint64_t s : b.succ) {
          std::cout << " "; hex(std::cout, s);
        }
        std::cout << "\n";
      }
    }
  }
  std::cout << "\ncall/jump xrefs:\n";
  size_t shown = 0;
  for (const Xref& x : a.xrefs) {
    if (shown++ >= 20000) break;
    std::cout << "  "; hex(std::cout, x.from);
    std::cout << (x.call ? " call " : " jump ");
    hex(std::cout, x.to);
    std::cout << "\n";
  }
}

static void usage(const char* argv0) {
  std::cout << "usage: " << argv0 << " <binary> [--disasm] [--cfg] [--strings]\n";
}

int main(int argc, char** argv) {
  if (argc < 2) {
    usage(argv[0]);
    return 1;
  }

  std::string path;
  bool want_disasm = false;
  bool want_cfg = false;
  bool want_strings = false;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "--disasm") want_disasm = true;
    else if (a == "--cfg") want_cfg = true;
    else if (a == "--strings") want_strings = true;
    else if (a == "--help" || a == "-h") {
      usage(argv[0]);
      return 0;
    } else if (!a.empty() && a[0] == '-') {
      std::cerr << "unknown option: " << a << "\n";
      return 1;
    } else if (path.empty()) {
      path = a;
    }
  }

  if (path.empty()) {
    usage(argv[0]);
    return 1;
  }

  const std::vector<uint8_t> raw = read_file(path);
  if (raw.empty()) {
    std::cerr << "error: cannot read file\n";
    return 1;
  }

  BinaryInfo bi;
  bi.path = path;
  bool ok = false;
  if (raw.size() >= 4 && raw[0] == 0x7f && raw[1] == 'E' && raw[2] == 'L' &&
      raw[3] == 'F') {
    ok = parse_elf(raw, bi);
  } else if (raw.size() >= 2 && raw[0] == 'M' && raw[1] == 'Z') {
    ok = parse_pe(raw, bi);
  }
  if (!ok) {
    std::cerr << "error: unsupported or malformed binary\n";
    return 1;
  }

  print_summary(bi);

  if (want_strings) {
    const auto ss = extract_strings(bi);
    std::cout << "\nstrings (" << ss.size() << "):\n";
    for (const std::string& s : ss) std::cout << "  " << s << "\n";
  }
  if (want_disasm) print_disasm(bi);
  if (want_cfg) print_cfg(analyze(bi));

  return 0;
}
