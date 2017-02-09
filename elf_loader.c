#include "elf_loader.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/auxv.h>

#define powerof2(x) ((((x)-1)&(x))==0)

#define PAGE_START(x) ((x) & PAGE_MASK)
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)
#define PAGE_END(x) PAGE_START((x) + (PAGE_SIZE-1))

static LIST_HEAD(mod_list);

static struct elf_module *elf_module_alloc(const char *name)
{
    struct elf_module *m;

    if (strlen(name) >= ELF_MODULE_NAME_LEN) {
        LOG_ERR("ELF name to long");
        return NULL;
    }

    m = malloc(sizeof(*m));
    if (m == NULL) {
        LOG_ERR("\"%s\" elf module memory alloc failed: %s", name, strerror(errno));
        return NULL;
    }

    memset(m, 0, sizeof(*m));
    strncpy(m->name, name, sizeof(m->name) - 1);
    INIT_LIST_HEAD(&m->list);
    m->refcnt = 1;

    LOG_DEBUG("name %s: allocated struct elf_module @ %p", name, m);
    return m;
}

static void elf_module_free(struct elf_module *m)
{    
    if (!m)
        return;
    
    LOG_DEBUG("name %s: freeing soinfo @ %p", m->name, m);
        
    if (m->base)
        munmap((void *)m->base, m->size);
    free(m);
}

static struct elf_module *find_module(const char *name)
{
    struct list_head *pos;
    struct elf_module *m = NULL, *tmp;

    list_for_each(pos, &mod_list) {
        tmp = list_entry(pos, struct elf_module, list);
        if (!strcmp(name, tmp->name)) {
            m = tmp;
            break;
        }
    }

    if (m != NULL) {
        if (m->flags & FLAG_LINKED)
            return m;
        LOG_ERR("OOPS: recursive link to \"%s\"", m->name);
        return NULL;
    }

    LOG_DEBUG("[ \"%s\" has not been loaded yet ]", name);
    return NULL;
}

//
// elf info
//

struct elf_info {
    const char *name;
    const ElfW(Ehdr) *hdr;
    size_t len;

    ElfW(Phdr) *phdr_table;
};

#if defined(__x86_64__)
#define elf_check_arch(x) ((x)->e_machine == EM_X86_64)
#elif defined(__i386__)
#define elf_check_arch(x) ((x)->e_machine == EM_386)
#endif

static bool verify_elf_header(struct elf_info *info)
{
    int elf_class;

    if (info->len < sizeof(*(info->hdr))) {
        LOG_ERR("\"%s\" is too small to be an ELF executable. Expected at least %zu bytes, "
                "only found %zu bytes", info->name, sizeof(*(info->hdr)), info->len);
		return false;
    }
	if (memcmp(info->hdr->e_ident, ELFMAG, SELFMAG)) {
        LOG_ERR("\"%s\" has bad ELF magic", info->name);
        return false;
    }
    
    // Try to give a clear diagnostic for ELF class mismatches, since they're
    // an easy mistake to make during the 32-bit/64-bit transition period.
    elf_class = info->hdr->e_ident[EI_CLASS];
#if defined(__LP64__)
    if (elf_class != ELFCLASS64) {
        if (elf_class == ELFCLASS32) {
            LOG_ERR("\"%s\" is 32-bit instead of 64-bit", info->name);
        } else {
            LOG_ERR("\"%s\" has unknown ELF class: %d", info->name, elf_class);
        }
        return false;
    }
#else
    if (elf_class != ELFCLASS32) {
        if (elf_class == ELFCLASS64) {
            LOG_ERR("\"%s\" is 64-bit instead of 32-bit", info->name);
        } else {
            LOG_ERR("\"%s\" has unknown ELF class: %d", info->name, elf_class);
        }
        return false;
    }
#endif

    if (info->hdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        LOG_ERR("\"%s\" not little-endian: %d", info->name, info->hdr->e_ident[EI_DATA]);
        return false;
    }

	if (info->hdr->e_type != ET_EXEC && info->hdr->e_type != ET_DYN) {
        LOG_ERR("\"%s\" has unexpected e_type: %d", info->name, info->hdr->e_type);
        return false;
    }

    if (info->hdr->e_version != EV_CURRENT) {
        LOG_ERR("\"%s\" has unexpected e_version: %d", info->name, info->hdr->e_version);
        return false;
    }

	if (!elf_check_arch(info->hdr)) {
        LOG_ERR("\"%s\" has unexpected e_machine: %d", info->name, info->hdr->e_machine);
    	return false;
    }

    LOG_DEBUG("\"%s\" verify elf header done.", info->name);
    return true;
}

static bool read_program_headers(struct elf_info *info)
{
    if (info->hdr->e_phoff == 0) {
        LOG_ERR("\"%s\" has no program header table", info->name);
        return false;
    }

    if (info->hdr->e_phnum < 1 || info->hdr->e_phnum > (65536U / sizeof(ElfW(Phdr)))) {
        LOG_ERR("\"%s\" has invalid e_phnum: %d", info->name, info->hdr->e_phnum);
        return false;
    }

    if (info->hdr->e_phentsize != sizeof(ElfW(Phdr))) {
        LOG_ERR("\"%s\" has invalid e_phentsize", info->name);
        return false;
    }

    if (info->hdr->e_phoff >= info->len 
            || (info->hdr->e_phnum * sizeof(ElfW(Phdr)) > info->len - info->hdr->e_phoff)) {
        LOG_ERR("\"%s\" has invalid offset/size of program header table", info->name);
        return false;
    }

    info->phdr_table = (ElfW(Phdr) *)((char *)info->hdr + info->hdr->e_phoff);
    LOG_DEBUG("\"%s\" read program header done.", info->name);
    return true;
}

//
// symbol
//
static bool is_symbol_global_and_defined(const struct elf_module *m, const ElfW(Sym) *s)
{
    if (ELFW(ST_BIND)(s->st_info) == STB_GLOBAL || ELFW(ST_BIND)(s->st_info) == STB_WEAK)
        return s->st_shndx != SHN_UNDEF;
    return false;
}

static uint32_t elfhash(const char *name)
{
    const uint8_t *name_bytes = (const uint8_t *)name;
    uint32_t h = 0, g;
  
    while (*name_bytes) {
        h = (h << 4) + *name_bytes++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
  
    return h;
}

static ElfW(Sym) *elfhash_lookup(struct elf_module *m, const char *name)
{
    uint32_t n;
    uint32_t hash = elfhash(name);
    ElfW(Sym) *symtab = m->symtab;
    const char *strtab = m->strtab;

    LOG_DEBUG("SEARCH %s in %s@0x%zx %08x %zu", name, m->name, m->base, hash, hash % m->nbucket);

    for (n = m->bucket[hash % m->nbucket]; n != 0; n = m->chain[n]) {
        ElfW(Sym) *s = symtab + n;
        if (strcmp(strtab + s->st_name, name))
            continue;

        if (is_symbol_global_and_defined(m, s)) {
            LOG_DEBUG("FOUND %s in %s (%zx) %zu", name, m->name, s->st_value, s->st_size);
            return s;
        }
    }

    return NULL;
}

// https://blogs.oracle.com/ali/entry/gnu_hash_elf_sections
static uint32_t gnuhash(const char *name)
{
    const uint8_t *name_bytes = (const uint8_t *)name;
    uint32_t h = 5381;

    while (*name_bytes != 0)
        h += (h << 5) + *name_bytes++; // h*33 + c = h + h * 32 + c = h + h << 5 + c

    return h;
}

static ElfW(Sym) *gnuhash_lookup(struct elf_module *m, const char *name)
{
    uint32_t n;
    uint32_t hash = gnuhash(name);
    uint32_t h2 = hash >> m->gnu_shift2;
    uint32_t bloom_mask_bits = sizeof(ElfW(Addr)) * 8;
    uint32_t word_num = (hash / bloom_mask_bits) & m->gnu_maskwords;
    ElfW(Addr) bloom_word = m->gnu_bloom_filter[word_num];
    ElfW(Sym) *symtab = m->symtab;
    const char *strtab = m->strtab;

    LOG_DEBUG("SEARCH %s in %s@%p (gnu)", name, m->name, (void *)m->base);

    // test against bloom filter
    if ((1 & (bloom_word >> (hash % bloom_mask_bits)) & (bloom_word >> (h2 % bloom_mask_bits))) == 0) {
        LOG_DEBUG("NOT FOUND %s in %s@%p (gnu)", name, m->name, (void *)m->base);
        return NULL;
    }

    // bloom test says "probably yes"...
    n = m->gnu_bucket[hash % m->gnu_nbucket];
    if (n == 0) {
        LOG_DEBUG("NOT FOUND %s in %s@%p (gun)", name, m->name, (void *)m->base);
        return NULL;
    }

    do {
        ElfW(Sym) *s = symtab + n;
        if (((m->gnu_chain[n] ^ hash) >> 1) != 0)
            continue;
        if (strcmp(strtab + s->st_name, name))
            continue;

        if (is_symbol_global_and_defined(m, s)) {
            LOG_DEBUG("FOUND %s in %s (%p) %zd", name, m->name, (void *)s->st_value, (size_t)s->st_size);
            return s;
        }
    } while ((m->gnu_chain[n++] & 1) == 0);

    return NULL;
}

ElfW(Sym) *lookup_symbol_in_module(struct elf_module *m, const char *name)
{
    return (m->flags & FLAG_GNU_HASH) ? gnuhash_lookup(m, name) : elfhash_lookup(m, name);
}

ElfW(Sym) *lookup_symbol_in_needed(struct elf_module *m, const char *name, 
                                   struct elf_module **m_from, struct elf_module *needed[])
{
    int i;
    ElfW(Sym) *s = NULL;

    // 1. look for local first
    s = lookup_symbol_in_module(m, name);
    if (s) {
        *m_from = m;
        goto done;
    }

    // 2. TODO: look for it in the preloads

    // 3. look for needed module
    for (i = 0; needed[i] != NULL; i++) {
        LOG_DEBUG("%s: looking up %s in %s", m->name, name, needed[i]->name);
        s = lookup_symbol_in_module(needed[i], name);
        if (s != NULL) {
            *m_from = needed[i];
            goto done;
        }
    }

done:
    if (s != NULL) {
        LOG_DEBUG("elf module %s sym %s s->st_value = 0x%zx, "
                  "found in %s, base = 0x%zx, load_bias = 0x%zx",
                   m->name, name, s->st_value,
                   (*m_from)->name, (*m_from)->base, (*m_from)->load_bias);
        return s;
    }

    return NULL;
}

//
// relocate
//

#if defined(__x86_64__)

static bool apply_relocate_add(struct elf_module *m, Elf64_Rela *rela, size_t count, struct elf_module *needed[])
{
    Elf64_Sym *symtab = m->symtab;
    const char *strtab = m->strtab;
    size_t i;
    struct elf_module *m_from;

    for (i = 0; i < count; ++i, ++rela) {
        uint32_t type = ELF64_R_TYPE(rela->r_info);
        uint32_t sym = ELF64_R_SYM(rela->r_info);
        Elf64_Addr reloc = (Elf64_Addr)(rela->r_offset + m->load_bias);
        Elf64_Addr sym_addr = 0;
        char *sym_name = NULL;
        Elf64_Addr addend = rela->r_addend;

        LOG_DEBUG("Processing '%s' relocation at index %zu", m->name, i);
        if (type == 0) /* R_*_NONE */
            continue;

        if (sym != 0) {
            Elf64_Sym *s;
            sym_name = (char *)(strtab + symtab[sym].st_name);
            s = lookup_symbol_in_needed(m, sym_name, &m_from, needed);
            if (s == NULL) {
                sym_addr = (Elf64_Addr)dlsym((void *)0 /*RTLD_DEFAULT*/, sym_name);
                if (sym_addr) {
                    LOG_DEBUG("dlsym(%s) = 0x%zx", sym_name, sym_addr);
                } else {
                    /* We only allow an undefined symbol if this is a weak reference.. */
                    s = &symtab[sym];
                    if (ELF64_ST_BIND(s->st_info) != STB_WEAK) {
                        LOG_ERR("cannot locate symbol \"%s\" referenced by \"%s\"...", sym_name, m->name);
                        return false;
                    }

                    switch (type) {
                    case R_X86_64_JUMP_SLOT:
                    case R_X86_64_GLOB_DAT:
                    case R_X86_64_RELATIVE:
                    case R_X86_64_IRELATIVE:
                    case R_X86_64_32:
                    case R_X86_64_64:
                        break;
                    case R_X86_64_PC32:
                        sym_addr = reloc;
                        break;
                    default:
                        LOG_ERR("unknown weak reloc type %d @ %p (%zu)", type, rela, i);
                        return false;
                    }
                }
            } else { /* s != NULL*/
                sym_addr = (Elf64_Addr)(s->st_value + m_from->load_bias);
            }
        }

        switch (type) {
        case R_X86_64_NONE:
            break;
        case R_X86_64_RELATIVE:
            LOG_DEBUG("RELO RELATIVE %16p <- %16p", 
                      (void *)reloc, (void *)(m->load_bias + addend));
            *(uint64_t *)reloc = (m->load_bias + addend);
            break;
        case R_X86_64_JUMP_SLOT:
            LOG_DEBUG("RELO JMP_SLOT %16p <- %16p %s", 
                      (void *)reloc, (void *)(sym_addr), sym_name);
            *(uint64_t *)reloc = sym_addr;
            break;
        case R_X86_64_GLOB_DAT:
            LOG_DEBUG("RELO GLOB_DAT %16p <- %16p %s", 
                      (void *)reloc, (void *)(sym_addr), sym_name);
            *(uint64_t *)reloc = sym_addr;
            break;
        case R_X86_64_COPY:
            LOG_DEBUG("RELO R_X86_64_COPY %16p <- %16p %s", 
                      (void *)reloc, (void *)(sym_addr), sym_name);
            *(uint64_t *)reloc = sym_addr;
            break;
        case R_X86_64_64:
            LOG_DEBUG("RELO R_X86_64_64 %08zx <- +%08zx %s", 
                      (size_t)reloc, (size_t)(sym_addr + addend), sym_name);
            *(uint64_t *)reloc = sym_addr + addend;
            break;
        case R_X86_64_32:
            LOG_DEBUG("RELO R_X86_64_32 %08zx <- +%08zx %s", 
                      (size_t)reloc, (size_t)(sym_addr + addend), sym_name);
            *(uint32_t *)reloc = sym_addr + addend;
            break;
        case R_X86_64_32S:
            LOG_DEBUG("RELO R_X86_64_32S %08zx <- +%08zx %s", 
                      (size_t)reloc, (size_t)(sym_addr + addend), sym_name);
            *(int32_t *)reloc = sym_addr + addend;
            break;
        case R_X86_64_PC32:
            LOG_DEBUG("RELO R_X86_64_PC32 %08zx <- +%08zx (%08zx - %08zx) %s", 
                      (size_t)reloc, (size_t)(sym_addr - reloc), 
                      (size_t)sym_addr, (size_t)reloc, sym_name);
            *(uint32_t *)reloc = sym_addr + addend - reloc;
            break;
        default:
            LOG_ERR("unknown reloc type %d @ %p (%zu)", type, rela, i);
            return false;
        }
    }
    return true;
}

#else /* __x86_32 */

static bool apply_relocate(struct elf_module *m, Elf32_Rel *rel, size_t count, struct elf_module *needed[])
{
    Elf32_Sym *symtab = m->symtab;
    const char *strtab = m->strtab;
    size_t i;
    struct elf_module *m_from;

    for (i = 0; i < count; ++i, ++rel) {
        unsigned type = ELF32_R_TYPE(rel->r_info);
        unsigned sym = ELF32_R_SYM(rel->r_info);
        Elf32_Addr reloc = (Elf32_Addr)(rel->r_offset + m->load_bias);
        Elf32_Addr sym_addr = 0;
        char *sym_name = NULL;

        LOG_DEBUG("Processing '%s' relocation at index %d", m->name, i);

        if (type == 0) /* R_*_NONE */
            continue;

        if (sym != 0) {
            Elf32_Sym *s;
            sym_name = (char *)(strtab + symtab[sym].st_name);
            s = lookup_symbol_in_needed(m, sym_name, &m_from, needed);
            if (s == NULL) {
                sym_addr = (Elf32_Addr)dlsym((void *)0 /*RTLD_DEFAULT*/, sym_name);
                if (sym_addr) {
                    LOG_DEBUG("dlsym(%s) = 0x%x", sym_name, sym_addr);
                } else {
                    /* We only allow an undefined symbol if this is a weak reference.. */
                    s = &symtab[sym];
                    if (ELF32_ST_BIND(s->st_info) != STB_WEAK) {
                        LOG_ERR("cannot locate symbol \"%s\" referenced by \"%s\"...", sym_name, m->name);
                        return false;
                    }
                    switch (type) {
                    case R_386_JMP_SLOT:
                    case R_386_GLOB_DAT:
                    case R_386_RELATIVE:
                    case R_386_IRELATIVE:
                    case R_386_32:
                        break;
                    case R_386_PC32:
                        sym_addr = reloc;
                        break;
                    default:
                        LOG_ERR("unknown weak reloc type %d @ %p (%zu)", type, rel, i);
                        return false; 
                    }
                }
            } else { /* s != NULL*/
                sym_addr = (Elf32_Addr)(s->st_value + m_from->load_bias);
            }
        }

        switch (type) {
        case R_386_JMP_SLOT:
            LOG_DEBUG("RELO JMP_SLOT %p <- %p %s\n", 
                      (void *)reloc, (void *)(sym_addr), sym_name);
            *(uint32_t *)reloc = sym_addr;
            break;
        case R_386_GLOB_DAT:
            LOG_DEBUG("RELO GLOB_DAT %p <- %p %s\n", 
                      (void *)reloc, (void *)(sym_addr), sym_name);
            *(uint32_t *)reloc = sym_addr;
            break;
        case R_386_RELATIVE:
            LOG_DEBUG("RELO RELATIVE %p <- %p\n", 
                      (void *)reloc, (void *)(m->load_bias));
            *(uint32_t *)reloc = m->load_bias + *(uint32_t *)reloc;
            break;
        case R_386_32:
            LOG_DEBUG("RELO R_386_32 %08x <- +%08x %s", reloc, sym_addr, sym_name);
            *(uint32_t *)reloc += sym_addr;
            break;
        case R_386_PC32:
            LOG_DEBUG("RELO R_386_PC32 %08x <- +%08x (%08x - %08x) %s",
                      reloc, (sym_addr - reloc), sym_addr, reloc, sym_name);
            *(uint32_t *)reloc += (sym_addr - reloc);
            break;
        default:
            LOG_ERR("unknown reloc type %d @ %p (%u)", type, rel, i);
            return false;
        }
    }
    return true;
}

#endif /* defined(__x86_64__) */

/* Returns the size of the extent of all the possibly non-contiguous
 * loadable segments in an ELF program header table. This corresponds
 * to the page-aligned size in bytes that needs to be reserved in the
 * process' address space. If there are no loadable segments, 0 is
 * returned.
 *
 * If out_min_vaddr or out_max_vaddr are not null, they will be
 * set to the minimum and maximum addresses of pages to be reserved,
 * or 0 if there is nothing to load.
 */
static size_t phdr_table_get_load_size(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                ElfW(Addr)* out_min_vaddr, ElfW(Addr)* out_max_vaddr)
{
    ElfW(Addr) min_vaddr = UINTPTR_MAX;
    ElfW(Addr) max_vaddr = 0;
    bool found_pt_load = false;
    size_t i;

    for (i = 0; i < phdr_count; ++i) {
        const ElfW(Phdr)* phdr = &phdr_table[i];

        if (phdr->p_type != PT_LOAD)
            continue;

        found_pt_load = true;

        if (phdr->p_vaddr < min_vaddr)
            min_vaddr = phdr->p_vaddr;

        if (phdr->p_vaddr + phdr->p_memsz > max_vaddr)
            max_vaddr = phdr->p_vaddr + phdr->p_memsz;
    }
    if (!found_pt_load)
        min_vaddr = 0;

    min_vaddr = PAGE_START(min_vaddr);
    max_vaddr = PAGE_END(max_vaddr);

    if (out_min_vaddr != NULL)
        *out_min_vaddr = min_vaddr;
    if (out_max_vaddr != NULL)
        *out_max_vaddr = max_vaddr;
    return max_vaddr - min_vaddr;
}

/* Return the address and size of the ELF file's .dynamic section in memory,
 * or null if missing.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 * Output:
 *   dynamic       -> address of table in memory (null on failure).
 *   dynamic_flags -> protection flags for section (unset on failure)
 * Return:
 *   void
 */
static void phdr_table_get_dynamic_section(const ElfW(Phdr) *phdr_table, size_t phdr_count,
                                           ElfW(Addr) load_bias, ElfW(Dyn) **dynamic,
                                           ElfW(Word) *dynamic_flags)
{
    size_t i;

    *dynamic = NULL;
    for (i = 0; i < phdr_count; ++i) {
        const ElfW(Phdr) *phdr = &phdr_table[i];
        if (phdr->p_type == PT_DYNAMIC) {
            *dynamic = (ElfW(Dyn) *)(load_bias + phdr->p_vaddr);
            if (dynamic_flags)
                *dynamic_flags = phdr->p_flags;
            return;
        }
    }
}

static ElfW(Phdr) *find_loaded_phdr(struct elf_module *m, struct elf_info *info)
{
    size_t i;
    ElfW(Addr) loaded_phdr = 0;
    const ElfW(Phdr) *pphdr;

    // If there is a PT_PHDR, use it directly.
    for (i = 0, pphdr = info->phdr_table; i < info->hdr->e_phnum; ++i, ++pphdr) {
        if (pphdr->p_type == PT_PHDR) {
            loaded_phdr = (ElfW(Addr))(m->load_bias + pphdr->p_vaddr);
            break;
        }
    }

    // Otherwise, check the first loadable segment. If its file offset
    // is 0, it starts with the ELF header, and we can trivially find the
    // loaded program header from it.
    if (loaded_phdr == 0) {
        for (i = 0, pphdr = info->phdr_table; i < info->hdr->e_phnum; ++i, ++pphdr) {
            if (pphdr->p_type == PT_LOAD) {
                if (pphdr->p_offset == 0) {
                    const ElfW(Ehdr) *ehdr = (const ElfW(Ehdr) *)(m->load_bias + pphdr->p_vaddr);
                    loaded_phdr = (ElfW(Addr))((char *)ehdr + ehdr->e_phoff);
                    break;
                }
                break;
            }
        }
    }

    if (loaded_phdr == 0) {
         LOG_ERR("can't find loaded phdr for \"%s\"", m->name);
         return false;
    }

    // Ensures that our program header is actually within a loadable
    // segment. This should help catch badly-formed ELF files that
    // would cause the linker to crash later when trying to access it.
    for (i = 0, pphdr = info->phdr_table; i < info->hdr->e_phnum; ++i, ++pphdr) {
        ElfW(Addr) seg_start, seg_end;

        if (pphdr->p_type != PT_LOAD)
            continue;
        seg_start = m->load_bias + pphdr->p_vaddr;
        seg_end = seg_start + pphdr->p_filesz;
        if (seg_start <= loaded_phdr 
                && (loaded_phdr + info->hdr->e_phnum * sizeof(ElfW(Phdr)) <= seg_end)) {
            LOG_DEBUG("find loaded phdr for \"%s\" done", m->name);
            return (ElfW(Phdr) *)loaded_phdr;
        }
    }

    LOG_ERR("\"%s\" loaded phdr 0x%zx not in loadable segment", m->name, loaded_phdr);
    return NULL;
}

static bool layout_segments(struct elf_module *m, struct elf_info *info)
{
    ElfW(Addr) min_vaddr;
    void *mm_start;
    size_t i;

    m->size = phdr_table_get_load_size(info->phdr_table, info->hdr->e_phnum, &min_vaddr, NULL);
    if (m->size == 0) {
        LOG_ERR("\"%s\" has no loadable segments", m->name);
        return false;
    }

    mm_start = mmap(NULL,
                    m->size,
                    PROT_READ | PROT_WRITE | PROT_EXEC, 
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0); // munmap in elf_module_free()
    if (mm_start == MAP_FAILED) {
        LOG_ERR("couldn't map \"%s\" address space, %s", m->name, strerror(errno));
        return false;
    }

    memset(mm_start, 0, m->size);
    m->base = (ElfW(Addr))mm_start;
    m->load_bias = (char *)mm_start - (char *)min_vaddr;

    for (i = 0; i < info->hdr->e_phnum; ++i) {
        const ElfW(Phdr) *phdr = &info->phdr_table[i];
        if (phdr->p_type != PT_LOAD)
            continue;
        if (phdr->p_offset + phdr->p_filesz > info->len) {
            LOG_ERR("\"%s\" has invalid segment[%zu]:"
                    "p_offset (%zx) + p_filesz (%zx) past end of %zx)",
                    m->name, i, phdr->p_offset, phdr->p_filesz, info->len);
            return false;
        }
        memcpy((char *)m->load_bias + phdr->p_vaddr, 
               (char *)info->hdr + phdr->p_offset, phdr->p_filesz);
    }

    return true;
}

static bool load_dynamic(struct elf_module *m)
{
    ElfW(Dyn) *d;

    m->needed_count = 0;
    for (d = m->dynamic; d->d_tag != DT_NULL; ++d) {
        LOG_DEBUG("d = %p, d[0](tag) = 0x%p d[1](val) = 0x%p", 
                  d, (void *)d->d_tag, (void *)d->d_un.d_val);
        
        switch (d->d_tag) {
        case DT_HASH:
            m->nbucket = ((uint32_t *)(m->load_bias + d->d_un.d_ptr))[0];
            m->nchain = ((uint32_t *)(m->load_bias + d->d_un.d_ptr))[1];
            m->bucket = (uint32_t *)(m->load_bias + d->d_un.d_ptr + 8);
            m->chain = (uint32_t *)(m->load_bias + d->d_un.d_ptr + 8 + m->nbucket *4);
            break;
        case DT_GNU_HASH:
            m->gnu_nbucket = ((uint32_t *)(m->load_bias + d->d_un.d_ptr))[0];
            // skip symndx
            m->gnu_maskwords = ((uint32_t *)(m->load_bias + d->d_un.d_ptr))[2];
            m->gnu_shift2 = ((uint32_t *)(m->load_bias + d->d_un.d_ptr))[3];

            m->gnu_bloom_filter = (ElfW(Addr) *)(m->load_bias + d->d_un.d_ptr + 16);
            m->gnu_bucket = (uint32_t *)(m->gnu_bloom_filter + m->gnu_maskwords);
            // amend chain for symndx = header[1]
            m->gnu_chain = m->gnu_bucket + m->gnu_nbucket -
                ((uint32_t *)(m->load_bias + d->d_un.d_ptr))[1];

            if (!powerof2(m->gnu_maskwords)) {
                LOG_ERR("invalid maskwords for gnu_hash = 0x%x, in \"%s\" expecting power to two",
                        m->gnu_maskwords, m->name);
                return false;
            }
            m->gnu_maskwords--;
            m->flags |= FLAG_GNU_HASH;
            break;
        case DT_STRTAB:
            m->strtab = (char *)(m->load_bias + d->d_un.d_ptr);
            break; 
        case DT_STRSZ:
            m->strtab_size = d->d_un.d_val;
            break; 
        case DT_SYMTAB:
            m->symtab = (ElfW(Sym) *)(m->load_bias + d->d_un.d_ptr);
            break; 
        case DT_SYMENT:
            if (d->d_un.d_val != sizeof(ElfW(Sym))) {
                LOG_ERR("invalid DT_SYMENT: %zu in \"%s\"", (size_t)d->d_un.d_val, m->name);
                return false;
            }
            break;
#if defined(__x86_64__)
        case DT_PLTREL:
            if (d->d_un.d_val != DT_RELA) {
                LOG_ERR("unsupported DT_PLTREL in \"%s\"; expected DT_RELA", m->name);
                return false;
            }
            break;
        case DT_JMPREL:
            m->plt_rela = (ElfW(Rela) *)(m->load_bias + d->d_un.d_ptr);
            break;
        case DT_PLTRELSZ:
            m->plt_rela_count = d->d_un.d_val / sizeof(ElfW(Rela));
            break;
        case DT_RELA:
            m->rela = (ElfW(Rela) *)(m->load_bias + d->d_un.d_ptr);
            break;
        case DT_RELASZ:
            m->rela_count = d->d_un.d_val /sizeof(ElfW(Rela));
            break;
        case DT_RELAENT:
            if (d->d_un.d_val != sizeof(ElfW(Rela))) {
                LOG_ERR("invalid DT_RELAENT: %zu", (size_t)d->d_un.d_val);
                return false;
            }
            break;
        case DT_REL:
            LOG_ERR("unsupported DT_REL in \"%s\"", m->name);
            return false;
        case DT_RELSZ:
            LOG_ERR("unsupported DT_RELSZ in \"%s\"", m->name);
            return false;
#else
        case DT_PLTREL:
            if (d->d_un.d_val != DT_REL) {
                LOG_ERR("unsupported DT_PLTREL in \"%s\"; expected DT_REL", m->name);
                return false;
            }
            break;
        case DT_JMPREL:
            m->plt_rel = (ElfW(Rel) *)(m->load_bias + d->d_un.d_ptr);
            break;
        case DT_PLTRELSZ:
            m->plt_rel_count = d->d_un.d_val / sizeof(ElfW(Rel));
            break;
        case DT_REL:
            m->rel = (ElfW(Rel) *)(m->load_bias + d->d_un.d_ptr);
            break;
        case DT_RELSZ:
            m->rel_count = d->d_un.d_val / sizeof(ElfW(Rel));
            break;
        case DT_RELENT:
            if (d->d_un.d_val != sizeof(ElfW(Rel))) {
                LOG_ERR("invalid DT_RELENT: %zu", (size_t)d->d_un.d_val);
                return false;
            }
            break;
        case DT_RELA:
            LOG_ERR("unsupported DT_RELA in \"%s\"", m->name);
            return false;
        case DT_RELASZ:
            LOG_ERR("unsupported DT_RELASZ in \"%s\"", m->name);
            return false;
#endif
        case DT_NEEDED:
            m->needed_count++;
            break; 
        default:
            LOG_DEBUG("\"%s\" unused DT entry: type %p arg %p",
                      m->name, (void *)d->d_tag, (void *)d->d_un.d_val);
            break; 
        };
    }

    LOG_DEBUG("mod->base = %zx, mod->strtab = %p, mod->symtab = %p",
              m->base, m->strtab, m->symtab);

    // Sanity checks.
    if (m->nbucket == 0 && m->gnu_nbucket == 0) {
        LOG_ERR("empty/missing DT_HASH/DT_GNU_HASH in \"%s\" "
                "(new hash type from the future?)", m->name);
        return false;
    }
    if (m->strtab == 0) {
        LOG_ERR("empty/missing DT_STRTAB in \"%s\"", m->name);
        return false;
    }
    if (m->symtab == 0) {
        LOG_ERR("empty/missing DT_SYMTAB in \"%s\"", m->name);
        return false;
    }
        
    return true;
}

static bool elf_link(struct elf_module *m)
{
    bool ret = false;
    ElfW(Dyn) *d;
    struct elf_module **needed;
    struct elf_module **pneeded;

    LOG_DEBUG("[ linking %s ]", m->name);
    LOG_DEBUG("mod->base = %zx mod->flags = 0x%08x", m->base, m->flags);

    /* load needed module */
    pneeded = needed = (struct elf_module **)malloc((1 + m->needed_count) * sizeof(struct elf_module *));
    if (needed == NULL) {
        LOG_ERR("\"%s\"malloc for needed array failed", m->name);
        return false;
    }

    for (d = m->dynamic; d->d_tag != DT_NULL; ++d) {
        if (d->d_tag == DT_NEEDED) {
            struct elf_module *need_mod;
            const char *need_name = m->strtab + d->d_un.d_val;
            LOG_DEBUG("%s needs %s", m->name, need_name);
            need_mod = find_module(need_name);
            if (need_mod != NULL) {
                need_mod->refcnt++;
                *pneeded++ = need_mod;
                continue;
            }
            LOG_DEBUG("load module %s use dlopen()", m->name);
            if (dlopen(need_name, RTLD_NOW | RTLD_GLOBAL) == NULL) {
                LOG_ERR("could not load module \"%s\" needed by \"%s\"", need_name, m->name);
                return false;
            }
        }
    }
    *pneeded = NULL;

#if defined(__x86_64__)
    if (m->rela != NULL) {
        LOG_DEBUG("[ relocating %s ]", m->name);
        if (!apply_relocate_add(m, m->rela, m->rela_count, needed))
            goto out;
    }

    if (m->plt_rela != NULL) {
        LOG_DEBUG("[ relocating %s plt ]", m->name);
        if (!apply_relocate_add(m, m->plt_rela, m->plt_rela_count, needed))
            goto out;
    }
#else
    if (m->rel != NULL) {
        LOG_DEBUG("[ relocating %s ]", m->name);
        if (!apply_relocate(m, m->rel, m->rel_count, needed))
            goto out;
    }

    if (m->plt_rel != NULL) {
        LOG_DEBUG("[ relocating %s plt ]", m->name );
        if (!apply_relocate(m, m->plt_rel, m->plt_rel_count, needed))
            goto out;
    }
#endif

    m->flags |= FLAG_LINKED;
    ret = true;
out:
    free(needed);
    LOG_DEBUG("[ finished linking %s, ret=%d ]", m->name, ret);
    return ret;
}

struct elf_module *load_elf_module(const char *name, const void *elf_data, size_t elf_len)
{
    struct elf_info info = { .name = name, .hdr = elf_data, .len = elf_len };
    struct elf_module *m;

    LOG_DEBUG("load_elf_module: name=%s, bin=%p, len=%zu", name, elf_data, elf_len);

    if (find_module(name)) {
        LOG_ERR("\"%s\" already exist", name);
        return NULL;
    }

    if (!verify_elf_header(&info) || !read_program_headers(&info))
        return NULL;

    m = elf_module_alloc(name);
    if (m == NULL)
        return NULL;
    
    if (!layout_segments(m, &info))
        goto out_free;

    m->phdr = find_loaded_phdr(m, &info);
    if (m->phdr == NULL)
        goto out_free;
    m->phnum = info.hdr->e_phnum;
    m->entry = m->load_bias + info.hdr->e_entry;

    phdr_table_get_dynamic_section(m->phdr, m->phnum, m->load_bias, &m->dynamic, NULL);
    if (m->dynamic) {
        if (!load_dynamic(m))
            goto out_free;

        if (!elf_link(m))
            goto out_free;
    }

    list_add_tail(&m->list, &mod_list);
    
    LOG_DEBUG("[ \"%s\" load done, base=0x%zx sz=0x%zx entry=0x%zx ]", 
              m->name, m->base, m->size, m->entry);
    return m;

out_free:
    elf_module_free(m);
    return NULL;
}

void unload_elf_module(const char *name)
{
    struct elf_module *m;
    ElfW(Dyn) *d;
    
    m = find_module(name);
    if (m == NULL)
        return;
    
    if (m->refcnt == 1) {
        LOG_DEBUG("unloading \"%s\"", m->name);

        list_del(&m->list);

        for (d = m->dynamic; d->d_tag != DT_NULL; ++d) {
            if (d->d_tag == DT_NEEDED) {
                const char *need_name = m->strtab + d->d_un.d_val;
                LOG_DEBUG("%s needs to unload %s", m->name, need_name);
                unload_elf_module(need_name);
            }
        }

        elf_module_free(m);
    } else {
        m->refcnt--;
        LOG_DEBUG("not unloading \"%s\", decrementing refcnt to %zu", m->name, m->refcnt);
    }
}

typedef int (*main_func_t)(void);

int run_elf_module(struct elf_module *m, const char *func)
{
    ElfW(Sym *) s = lookup_symbol_in_module(m, func);
    main_func_t fn;

    if (!s) {
        LOG_ERR("not found function %s", func);
        return -1;
    }

    fn = (void *)(m->load_bias + s->st_value);

    return fn();
}
