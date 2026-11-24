#include "litehook.h"
#include "litehook_internal.h"
#include <CommonCrypto/CommonDigest.h>
#include <TargetConditionals.h>
#include <libkern/OSByteOrder.h>
#include <libkern/OSCacheControl.h>
#include <mach/vm_map.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uuid/uuid.h>

// Only data is constructed in writable memory. Executable pages come from dyld.
static pthread_mutex_t imageLock = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local bool installingImage;
static int (*prepareImage)(int fd);

void litehook_set_image_prepare_callback(int (*callback)(int fd))
{
    pthread_mutex_lock(&imageLock);
    prepareImage = callback;
    pthread_mutex_unlock(&imageLock);
}

struct patch_image {
    char path[PATH_MAX];
    int fd;
    void *handle;
    uuid_t uuid;
    vm_address_t payload;
    size_t length;
};

// CodeDirectory through version 0x20400, in big-endian byte order.
struct patch_cd {
    uint32_t magic, length, version, flags, hashOffset, identOffset;
    uint32_t nSpecialSlots, nCodeSlots, codeLimit;
    uint8_t hashSize, hashType, platform, pageSize;
    uint32_t spare2, scatterOffset, teamOffset, spare3;
    uint64_t codeLimit64, execSegBase, execSegLimit, execSegFlags;
} __attribute__((packed));
_Static_assert(sizeof(struct patch_cd) == 88, "CodeDirectory layout");

static bool round_size(size_t size, size_t page, size_t *out)
{
    if (size > SIZE_MAX - (page - 1)) return false;
    *out = (size + page - 1) & ~(page - 1);
    return true;
}

static kern_return_t litehook_prepare_patch_pages(void *target, void *source, size_t size,
                                                 vm_address_t *start, size_t *length, void **bytes)
{
    size_t page = vm_page_size;
    uintptr_t address = (uintptr_t)target;
    if (!target || !source || !page || (page & (page - 1)) || size > UINTPTR_MAX - address)
        return KERN_INVALID_ARGUMENT;
    *start = address & ~(uintptr_t)(page - 1);
    size_t offset = address - *start;
    if (size > SIZE_MAX - offset || !round_size(offset + size, page, length) || *length > UINTPTR_MAX - *start)
        return KERN_INVALID_ARGUMENT;
    *bytes = malloc(*length);
    if (!*bytes) return KERN_RESOURCE_SHORTAGE;
    vm_size_t copied = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), *start, *length,
                                             (vm_address_t)*bytes, &copied);
    if (kr != KERN_SUCCESS || copied != *length) {
        free(*bytes);
        *bytes = NULL;
        return kr == KERN_SUCCESS ? KERN_FAILURE : kr;
    }
    memcpy((uint8_t *)*bytes + offset, source, size);
    return KERN_SUCCESS;
}

static void add_segment(uint8_t **cursor, const char *name, uint64_t offset,
                        uint64_t size, uint64_t fileSize, vm_prot_t prot)
{
    struct segment_command_64 *seg = (void *)*cursor;
    seg->cmd = LC_SEGMENT_64;
    seg->cmdsize = sizeof(*seg);
    strlcpy(seg->segname, name, sizeof(seg->segname));
    seg->vmaddr = offset;
    seg->vmsize = size;
    seg->fileoff = offset;
    seg->filesize = fileSize;
    seg->maxprot = seg->initprot = prot;
    *cursor += sizeof(*seg);
}

static kern_return_t litehook_create_patch_image(const void *bytes, size_t length, struct patch_image *image)
{
    const size_t page = vm_page_size, hashPage = 4096;
    // Keep all file offsets, CodeDirectory sizes, and SHA-256 input lengths bounded.
    if (length > UINT32_MAX - page) return KERN_INVALID_ARGUMENT;
    size_t codeSize = page + length;
    size_t slots = (codeSize + hashPage - 1) / hashPage;
    const char identifier[] = "litehook.patch";
    size_t cdSize = sizeof(struct patch_cd) + sizeof(identifier) + slots * CC_SHA256_DIGEST_LENGTH;
    size_t sigSize = 20 + cdSize;
    size_t linkSize;
    if (sigSize > UINT32_MAX || codeSize > UINT32_MAX - sigSize || !round_size(sigSize, page, &linkSize))
        return KERN_INVALID_ARGUMENT;
    size_t fileSize = codeSize + sigSize;
    uint8_t *file = calloc(1, fileSize);
    if (!file) return KERN_RESOURCE_SHORTAGE;

    struct mach_header_64 *header = (void *)file;
    header->magic = MH_MAGIC_64;
    header->cputype = CPU_TYPE_ARM64;
#if __arm64e__
    header->cpusubtype = CPU_SUBTYPE_ARM64E | (cpu_subtype_t)0x80000000; // arm64e ABI v2
#else
    header->cpusubtype = CPU_SUBTYPE_ARM64_ALL;
#endif
    header->filetype = MH_DYLIB;
    header->flags = MH_DYLDLINK | MH_TWOLEVEL | MH_NOUNDEFS;
    header->ncmds = 10;
    uint8_t *cursor = file + sizeof(*header);
    add_segment(&cursor, "__TEXT", 0, page, page, VM_PROT_READ | VM_PROT_EXECUTE);
    add_segment(&cursor, "__LTHPATCH", page, length, length, VM_PROT_READ | VM_PROT_EXECUTE);
    add_segment(&cursor, "__LINKEDIT", codeSize, linkSize, sigSize, VM_PROT_READ);

    struct dylib_command *id = (void *)cursor;
    uuid_generate(image->uuid);
    char uuidString[37], installName[80];
    uuid_unparse_lower(image->uuid, uuidString);
    snprintf(installName, sizeof(installName), "@rpath/litehook-%s.dylib", uuidString);
    id->cmd = LC_ID_DYLIB;
    id->cmdsize = (uint32_t)((sizeof(*id) + strlen(installName) + 1 + 7) & ~7);
    id->dylib.name.offset = sizeof(*id);
    id->dylib.current_version = id->dylib.compatibility_version = 0x10000;
    memcpy(cursor + sizeof(*id), installName, strlen(installName) + 1);
    cursor += id->cmdsize;

    struct uuid_command *uuid = (void *)cursor;
    uuid->cmd = LC_UUID; uuid->cmdsize = sizeof(*uuid);
    memcpy(uuid->uuid, image->uuid, sizeof(uuid->uuid)); cursor += sizeof(*uuid);
    struct build_version_command *build = (void *)cursor;
    build->cmd = LC_BUILD_VERSION; build->cmdsize = sizeof(*build);
#if TARGET_OS_OSX
    build->platform = PLATFORM_MACOS; build->minos = build->sdk = 0x000b0000;
#else
    build->platform = PLATFORM_IOS; build->minos = build->sdk = 0x000f0000;
#endif
    cursor += sizeof(*build);
    struct dyld_info_command *dyld = (void *)cursor;
    dyld->cmd = LC_DYLD_INFO_ONLY; dyld->cmdsize = sizeof(*dyld); cursor += sizeof(*dyld);
    struct symtab_command *sym = (void *)cursor;
    sym->cmd = LC_SYMTAB; sym->cmdsize = sizeof(*sym); sym->symoff = sym->stroff = (uint32_t)codeSize;
    cursor += sizeof(*sym);
    struct dysymtab_command *dysym = (void *)cursor;
    dysym->cmd = LC_DYSYMTAB; dysym->cmdsize = sizeof(*dysym); cursor += sizeof(*dysym);
    struct linkedit_data_command *signature = (void *)cursor;
    signature->cmd = LC_CODE_SIGNATURE; signature->cmdsize = sizeof(*signature);
    signature->dataoff = (uint32_t)codeSize; signature->datasize = (uint32_t)sigSize;
    cursor += sizeof(*signature);
    header->sizeofcmds = (uint32_t)(cursor - file - sizeof(*header));
    if ((size_t)(cursor - file) > page) { free(file); return KERN_INVALID_ARGUMENT; }
    memcpy(file + page, bytes, length);

    uint32_t *super = (void *)(file + codeSize);
    super[0] = OSSwapHostToBigInt32(0xfade0cc0);
    super[1] = OSSwapHostToBigInt32((uint32_t)sigSize);
    super[2] = OSSwapHostToBigInt32(1);
    super[3] = 0; // CSSLOT_CODEDIRECTORY
    super[4] = OSSwapHostToBigInt32(20);
    struct patch_cd *cd = (void *)(super + 5);
    cd->magic = OSSwapHostToBigInt32(0xfade0c02);
    cd->length = OSSwapHostToBigInt32((uint32_t)cdSize);
    cd->version = OSSwapHostToBigInt32(0x20400);
    cd->flags = OSSwapHostToBigInt32(2); // CS_ADHOC, no TeamID (TXM normalized)
    cd->hashOffset = OSSwapHostToBigInt32(sizeof(*cd) + sizeof(identifier));
    cd->identOffset = OSSwapHostToBigInt32(sizeof(*cd));
    cd->nCodeSlots = OSSwapHostToBigInt32((uint32_t)slots);
    cd->codeLimit = OSSwapHostToBigInt32((uint32_t)codeSize);
    cd->hashSize = CC_SHA256_DIGEST_LENGTH; cd->hashType = 2; cd->pageSize = 12;
    cd->execSegBase = 0;
    cd->execSegLimit = OSSwapHostToBigInt64(codeSize);
    memcpy((uint8_t *)cd + sizeof(*cd), identifier, sizeof(identifier));
    uint8_t *hashes = (uint8_t *)cd + sizeof(*cd) + sizeof(identifier);
    for (size_t i = 0; i < slots; i++) {
        size_t n = codeSize - i * hashPage;
        if (n > hashPage) n = hashPage;
        CC_SHA256(file + i * hashPage, (CC_LONG)n, hashes + i * CC_SHA256_DIGEST_LENGTH);
    }

    const char *tmp = getenv("TMPDIR");
    if (!tmp || !*tmp) tmp = "/tmp";
    int n = snprintf(image->path, sizeof(image->path), "%s/litehook-%s-XXXXXX", tmp, uuidString);
    if (n < 0 || (size_t)n >= sizeof(image->path)) { free(file); image->path[0] = 0; return KERN_INVALID_ARGUMENT; }
    int fd = mkstemp(image->path);
    if (fd < 0) { free(file); image->path[0] = 0; return KERN_FAILURE; }
    size_t written = 0;
    while (written < fileSize) {
        ssize_t nwrite = write(fd, file + written, fileSize - written);
        if (nwrite < 0 && errno == EINTR) continue;
        if (nwrite <= 0) break;
        written += (size_t)nwrite;
    }
    free(file);
    int closeResult = close(fd);
    if (written != fileSize || closeResult != 0) return KERN_FAILURE;
    image->fd = open(image->path, O_RDONLY | O_CLOEXEC);
    return image->fd < 0 ? KERN_FAILURE : KERN_SUCCESS;
}

static kern_return_t litehook_load_patch_image(struct patch_image *image)
{
    // Explicitly attach before dlopen: __fcntl redirection may not exist yet.
    if (prepareImage(image->fd) != 0) return KERN_FAILURE;
    image->handle = dlopen(image->path, RTLD_NOW | RTLD_LOCAL);
    if (!image->handle) return KERN_FAILURE;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header_64 *h = (void *)_dyld_get_image_header(i);
        if (h->magic != MH_MAGIC_64) continue;
        const uint8_t *end = (const uint8_t *)(h + 1) + h->sizeofcmds;
        const struct segment_command_64 *payload = NULL;
        bool matches = false;
        const struct load_command *lc = (void *)(h + 1);
        for (uint32_t j = 0; j < h->ncmds; j++) {
            if ((const uint8_t *)lc + sizeof(*lc) > end || lc->cmdsize < sizeof(*lc) || lc->cmdsize > (size_t)(end - (const uint8_t *)lc)) break;
            if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command))
                matches = uuid_compare(((const struct uuid_command *)lc)->uuid, image->uuid) == 0;
            if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
                const struct segment_command_64 *seg = (void *)lc;
                if (!strncmp(seg->segname, "__LTHPATCH", 16)) payload = seg;
            }
            lc = (void *)((const uint8_t *)lc + lc->cmdsize);
        }
        if (matches && payload && payload->vmsize == image->length && payload->filesize == image->length
            && payload->initprot == (VM_PROT_READ | VM_PROT_EXECUTE)) {
            image->payload = payload->vmaddr + _dyld_get_image_vmaddr_slide(i);
            if (image->payload % vm_page_size) return KERN_INVALID_ADDRESS;
            return KERN_SUCCESS;
        }
    }
    return KERN_FAILURE;
}

static void litehook_destroy_patch_image(struct patch_image *image)
{
    if (image->handle) dlclose(image->handle);
    if (image->fd >= 0) close(image->fd);
    if (image->path[0]) unlink(image->path);
}

kern_return_t litehook_hook_memory_image(void *target, void *source, size_t sourceSize)
{
    if (!sourceSize) return KERN_SUCCESS;
    // Reject loader callback reentry instead of deadlocking on imageLock.
    if (installingImage) return KERN_FAILURE;
    installingImage = true;
    _litehook_patch_lock();
    pthread_mutex_lock(&imageLock);
    kern_return_t kr = KERN_FAILURE;
    void *bytes = NULL;
    vm_address_t start = 0;
    size_t length = 0;
    struct patch_image image = { .fd = -1 };
    if (!prepareImage) goto out;
    kr = litehook_prepare_patch_pages(target, source, sourceSize, &start, &length, &bytes);
    if (kr != KERN_SUCCESS) goto out;
    image.length = length;
    kr = litehook_create_patch_image(bytes, length, &image);
    if (kr != KERN_SUCCESS) goto out;
    kr = litehook_load_patch_image(&image);
    if (kr != KERN_SUCCESS) goto out;

    vm_prot_t current, maximum;
    vm_address_t destination = start;
    kr = vm_remap(mach_task_self(), &destination, length, 0,
                      VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, mach_task_self(), image.payload,
                      FALSE, &current, &maximum, VM_INHERIT_COPY);
    if (kr == KERN_SUCCESS) {
        sys_icache_invalidate((void *)start, length);
        if (destination != start || current != (VM_PROT_READ | VM_PROT_EXECUTE)) kr = KERN_PROTECTION_FAILURE;
    }
out:
    litehook_destroy_patch_image(&image);
    free(bytes);
    pthread_mutex_unlock(&imageLock);
    _litehook_patch_unlock();
    installingImage = false;
    return kr;
}
