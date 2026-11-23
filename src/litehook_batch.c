#include "litehook.h"
#include "litehook_internal.h"
#include <mach/mach_vm.h>
#include <ptrauth.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern kern_return_t litehook_hook_memory_default(void *, void *, size_t);
static pthread_mutex_t patchLock = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local unsigned patchLockDepth;
static _Thread_local bool committing;

void _litehook_patch_lock(void)
{
    if (patchLockDepth++ == 0) pthread_mutex_lock(&patchLock);
}

void _litehook_patch_unlock(void)
{
    if (--patchLockDepth == 0) pthread_mutex_unlock(&patchLock);
}

struct function_patch {
    uintptr_t address;
    uint32_t instructions[5];
};

struct patch_range {
    uintptr_t start, end;
    void *bytes;
};

static int compare_ranges(const void *a, const void *b)
{
    const struct patch_range *left = a, *right = b;
    return (left->start > right->start) - (left->start < right->start);
}

kern_return_t litehook_batch_hook_function(const struct litehook_function_hook *hooks, size_t count)
{
    if (!count) return KERN_SUCCESS;
    if (!hooks || count > SIZE_MAX / sizeof(struct function_patch) || count > SIZE_MAX / sizeof(struct patch_range))
        return KERN_INVALID_ARGUMENT;
    if (committing) return KERN_FAILURE;
    size_t page = vm_page_size;
    if (!page || (page & (page - 1))) return KERN_INVALID_ARGUMENT;
    struct function_patch *patches = calloc(count, sizeof(*patches));
    struct patch_range *ranges = calloc(count, sizeof(*ranges));
    if (!patches || !ranges) { free(patches); free(ranges); return KERN_RESOURCE_SHORTAGE; }
    kern_return_t kr = KERN_INVALID_ARGUMENT;
    size_t rangeCount = 0;
    bool locked = false;
    for (size_t i = 0; i < count; i++) {
        uintptr_t address = (uintptr_t)ptrauth_strip(hooks[i].original, ptrauth_key_function_pointer);
        uintptr_t replacement = (uintptr_t)ptrauth_strip(hooks[i].replacement, ptrauth_key_function_pointer);
        size_t size = sizeof(patches[i].instructions);
        if (!address || !replacement || (address & 3) || address > UINTPTR_MAX - size) goto out;
        uintptr_t end = address + size;
        if (end > UINTPTR_MAX - (page - 1)) goto out;
        patches[i].address = address;
        // movk x16, imm16, lsl #0/#16/#32/#48; br x16
        for (unsigned j = 0; j < 4; j++) {
            patches[i].instructions[j] = 0xf2800000 | (j << 21)
                | (((replacement >> (j * 16)) & 0xffff) << 5) | 16;
        }
        patches[i].instructions[4] = 0xd61f0200;
        ranges[i].start = address & ~(uintptr_t)(page - 1);
        ranges[i].end = (end + page - 1) & ~(uintptr_t)(page - 1);
    }

    committing = true;
    _litehook_patch_lock();
    locked = true;
    kern_return_t (*backend)(void *, void *, size_t) = litehook_hook_memory;
    if (!backend) { kr = KERN_FAILURE; goto out; }
    // Alternate backends (notably hookd) have their own size/protocol limits.
    // Preserve their original short writes rather than sending whole VM pages.
    if (backend != litehook_hook_memory_default && backend != litehook_hook_memory_image) {
        kr = KERN_SUCCESS;
        for (size_t i = 0; i < count; i++) {
            kr = backend((void *)patches[i].address, patches[i].instructions, sizeof(patches[i].instructions));
            if (kr != KERN_SUCCESS) break;
        }
        goto out;
    }

    qsort(ranges, count, sizeof(*ranges), compare_ranges);
    for (size_t i = 0; i < count; i++) {
        if (rangeCount && ranges[i].start <= ranges[rangeCount - 1].end) {
            if (ranges[i].end > ranges[rangeCount - 1].end) ranges[rangeCount - 1].end = ranges[i].end;
        } else {
            ranges[rangeCount++] = ranges[i];
        }
    }
    // Prepare every snapshot before installing anything. Keep the same lock
    // through installation so immediate hooks cannot invalidate these snapshots.
    for (size_t i = 0; i < rangeCount; i++) {
        size_t size = ranges[i].end - ranges[i].start;
        ranges[i].bytes = malloc(size);
        if (!ranges[i].bytes) { kr = KERN_RESOURCE_SHORTAGE; goto out; }
        mach_vm_size_t copied = 0;
        kr = mach_vm_read_overwrite(mach_task_self(), ranges[i].start, size,
                                    (mach_vm_address_t)ranges[i].bytes, &copied);
        if (kr != KERN_SUCCESS || copied != size) {
            if (kr == KERN_SUCCESS) kr = KERN_FAILURE;
            goto out;
        }
        // Original array order is significant: the newest overlapping hook wins.
        for (size_t j = 0; j < count; j++) {
            if (patches[j].address >= ranges[i].start && patches[j].address < ranges[i].end)
                memcpy((uint8_t *)ranges[i].bytes + patches[j].address - ranges[i].start,
                       patches[j].instructions, sizeof(patches[j].instructions));
        }
    }
    for (size_t i = 0; i < rangeCount; i++) {
        kr = backend((void *)ranges[i].start, ranges[i].bytes, ranges[i].end - ranges[i].start);
        if (kr != KERN_SUCCESS) break;
    }
out:
    if (locked) { _litehook_patch_unlock(); committing = false; }
    for (size_t i = 0; i < rangeCount; i++) free(ranges[i].bytes);
    free(ranges);
    free(patches);
    return kr;
}
