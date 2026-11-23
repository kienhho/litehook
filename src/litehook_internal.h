#ifndef LITEHOOK_INTERNAL_H
#define LITEHOOK_INTERNAL_H

// Recursive per thread so batch snapshots and the image backend share one lock.
void _litehook_patch_lock(void);
void _litehook_patch_unlock(void);

#endif
