#include <assert.h>
#include <stdio.h>
#include <string.h>
#define MAX_NR 512
#define BITMAP_LONGS (MAX_NR / 64 + 1)
#define HOOK_INLINE 1
#define HOOK_FP 2
#define HOOK_NO_ERR 0
#define mb_ish() ((void)0)
typedef int hook_err_t;
typedef struct { int unused; } hook_fargs0_t;
#include "hook_table.h"
static void after_generic_ret(hook_fargs0_t *args, void *data) { (void)args; (void)data; }
static void after_clone_ret(hook_fargs0_t *args, void *data) { (void)args; (void)data; }
static void before_generic(void) {}
static int g_enabled;
static unsigned long g_nr_bitmap[BITMAP_LONGS];
static int attempts[MAX_NR], removals[MAX_NR], fail_nr = -1;
static inline void bitmap_set(volatile unsigned long *bits, int nr) { bits[nr / 64] |= 1UL << (nr % 64); }
static inline int bitmap_test(volatile unsigned long *bits, int nr) { return (bits[nr / 64] >> (nr % 64)) & 1; }
static int install(int nr, int arity, void *before, void *after, void *data) {
    hook_entry_t *entry = data;
    assert(entry >= hooks && entry < hooks + HOOK_COUNT);
    assert(entry->nr == nr && entry->narg == arity);
    assert(before == (void *)before_generic && after == entry->after);
    attempts[nr]++;
    return nr == fail_nr ? 1 : HOOK_NO_ERR;
}
#define inline_hook_syscalln install
#define fp_hook_syscalln install
static void remove_callback(int nr, void *before, void *after) {
    (void)before; (void)after; removals[nr]++;
}
#define inline_unhook_syscalln remove_callback
#define fp_unhook_syscalln remove_callback
/* Actual production installer, remover, lookup and configuration functions. */
#include "hook_config.inc"
static void reset(void) {
    for (unsigned int i = 0; i < HOOK_COUNT; i++) hooks[i].active = hooks[i].method = 0;
    memset(g_nr_bitmap, 0, sizeof(g_nr_bitmap));
    memset(attempts, 0, sizeof(attempts));
    g_enabled = 0; fail_nr = -1;
}
static int installed(void) {
    int total = 0;
    for (unsigned int i = 0; i < HOOK_COUNT; i++) total += hooks[i].active;
    return total;
}
int main(void) {
    char response[256];
    unsigned long original[BITMAP_LONGS];
    reset();
    assert(installed() == 0);
    configure_hooks("56,63,56", response, sizeof(response));
    assert(strstr(response, "\"set_nrs_count\":2"));
    assert(installed() == 2 && attempts[56] == 1 && attempts[63] == 1);
    configure_hooks("63,56", response, sizeof(response));
    assert(attempts[56] == 1 && attempts[63] == 1);
    configure_hooks("198", response, sizeof(response));
    assert(installed() == 3 && !bitmap_test(g_nr_bitmap, 56) && bitmap_test(g_nr_bitmap, 198));
    memcpy(original, g_nr_bitmap, sizeof(original));
    const char *invalid[] = {"", " ", "56,", "56,,63", "56junk", "56 63", "-1", "56,999999999999999999999999", "56,0"};
    for (unsigned int i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        configure_hooks(invalid[i], response, sizeof(response));
        assert(strstr(response, "\"ok\":false"));
        assert(installed() == 3 && memcmp(original, g_nr_bitmap, sizeof(original)) == 0);
    }
    g_enabled = 1;
    configure_hooks("65", response, sizeof(response));
    assert(strstr(response, "KPM_MONITORING_ENABLED"));
    assert(attempts[65] == 0 && memcmp(original, g_nr_bitmap, sizeof(original)) == 0);
    g_enabled = 0;
    fail_nr = 65;
    configure_hooks("57,65", response, sizeof(response));
    assert(strstr(response, "KPM_HOOK_INSTALL_FAILED") && strstr(response, "\"nr\":65"));
    assert(!g_enabled && memcmp(original, g_nr_bitmap, sizeof(original)) == 0);
    assert(find_hook(57)->active && !find_hook(65)->active);
    int old_attempts = attempts[57];
    fail_nr = -1;
    configure_hooks("57,65", response, sizeof(response));
    assert(strstr(response, "\"ok\":true") && attempts[57] == old_attempts);
    assert(bitmap_test(g_nr_bitmap, 57) && bitmap_test(g_nr_bitmap, 65));
    for (unsigned int i = 0; i < HOOK_COUNT; i++) {
        if (hooks[i].active) {
            remove_hook(&hooks[i]); remove_hook(&hooks[i]);
            assert(removals[hooks[i].nr] == 1);
        }
    }
    assert(installed() == 0);
    /* Verify udata and callbacks for every static entry, including clone. */
    reset();
    for (unsigned int i = 0; i < HOOK_COUNT; i++) assert(install_hook(&hooks[i]) == 0);
    assert(installed() == 75);
    assert(find_hook(63)->after == (void *)after_generic_ret);
    assert(find_hook(220)->after == (void *)after_clone_ret);
    assert(find_hook(435)->after == (void *)after_clone_ret);
    for (unsigned int i = 0; i < 5; i++) {
        const int paired[] = {29, 222, 35, 38, 276};
        assert(find_hook(paired[i])->after == (void *)after_generic_ret);
    }
    assert(find_hook(98)->after == 0);
    puts("lazy hook configuration checks passed");
    return 0;
}
