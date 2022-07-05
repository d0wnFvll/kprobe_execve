#include <linux/binfmts.h>

bool argv_dump_page(struct linux_binprm *bprm, unsigned long pos,
              char *dump) {
    struct page *page;

    /* dump should be released on your own. */
    if (!dump) {
        dump = kzalloc(PAGE_SIZE, GFP_NOFS);
        if (!dump) {
            return false;
        }
    }
    /* Same with get_arg_page(bprm, pos, 0) in fs/exec.c */
#ifdef CONFIG_MMU
    /*
     * This is called at execve() time in order to dig around
     * in the argv/environment of the new proceess
     * (represented by bprm).  'current' is the process doing
     * the execve().
     */
    if (get_user_pages_remote(bprm->mm, pos, 1,
                FOLL_FORCE, &page, NULL, NULL) <= 0) {
        return false;
    }
#else
    page = bprm->page[pos / PAGE_SIZE];
#endif
    const unsigned int offset = pos % PAGE_SIZE;
    /*
        * Maybe kmap()/kunmap() should be used here.
        * But remove_arg_zero() uses kmap_atomic()/kunmap_atomic().
        * So do I.
        */
    char *kaddr = kmap_atomic(page);

    memcpy(dump + offset, kaddr + offset,
            PAGE_SIZE - offset);
    kunmap_atomic(kaddr);
    /* Same with put_arg_page(page) in fs/exec.c */
#ifdef CONFIG_MMU
    put_page(page);
#endif
    return true;
}

static char *argv_print_bprm(struct linux_binprm *bprm,
                   char *dump)
{
    static const int tomoyo_buffer_len = 4096 * 2;
    char *buffer = kzalloc(tomoyo_buffer_len, GFP_NOFS);
    char *cp;
    char *last_start;
    int len;
    unsigned long pos = bprm->p;
    int offset = pos % PAGE_SIZE;
    int argv_count = bprm->argc;
    int envp_count = bprm->envc;
    bool truncated = false;

    if (!buffer) {
        return NULL;
    }
    
    len = snprintf(buffer, tomoyo_buffer_len - 1, "argv[]={ ");
    cp = buffer + len;
    if (!argv_count) {
        memmove(cp, "} envp[]={ ", 11);
        cp += 11;
    }
    last_start = cp;
    while (argv_count || envp_count) {
        if (!argv_dump_page(bprm, pos, dump)) {
            goto out;
        }
        pos += PAGE_SIZE - offset;
        /* Read. */
        while (offset < PAGE_SIZE) {
            const char *kaddr = dump;
            const unsigned char c = kaddr[offset++];

            if (cp == last_start) {
                *cp++ = '"';
            }
            if (cp >= buffer + tomoyo_buffer_len - 32) {
                /* Reserve some room for "..." string. */
                truncated = true;
            } else if (c == '\\') {
                *cp++ = '\\';
                *cp++ = '\\';
            } else if (c > ' ' && c < 127) {
                *cp++ = c;
            } else if (!c) {
                *cp++ = '"';
                *cp++ = ' ';
                last_start = cp;
            } else {
                *cp++ = '\\';
                *cp++ = (c >> 6) + '0';
                *cp++ = ((c >> 3) & 7) + '0';
                *cp++ = (c & 7) + '0';
            }
            if (c) {
                continue;
            }
            if (argv_count) {
                if (--argv_count == 0) {
                    if (truncated) {
                        cp = last_start;
                        memmove(cp, "... ", 4);
                        cp += 4;
                    }
                    memmove(cp, "} envp[]={ ", 11);
                    cp += 11;
                    last_start = cp;
                    truncated = false;
                }
            } else if (envp_count) {
                if (--envp_count == 0) {
                    if (truncated) {
                        cp = last_start;
                        memmove(cp, "... ", 4);
                        cp += 4;
                    }
                }
            }
            if (!argv_count && !envp_count) {
                break;
            }
        }
        offset = 0;
    }
    *cp++ = '}';
    *cp = '\0';
    return buffer;
out:
    snprintf(buffer, tomoyo_buffer_len - 1,
         "argv[]={ ... } envp[]= { ... }");
    return buffer;
}
