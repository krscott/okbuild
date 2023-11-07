#ifndef OKBUILD_H_
#define OKBUILD_H_

#include <assert.h>
#include <errno.h>
#include <io.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef _MSC_BUILD
#include <libgen.h>
#endif  // _MSC_BUILD

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <glob.h>
#endif

// Util macros

#define OKBAPI static inline

#define OKB_STR(x) #x
#define OKB_STR_VALUE(x) OKB_STR(x)

#define okb_countof(a) (sizeof(a) / sizeof(a[0]))

// Logging

// All modern compilers support ##__VA_ARGS__
// msvc does not handle __VA_ARGS__ correctly without ##
#ifdef __clang__
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif

#ifndef OKB_LOG_FILE
#define OKB_LOG_FILE stderr
#endif  // OKB_LOG_FILE

#ifndef OKB_LOG
#define OKB_LOG(lvl, fmt, ...) fprintf(OKB_LOG_FILE, "[" lvl "] " fmt "\n", ##__VA_ARGS__)
#endif

#define okb_debug(fmt, ...) OKB_LOG("DEBUG", fmt, ##__VA_ARGS__)
#define okb_info(fmt, ...) OKB_LOG("INFO", fmt, ##__VA_ARGS__)
#define okb_warn(fmt, ...) OKB_LOG("WARN", fmt, ##__VA_ARGS__)
#define okb_error(fmt, ...) OKB_LOG("ERROR", fmt, ##__VA_ARGS__)
#define okb_fatal(fmt, ...) OKB_LOG("FATAL", fmt, ##__VA_ARGS__)

// Error

enum okb_err {
    OKB_OK,
    OKB_PANIC,
    OKB_FILE_DOES_NOT_EXIST,
    OKB_ERRNO,
    OKB_WINDOWS,
    OKB_SUBPROC,
};

OKBAPI char* okb_err_cstr(enum okb_err err) {
    switch (err) {
        case OKB_OK:
            return "No error";
        case OKB_PANIC:
            return "okbuild okb_panic";
        case OKB_FILE_DOES_NOT_EXIST:
            return "File does not exist";
        case OKB_ERRNO:
            return strerror(errno);
        case OKB_WINDOWS:
            return "Windows error";
        case OKB_SUBPROC:
            return "Sub-process error";
        default:
            return "Unknown error";
    }
}

#define okb_trace_err(err) okb_trace_err_((err), __FILE__, __LINE__)
OKBAPI enum okb_err okb_trace_err_(enum okb_err err, char const* file, int line) {
    if (err) {
        okb_error("%s:%d %s", file, line, okb_err_cstr(err));
    }
    return err;
}

#define okb_assert_ok(err) okb_assert_ok_((err), __FILE__, __LINE__)
OKBAPI void okb_assert_ok_(enum okb_err err, char const* file, int line) {
    if (err) {
        okb_fatal("%s:%d %s", file, line, okb_err_cstr(err));
        assert(false); /* Trigger debugger */
        exit((int)err);
    }
}

#define okb_panic(fmt, ...)                                                 \
    do {                                                                    \
        fprintf(                                                            \
            OKB_LOG_FILE,                                                   \
            "Panic at " __FILE__ ":" OKB_STR_VALUE(__LINE__) ": " fmt "\n", \
            ##__VA_ARGS__                                                   \
        );                                                                  \
        assert(false); /* Trigger debugger */                               \
        exit(OKB_PANIC);                                                    \
    } while (1)

// Util functions

OKBAPI size_t okb_checked_mul(size_t a, size_t b) {
    size_t result = (size_t)(a) * (size_t)(b);
    if (a > 1 && result / a != b) okb_panic("multiply overflow");
    return result;
}

OKBAPI ptrdiff_t okb_next_power_of_2(ptrdiff_t n) {
    ptrdiff_t k = 1;
    while (k < n) k *= 2;
    return k;
}

OKBAPI bool okb_cstr_contains_char(char const* s, char c) {
    assert(s);
    while (*s) {
        if (*s == c) return true;
        ++s;
    }
    return false;
}

OKBAPI bool okb_cstr_ends_with(char const* s, char const* end) {
    assert(s);
    ptrdiff_t const s_len = strlen(s);
    ptrdiff_t const end_len = strlen(end);
    if (end_len > s_len) return false;
    return strcmp(s + s_len - end_len, end) == 0;
}

// Memory

#ifndef OKBUILD_MALLOC
#define OKBUILD_MALLOC malloc
#endif
#ifndef OKBUILD_REALLOC
#define OKBUILD_REALLOC realloc
#endif
#ifndef OKBUILD_FREE
#define OKBUILD_FREE free
#endif

OKBAPI void* okb_alloc(size_t nelem, size_t elsize) {
    void* ptr = OKBUILD_MALLOC(okb_checked_mul(nelem, elsize));
    if (!ptr) okb_panic("out of memory");
    return ptr;
}

OKBAPI void* okb_realloc(void* ptr, size_t nelem, size_t elsize) {
    void* new_ptr = OKBUILD_REALLOC(ptr, okb_checked_mul(nelem, elsize));
    if (!new_ptr) okb_panic("out of memory");
    return new_ptr;
}

OKBAPI void okb_free(void* ptr) { OKBUILD_FREE(ptr); }

// Dynamic Array macros

#define OKB_DA_RESERVE(da_struct_name, da_ptr, additional)                                    \
    do {                                                                                      \
        struct da_struct_name* da_ = (da_ptr);                                                \
        ptrdiff_t n_ = (additional);                                                          \
        assert(da_);                                                                          \
        if (n_ <= 0) break;                                                                   \
        ptrdiff_t const initial_capacity_ = 8;                                                \
        ptrdiff_t new_cap_ = da_->len + n_;                                                   \
        new_cap_ =                                                                            \
            new_cap_ > initial_capacity_ ? okb_next_power_of_2(new_cap_) : initial_capacity_; \
        if (new_cap_ <= da_->cap) break;                                                      \
        da_->buf = okb_realloc(da_->buf, new_cap_, sizeof(da_->buf[0]));                      \
        da_->cap = new_cap_;                                                                  \
    } while (0)

#define OKB_DA_EXTEND(da_struct_name, da_ptr, nelem, data)              \
    do {                                                                \
        struct da_struct_name* da_ = (da_ptr);                          \
        ptrdiff_t n_ = (nelem);                                         \
        assert(da_);                                                    \
        if (n_ <= 0) break;                                             \
        da_struct_name##_reserve(da_, n_);                              \
        memmove(&da_->buf[da_->len], (data), n_ * sizeof(da_->buf[0])); \
        da_->len += n_;                                                 \
    } while (0)

#define OKB_DA_PUSH(da_struct_name, da_ptr, elem) \
    do {                                          \
        struct da_struct_name* da_ = (da_ptr);    \
        assert(da_);                              \
        da_struct_name##_reserve(da_, 1);         \
        da_->buf[da_->len++] = (elem);            \
    } while (0)

// CString buffer

struct okb_cstring {
    // Pointer to owned cstr buffer
    char* buf;
    // Number of characters (not including null terminator)
    ptrdiff_t len;
    // Buffer capacity (including null terminator)
    ptrdiff_t cap;
};

OKBAPI struct okb_cstring okb_cstring_init(void) { return (struct okb_cstring){0}; }

OKBAPI void okb_cstring_deinit(struct okb_cstring* cs) {
    assert(cs);
    if (cs->buf) okb_free(cs->buf);
}

OKBAPI void okb_cstring_clear(struct okb_cstring* cs) {
    assert(cs);
    cs->len = 0;
}

OKBAPI void okb_cstring_reserve(struct okb_cstring* cs, ptrdiff_t additional) {
    if (additional <= 0) return;
    OKB_DA_RESERVE(okb_cstring, cs, additional + 1);  // +1 for null terminator
}

OKBAPI void okb_cstring_extend(struct okb_cstring* cs, ptrdiff_t n, char const* bytes) {
    OKB_DA_EXTEND(okb_cstring, cs, n, bytes);

    if (n > 0) {
        assert(cs->len < cs->cap);
        cs->buf[cs->len] = '\0';
    }
}

OKBAPI void okb_cstring_extend_cstr(struct okb_cstring* cs, char const* cstr) {
    assert(cs);
    assert(cstr);
    okb_cstring_extend(cs, strlen(cstr), cstr);
}

OKBAPI void okb_cstring_push(struct okb_cstring* cs, char c) {
    OKB_DA_PUSH(okb_cstring, cs, c);
    cs->buf[cs->len] = '\0';
}

OKBAPI char const* okb_cstring_as_cstr(struct okb_cstring cs) { return cs.buf; }

OKBAPI struct okb_cstring okb_cstring_init_with_cstr(char const* cstr) {
    assert(cstr);
    struct okb_cstring cs = okb_cstring_init();
    cs.len = strlen(cstr);
    if (cs.len > 0) {
        cs.cap = cs.len + 1;  // +1 for null terminator
        cs.buf = okb_alloc(cs.cap, sizeof(char*));
        strcpy(cs.buf, cstr);
    }
    return cs;
}

OKBAPI void okb_cstring_strip_file_ext(struct okb_cstring* cs) {
    assert(cs);
    ptrdiff_t len = cs->len;

    // Find len of string up to extension
    for (; len > 0; len--) {
        char c = cs->buf[len - 1];
        if (c == '\\' || c == '/') break;
        if (c == '.') {
            cs->len = len - 1;
            cs->buf[cs->len] = '\0';
            break;
        }
    }
}

OKBAPI void okb_cstring_replace_ext(struct okb_cstring* cs, char const* new_ext) {
    assert(cs);
    assert(new_ext);
    okb_cstring_strip_file_ext(cs);
    okb_cstring_push(cs, '.');
    okb_cstring_extend_cstr(cs, new_ext);
}

OKBAPI void okb_cstring_extend_cli_args(struct okb_cstring* cs, int argc, char** argv) {
    assert(cs);
    assert(argc >= 1);
    assert(argv);
    for (int i = 1; i < argc; ++i) {
        okb_cstring_extend_cstr(cs, " \"");
        okb_cstring_extend_cstr(cs, argv[i]);
        okb_cstring_push(cs, '"');
    }
}

// String list

// List of cstrings
struct okb_cslist {
    // Owned array of cstrings
    struct okb_cstring* buf;
    // Number of elements
    ptrdiff_t len;
    // Buffer capacity
    ptrdiff_t cap;
};

OKBAPI struct okb_cstring* okb_cslist_get(struct okb_cslist list, ptrdiff_t i) {
    assert(i >= 0 && i < list.len);
    return &list.buf[i];
}

OKBAPI char const* okb_cslist_get_cstr(struct okb_cslist list, ptrdiff_t i) {
    return okb_cstring_as_cstr(*okb_cslist_get(list, i));
}

OKBAPI struct okb_cslist okb_cslist_init(void) { return (struct okb_cslist){0}; }

OKBAPI struct okb_cslist okb_cslist_init_with_cstrs(ptrdiff_t n, char* cstrs[]) {
    struct okb_cslist list = {
        .buf = okb_alloc(n, sizeof(struct okb_cstring)),
        .len = n,
        .cap = n,
    };
    for (ptrdiff_t i = 0; i < n; ++i) {
        list.buf[i] = okb_cstring_init_with_cstr(cstrs[i]);
    }
    return list;
}

OKBAPI void okb_cslist_deinit(struct okb_cslist* list) {
    assert(list);
    if (list->buf) {
        for (ptrdiff_t i = 0; i < list->len; ++i) {
            okb_cstring_deinit(okb_cslist_get(*list, i));
        }
        okb_free(list->buf);
    }
}

OKBAPI void okb_cslist_reserve(struct okb_cslist* list, ptrdiff_t additional) {
    OKB_DA_RESERVE(okb_cslist, list, additional);
}

OKBAPI void okb_cslist_push(struct okb_cslist* list, struct okb_cstring cstring_owned) {
    OKB_DA_PUSH(okb_cslist, list, cstring_owned);
}

OKBAPI void okb_cslist_push_cstr(struct okb_cslist* list, char const* cstr) {
    assert(list);
    okb_cslist_push(list, okb_cstring_init_with_cstr(cstr));
}

OKBAPI void okb_cslist_extend(struct okb_cslist* list, struct okb_cslist other) {
    assert(list);
    for (ptrdiff_t i = 0; i < other.len; ++i) {
        okb_cslist_push_cstr(list, okb_cslist_get_cstr(other, i));
    }
}

OKBAPI void okb_cslist_extend_cstrs(struct okb_cslist* list, ptrdiff_t n, char const** cstrs) {
    assert(list);
    for (ptrdiff_t i = 0; i < n; ++i) {
        okb_cslist_push_cstr(list, cstrs[i]);
    }
}

// Filesystem

OKBAPI char const* okb_fs_basename(char const* path) {
    assert(path);
#ifdef _MSC_BUILD
    static char scratch[100];
    _splitpath_s(path, NULL, 0, NULL, 0, scratch, sizeof(scratch), NULL, 0);
    char const* out = strstr(path, scratch);
    if (!out) {
        okb_warn("Could not find basename of %s", path);
        return path;
    }
    return out;
#else
    // libgen.h
    return basename((char*)path);
#endif
}

struct okb_fs_stat_res {
    struct stat stat;
    enum okb_err err;
};
OKBAPI struct okb_fs_stat_res okb_fs_stat(char const* filename) {
    assert(filename);
    struct stat st;
    if (stat(filename, &st)) {
        if (errno == ENOENT) return (struct okb_fs_stat_res){.err = OKB_FILE_DOES_NOT_EXIST};

        okb_error("`stat(\"%s\")`: %s (errno=%d)", filename, strerror(errno), errno);
        return (struct okb_fs_stat_res){.err = OKB_ERRNO};
    }
    return (struct okb_fs_stat_res){.stat = st};
}

OKBAPI bool okb_fs_exists(char const* filename) { return !okb_fs_stat(filename).err; }

OKBAPI enum okb_err okb_fs_remove(char const* filename) {
    assert(filename);
    // okb_debug("`remove(\"%s\")`", filename);
    if (remove(filename)) {
        okb_error("`remove(\"%s\")`: %s (errno=%d)", filename, strerror(errno), errno);
        return OKB_ERRNO;
    }
    return OKB_OK;
}

OKBAPI enum okb_err okb_fs_remove_if_exists(char const* filename) {
    assert(filename);
    // okb_debug("`okb_fs_remove_if_exists(\"%s\")`", filename);
    if (okb_fs_exists(filename)) return okb_fs_remove(filename);
    return OKB_OK;
}

OKBAPI enum okb_err okb_fs_rename(char const* src, char const* dest) {
    assert(src);
    assert(dest);
    // okb_debug("`rename(\"%s\", \"%s\")`", src, dest);
    if (rename(src, dest)) {
        okb_error("`rename(\"%s\", \"%s\")`: %s (errno=%d)", src, dest, strerror(errno), errno);
        return OKB_ERRNO;
    }
    return OKB_OK;
}

struct okb_fs_fopen_res {
    FILE* file;
    enum okb_err err;
};

OKBAPI struct okb_fs_fopen_res okb_fs_open(char const* filename, char const* mode) {
    assert(filename);
    assert(mode);
    FILE* fp = fopen(filename, mode);
    if (!fp) {
        okb_error("fopen(\"%s\", \"%s\"): %s (errno=%d)", filename, mode, strerror(errno), errno);
        return (struct okb_fs_fopen_res){.err = OKB_ERRNO};
    }
    return (struct okb_fs_fopen_res){.file = fp};
}

OKBAPI enum okb_err okb_fs_close(FILE* fp) {
    assert(fp);
    if (fclose(fp)) {
        okb_error("Could not close: %s (errno=%d)", strerror(errno), errno);
        return OKB_ERRNO;
    }
    return OKB_OK;
}

OKBAPI enum okb_err okb_fs_puts(char const* s, FILE* fp) {
    assert(s);
    assert(fp);
    if (fputs(s, fp) == EOF) {
        okb_error("File write: %s (errno=%d)", strerror(errno), errno);
        return OKB_ERRNO;
    }
    return OKB_OK;
}

OKBAPI enum okb_err okb_fs_printf(FILE* fp, char const* fmt, ...) {
    assert(fp);
    assert(fmt);
    va_list args;
    va_start(args, fmt);
    int bytes = vfprintf(fp, fmt, args);
    va_end(args);
    if (bytes < 0) {
        if (fp != stderr) {
            okb_error("File write: %s (errno=%d)", strerror(errno), errno);
        }
        return OKB_ERRNO;
    }
    return OKB_OK;
}

OKBAPI enum okb_err okb_fs_copy(char const* src, char const* dest) {
    assert(src);
    assert(dest);
#if defined(_WIN32)
    if (!CopyFileA(src, dest, 0)) {
        okb_error("`CopyFile(\"%s\", \"%s\", 0)` failed (error=%lu)", src, dest, GetLastError());
        return OKB_WINDOWS;
    }
    return OKB_OK;
#elif defined(FICLONE)
    enum okb_err err = OKB_OK;

    int fd_src = -1;
    int fd_dest = -1;

    fd_src = open(src, O_RDONLY);
    if (fd_src < 0) {
        okb_error("open(\"%s\", O_RDONLY): %s (errno=%d)", src, strerror(errno), errno);
        err = OKB_ERRNO;
        goto error;
    }
    fd_dest = open(dest, O_WRONLY | O_CREAT);
    if (fd_dest < 0) {
        okb_error("open(\"%s\", O_WRONLY): %s (errno=%d)", dest, strerror(errno), errno);
        err = OKB_ERRNO;
        goto error;
    }
    if (ioctl(dest_fd, FICLONE, src_fd)) {
        okb_error("ioctl(%s, FICLONE, %s): %s (errno=%d)", dest, src, strerror(errno), errno);
        err = OKB_ERRNO;
        goto error;
    }

error:
    int save_errno = errno;
    if (fd_src >= 0) close(fd_src);
    if (fd_dest >= 0) close(fd_dest);
    errno = save_errno;

    return err;
#else
// todo Use clonefile for MacOS
#warning "Using fallback version of 'okb_fs_copy'"

    struct okb_fs_fopen_res res;
    FILE* f_in = NULL;
    FILE* f_out = NULL;

    if ((res = okb_fs_open(src, "rb")).err) goto error;
    f_in = res.file;

    if ((res = okb_fs_open(dest, "wb")).err) goto error;
    f_out = res.file;

    int c;
    while ((c = fgetc(f_in)) != EOF) {
        if (fputc(c, f_out) == EOF) {
            okb_error("%s: write error during copy", dest);
            res.err = OKB_ERRNO;
            goto error;
        }
    }

error:
    int save_errno = errno;
    if (f_in) okb_fs_close(f_in);
    if (f_out) okb_fs_close(f_out);
    errno = save_errno;

    return res.err;
#endif
}

// Glob

struct okb_glob {
    int error;
#ifdef _WIN32
    char const* pattern;
    intptr_t handle;
    struct _finddata_t data;
#else
    ptrdiff_t i;
    glob_t buf;
#endif
};

OKBAPI struct okb_glob okb_glob_init(char const* const pattern) {
    assert(pattern);
    return (struct okb_glob){
        .error = 0,
        .pattern = pattern,
#ifdef _WIN32
        .handle = -1,
#else
        .i = 0,
#endif
    };
}

OKBAPI enum okb_err okb_glob_deinit(struct okb_glob* glob) {
    glob->pattern = NULL;

#ifdef _WIN32
    if (glob->handle != -1) _findclose(glob->handle);
    glob->handle = -1;

    if (glob->error) {
        okb_error("glob error: %s", strerror(glob->error));
        return OKB_ERRNO;
    }
#else
    globfree(&glob->buf);

    if (glob->error) {
        okb_error("glob error (%d)", glob->error);
        errno = glob->error;
        return OKB_ERRNO;
    }
#endif

    return OKB_OK;
}

OKBAPI char const* okb_glob_next(struct okb_glob* glob) {
    assert(glob);
    if (glob->error) return NULL;
    assert(glob->pattern);

#ifdef _WIN32

    if (glob->handle == -1) {
        glob->handle = _findfirst(glob->pattern, &glob->data);
        if (glob->handle == -1) {
            if (errno != ENOENT) {
                glob->error = errno;
            }
            return NULL;
        }
    } else {
        if (_findnext(glob->handle, &glob->data) == -1) {
            if (errno != ENOENT) {
                glob->error = errno;
            }
            return NULL;
        }
    }

    return glob->data.name;

#else

    assert(glob->i >= 0);
    if (glob->i == 0) {
        int err = glob(glob->pattern, 0, NULL, &glob->buf);
        if (err != GLOB_NOMATCH) {
            glob->error = err;
            return NULL;
        }
    }

    int i = glob->i;
    glob->i++;
    return i < glob->buf.gl_pathc ? glob->buf.gl_pathc[i] : NULL;
#endif
}

OKBAPI enum okb_err okb_fs_delete_glob(char const* pattern) {
    assert(pattern);
    struct okb_glob glob = okb_glob_init(pattern);
    for (char const* fname; (fname = okb_glob_next(&glob));) {
        okb_info("Deleting '%s'", fname);
        (void)okb_fs_remove(fname);
    }
    return okb_glob_deinit(&glob);
}

OKBAPI enum okb_err okb_cslist_add_glob(struct okb_cslist* list, char const* pattern) {
    assert(list);
    assert(pattern);
    struct okb_glob glob = okb_glob_init(pattern);
    for (char const* fname; (fname = okb_glob_next(&glob));) {
        okb_cslist_push_cstr(list, fname);
    }
    return okb_glob_deinit(&glob);
}

// System command

struct okb_system_res {
    ptrdiff_t exit_code;
    enum okb_err err;
};

OKBAPI struct okb_system_res okb_system(char const* cmd) {
    assert(cmd);
    ptrdiff_t cmd_err = system(cmd);
    switch (cmd_err) {
        case -1:
            okb_error("system(\"%s\"): %s (errno=%d)", cmd, strerror(errno), errno);
            return (struct okb_system_res){.err = OKB_ERRNO};
        case -1073741819:  // Windows 0xC0000005: Access Violation
            okb_error("system(\"%s\"): Segmentation Fault", cmd);
            return (struct okb_system_res){.err = OKB_SUBPROC};
        case -1073740940:  // Windows 0xC0000374: Heap Corruption
            okb_error("system(\"%s\"): Heap Corruption", cmd);
            return (struct okb_system_res){.err = OKB_SUBPROC};
        default:
            if (cmd_err < 0) {
                okb_error("system(\"%s\") returned %lld", cmd, cmd_err);
                return (struct okb_system_res){.err = OKB_SUBPROC};
            }
            return (struct okb_system_res){.exit_code = cmd_err};
    }
}

OKBAPI enum okb_err okb_run(char const* cmd) {
    assert(cmd);
    struct okb_system_res res = okb_system(cmd);
    if (res.err) return res.err;
    if (res.exit_code != 0) {
        okb_error("Command returned non-zero exit code: %lld", res.exit_code);
        return OKB_SUBPROC;
    }
    return OKB_OK;
}

// Build

enum okb_compiler_kind {
    OKB_COMPILER_UNKNOWN,
    OKB_COMPILER_CLANG,
    OKB_COMPILER_GCC,
    OKB_COMPILER_MSVC,
};

#define OKB_ENVVAR_REBUILD "OKBUILD_REBUILD"

#define OKB_DEFAULT_BUILD_C "build.c"

#if defined(__zig_cc__)
// `__zig_cc__` must be provided manually when running zig cc
#define OKB_DEFAULT_COMPILER "zig cc"
#define OKB_DEFAULT_COMPILER_KIND OKB_COMPILER_CLANG
#elif defined(__clang__)
#define OKB_DEFAULT_COMPILER "clang"
#define OKB_DEFAULT_COMPILER_KIND OKB_COMPILER_CLANG
#elif defined(__GNUC__)
#define OKB_DEFAULT_COMPILER "gcc"
#define OKB_DEFAULT_COMPILER_KIND OKB_COMPILER_GCC
#elif defined(_MSC_BUILD)
#define OKB_DEFAULT_COMPILER "cl"
#define OKB_DEFAULT_COMPILER_KIND OKB_COMPILER_MSVC
#else
#define OKB_DEFAULT_COMPILER ""
#define OKB_DEFAULT_COMPILER_KIND OKB_COMPILER_UNKNOWN
#endif

#if defined(_MSC_BUILD)
#define OKB_DEFAULT_CFLAGS "/D /Wall /Zi /Zc:preprocessor"
#elif defined(__zig_cc__)
// `__zig_cc__` must be provided manually when running zig cc
#define OKB_DEFAULT_CFLAGS "-D__zig_cc__ -Wall -Wextra -pedantic -Werror -g"
#else
#define OKB_DEFAULT_CFLAGS "-Wall -Wextra -pedantic -Werror -g"
#endif

#ifdef _WIN32
#define OKB_DEFAULT_OUT_FILENAME "build.exe"
#define OKB_DEFAULT_IS_WIN_EXE true
#else
#define OKB_DEFAULT_OUT_FILENAME "build"
#define OKB_DEFAULT_IS_WIN_EXE false
#endif

struct okb_build {
    char const* build_c_filename;
    char const* build_out_filename;
    char const* compiler;
    char const* cflags;
    enum okb_compiler_kind compiler_kind;
    bool force_rebuild;
    bool target_is_win_exe;
    struct okb_cslist script_deps;
    int argc;
    char** argv;
};

OKBAPI struct okb_build* okb_build_init(int argc, char* argv[]) {
    assert(argc >= 1);
    assert(argv);
    struct okb_build* build = okb_alloc(1, sizeof(struct okb_build));
    *build = (struct okb_build){
        .build_c_filename = OKB_DEFAULT_BUILD_C,
        .build_out_filename = OKB_DEFAULT_OUT_FILENAME,
        .compiler = OKB_DEFAULT_COMPILER,
        .cflags = OKB_DEFAULT_CFLAGS,
        .compiler_kind = OKB_DEFAULT_COMPILER_KIND,
        .force_rebuild = false,
        .target_is_win_exe = OKB_DEFAULT_IS_WIN_EXE,
        .script_deps = okb_cslist_init(),
        .argc = argc,
        .argv = argv,
    };
    return build;
}

OKBAPI void okb_build_deinit(struct okb_build* build) {
    assert(build);
    okb_cslist_deinit(&build->script_deps);
}

// Add a filename (or glob pattern of filenames) to the build.c script dependency list.
OKBAPI void okb_build_add_script_dependency(struct okb_build* build, char const* filename) {
    assert(build);
    assert(filename);
    okb_cslist_add_glob(&build->script_deps, filename);
}

struct okb_build_is_old_res {
    bool is_old;
    enum okb_err err;
};

OKBAPI struct okb_build_is_old_res okb_is_file_older_than_time(char const* filename, time_t mtime) {
    assert(filename);
    struct okb_fs_stat_res stat_res = okb_fs_stat(filename);
    if (stat_res.err == OKB_FILE_DOES_NOT_EXIST) okb_error("File does not exist: %s", filename);
    if (stat_res.err) return (struct okb_build_is_old_res){.err = stat_res.err};
    return (struct okb_build_is_old_res){.is_old = stat_res.stat.st_mtime > mtime};
}

OKBAPI struct okb_build_is_old_res
okb_is_file_older_than_dependencies(char const* filename, struct okb_cslist dependencies) {
    assert(filename);
    assert(dependencies.len > 0);

    struct okb_fs_stat_res stat_res = okb_fs_stat(filename);
    if (stat_res.err == OKB_FILE_DOES_NOT_EXIST)
        return (struct okb_build_is_old_res){.is_old = true};
    if (okb_trace_err(stat_res.err)) return (struct okb_build_is_old_res){.err = stat_res.err};

    time_t filename_mtime = stat_res.stat.st_mtime;

    struct okb_build_is_old_res res = (struct okb_build_is_old_res){.is_old = false};

    for (ptrdiff_t i = 0; i < dependencies.len; ++i) {
        res = okb_is_file_older_than_time(okb_cslist_get_cstr(dependencies, i), filename_mtime);
        if (res.err || res.is_old) break;
    }

    return res;
}

OKBAPI enum okb_err okb_build_link(
    struct okb_build const* build,
    char const* output_filename,
    struct okb_cslist input_filenames
) {
    assert(build);
    assert(output_filename);
    assert(input_filenames.len > 0);

    enum okb_err err = OKB_OK;

    struct okb_cstring cmd = okb_cstring_init_with_cstr(build->compiler);
    struct okb_cstring output_filename_owned = okb_cstring_init_with_cstr(output_filename);

    for (ptrdiff_t i = 0; i < input_filenames.len; ++i) {
        okb_cstring_push(&cmd, ' ');
        okb_cstring_extend_cstr(&cmd, okb_cslist_get_cstr(input_filenames, i));
    }

    okb_cstring_push(&cmd, ' ');
    okb_cstring_extend_cstr(&cmd, build->cflags);

    if (build->compiler_kind == OKB_COMPILER_MSVC) {
        okb_cstring_extend_cstr(&cmd, " /link /out:");
    } else {
        okb_cstring_extend_cstr(&cmd, " -o");
    }
    okb_cstring_extend_cstr(&cmd, output_filename);

    // Remove stale .pdb file
    okb_cstring_replace_ext(&output_filename_owned, "pdb");
    if (okb_trace_err(err = okb_fs_remove_if_exists(okb_cstring_as_cstr(output_filename_owned))))
        goto error;

    // Remove stale .ilk file
    okb_cstring_replace_ext(&output_filename_owned, "ilk");
    if (okb_trace_err(err = okb_fs_remove_if_exists(okb_cstring_as_cstr(output_filename_owned))))
        goto error;

    okb_info("Linking: %s", okb_cstring_as_cstr(cmd));
    if (okb_trace_err(err = okb_run(okb_cstring_as_cstr(cmd)))) goto error;

error:
    okb_cstring_deinit(&output_filename_owned);
    okb_cstring_deinit(&cmd);

    return err;
}

OKBAPI enum okb_err okb_build_compile(
    struct okb_build const* build,
    char const* output_filename,
    char const* input_filename
) {
    assert(build);
    assert(output_filename);
    assert(input_filename);
    enum okb_err err = OKB_OK;

    struct okb_cstring cmd = okb_cstring_init_with_cstr(build->compiler);

    if (build->compiler_kind != OKB_COMPILER_MSVC) {
        okb_cstring_extend_cstr(&cmd, " -c");
    }

    okb_cstring_push(&cmd, ' ');
    okb_cstring_extend_cstr(&cmd, input_filename);

    okb_cstring_push(&cmd, ' ');
    okb_cstring_extend_cstr(&cmd, build->cflags);

    if (build->compiler_kind == OKB_COMPILER_MSVC) {
        okb_cstring_extend_cstr(&cmd, " /Fo");
    } else {
        okb_cstring_extend_cstr(&cmd, " -o");
    }
    okb_cstring_extend_cstr(&cmd, output_filename);

    okb_info("Compiling: %s", okb_cstring_as_cstr(cmd));
    if (okb_trace_err(err = okb_run(okb_cstring_as_cstr(cmd)))) goto error;

error:
    okb_cstring_deinit(&cmd);

    return err;
}

OKBAPI enum okb_err okb_rebuild_script(struct okb_build* build) {
    assert(build);
    enum okb_err err = OKB_OK;

    // Check if we are in a child process
    {
        char const* rebuild_state = getenv(OKB_ENVVAR_REBUILD);

        // If already rebuilt, then return
        if (rebuild_state && strcmp(rebuild_state, "1") == 0) goto done;

        char const* this_filename = okb_fs_basename((char*)build->argv[0]);

#ifdef _WIN32
        // Windows cleanup
        if (rebuild_state && strcmp(rebuild_state, "2") == 0) {
            // Move .okb_rebuild.pdb -> build.pdb
            {
                // TODO: Clean this up

                struct okb_cstring src = okb_cstring_init_with_cstr(this_filename);
                struct okb_cstring dest = okb_cstring_init_with_cstr(build->build_out_filename);

                okb_cstring_replace_ext(&src, "pdb");
                okb_cstring_replace_ext(&dest, "pdb");

                // delete old build.pdb
                if ((err = okb_fs_remove_if_exists(okb_cstring_as_cstr(dest))))
                    goto win_cleanup_error;

                // rename .okb_rebuild.pdb -> build.pdb
                if (okb_fs_exists(okb_cstring_as_cstr(src))) {
                    if ((err = okb_fs_rename(okb_cstring_as_cstr(src), okb_cstring_as_cstr(dest))))
                        goto win_cleanup_error;
                }

                okb_cstring_replace_ext(&src, "ilk");
                okb_cstring_replace_ext(&dest, "ilk");

                // delete old build.ilk
                if ((err = okb_fs_remove_if_exists(okb_cstring_as_cstr(dest))))
                    goto win_cleanup_error;

                // rename .okb_rebuild.ilk -> build.ilk
                if (okb_fs_exists(okb_cstring_as_cstr(src))) {
                    if ((err = okb_fs_rename(okb_cstring_as_cstr(src), okb_cstring_as_cstr(dest))))
                        goto win_cleanup_error;
                }

            win_cleanup_error:
                okb_cstring_deinit(&dest);
                okb_cstring_deinit(&src);

                if (okb_trace_err(err)) return err;
            }

            // Move .okb_rebuild.exe -> build.exe
            {
                // Retry-loop with exponential fall-off
                DWORD delay_ms = 10;
                for (ptrdiff_t retry = 1; retry <= 10; ++retry) {
                    Sleep(delay_ms);
                    delay_ms *= 2;
                    if ((err = okb_fs_remove_if_exists(build->build_out_filename))) continue;
                    if ((err = okb_fs_rename(this_filename, build->build_out_filename))) continue;
                    break;
                }
                if (okb_trace_err(err)) return err;
            }
            exit(0);
        }
#endif
    }

    // Check if need to rebuild
    if (!build->force_rebuild) {
        struct okb_cslist deps = okb_cslist_init();

        okb_cslist_push_cstr(&deps, build->build_c_filename);
        okb_cslist_extend(&deps, build->script_deps);

        struct okb_build_is_old_res res =
            okb_is_file_older_than_dependencies(build->build_out_filename, deps);

        okb_cslist_deinit(&deps);

        if (err || !res.is_old) return err;
    }

    // Rebuild, run, and exit
    {
        char const* const tmp_build_filename = okb_cstr_ends_with(build->build_out_filename, ".exe")
                                                   ? ".okb_rebuild.exe"
                                                   : ".okb_rebuild";

        struct okb_cstring cmd = okb_cstring_init();
        struct okb_cslist link_deps = okb_cslist_init();
        okb_cslist_push_cstr(&link_deps, build->build_c_filename);

        okb_info("Rebuilding build script");

        // Build temporary build binary
        if (okb_trace_err(err = okb_build_link(build, tmp_build_filename, link_deps)))
            goto rebuild_error;

        // Run temporary build binary
        putenv(OKB_ENVVAR_REBUILD "=1");
        okb_cstring_extend_cstr(&cmd, tmp_build_filename);

        // Add CLI arguments
        okb_cstring_extend_cli_args(&cmd, build->argc, build->argv);

        if (okb_trace_err(err = okb_run(okb_cstring_as_cstr(cmd)))) goto rebuild_error;

#ifdef _WIN32
        // Spawn another process to overwrite real build binary with temporary
        putenv(OKB_ENVVAR_REBUILD "=2");
        okb_cstring_clear(&cmd);
        okb_cstring_extend_cstr(&cmd, "start /b ");
        okb_cstring_extend_cstr(&cmd, tmp_build_filename);
        if (okb_trace_err(err = okb_run(okb_cstring_as_cstr(cmd)))) goto rebuild_error;
#else
        // Overwrite real build binary with temporary
        if (okb_trace_err(err = okb_fs_remove_if_exists(build->build_out_filename)))
            goto rebuild_error;
        if (okb_trace_err(err = okb_fs_rename(this_filename, build->build_out_filename)))
            goto rebuild_error;
#endif
        exit(0);

    rebuild_error:
        okb_cslist_deinit(&link_deps);
        okb_cstring_deinit(&cmd);
    }

done:
    return err;
}

OKBAPI enum okb_err okb_compile_rule(
    struct okb_cslist* out_object_filenames,
    struct okb_build const* build,
    char const* c_filename,
    struct okb_cslist dependency_filenames
) {
    assert(out_object_filenames);
    assert(build);
    assert(c_filename);
    // Generate .obj filename, and add it to list
    struct okb_cstring obj_filename = okb_cstring_init_with_cstr(c_filename);
    okb_cstring_replace_ext(&obj_filename, "obj");
    okb_cslist_push(out_object_filenames, obj_filename);

    char const* const obj_cstr = okb_cstring_as_cstr(obj_filename);

    enum okb_err err = OKB_OK;

    if (!build->force_rebuild) {
        // Check if C file or any dependencies were updated
        struct okb_cslist deps = okb_cslist_init();
        okb_cslist_push_cstr(&deps, c_filename);
        okb_cslist_extend(&deps, dependency_filenames);

        struct okb_build_is_old_res res = okb_is_file_older_than_dependencies(obj_cstr, deps);
        err = res.err;
        if (err || !res.is_old) goto done;
    }

    // Compile
    err = okb_build_compile(build, obj_cstr, c_filename);

done:
    return err;
}

OKBAPI enum okb_err okb_link_rule(
    struct okb_build const* build,
    char const* binary_name,
    struct okb_cslist object_filenames
) {
    assert(build);
    assert(binary_name);
    struct okb_cstring binary_filename = okb_cstring_init_with_cstr(binary_name);
    if (build->target_is_win_exe) {
        okb_cstring_replace_ext(&binary_filename, "exe");
    }

    enum okb_err err = OKB_OK;

    if (!build->force_rebuild) {
        struct okb_build_is_old_res res = okb_is_file_older_than_dependencies(
            okb_cstring_as_cstr(binary_filename), object_filenames
        );
        err = res.err;
        if (err || !res.is_old) goto done;
    }

    err = okb_build_link(build, okb_cstring_as_cstr(binary_filename), object_filenames);

done:
    okb_cstring_deinit(&binary_filename);
    return err;
}

OKBAPI bool okb_subcmd(struct okb_build* build, char const* cmd) {
    assert(build);
    assert(cmd);
    if (build->argc < 2) return false;
    return strcmp(cmd, build->argv[1]) == 0;
}

#endif  // OKBUILD_H_
