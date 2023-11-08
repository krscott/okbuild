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
    size_t result = a * b;
    if (a > 1 && result / a != b) okb_panic("multiply overflow");
    return result;
}

OKBAPI ptrdiff_t okb_next_power_of_2(ptrdiff_t n) {
    ptrdiff_t k = 1;
    while (k < n) k *= 2;
    return k;
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

OKBAPI void okb_cstring_push(struct okb_cstring* cs, char c) {
    OKB_DA_PUSH(okb_cstring, cs, c);
    cs->buf[cs->len] = '\0';
}

OKBAPI void okb_cstring_extend_chars(struct okb_cstring* cs, ptrdiff_t n, char const* chars) {
    if (n > 0) {
        assert(chars);
        OKB_DA_EXTEND(okb_cstring, cs, n, chars);
        assert(cs->len < cs->cap);
        cs->buf[cs->len] = '\0';
    }
}

OKBAPI void okb_cstring_extend_cstr(struct okb_cstring* cs, char const* cstr) {
    assert(cs);
    assert(cstr);
    okb_cstring_extend_chars(cs, strlen(cstr), cstr);
}

OKBAPI void okb_cstring_extend_cstr_escaped(struct okb_cstring* cs, char const* cstr) {
    assert(cs);
    assert(cstr);
    for (; *cstr; ++cstr) {
        switch (*cstr) {
            case '"':
                okb_cstring_extend_cstr(cs, "\\\"");
                break;
            case '\\':
                okb_cstring_extend_cstr(cs, "\\\\");
                break;
            default:
                okb_cstring_push(cs, *cstr);
        }
    }
}

OKBAPI void okb_cstring_extend(struct okb_cstring* cs, struct okb_cstring other) {
    okb_cstring_extend_chars(cs, other.len, other.buf);
}

OKBAPI void okb_cstring_set_cstr(struct okb_cstring* cs, char const* cstr) {
    okb_cstring_clear(cs);
    okb_cstring_extend_cstr(cs, cstr);
}

OKBAPI char const* okb_cstring_as_cstr(struct okb_cstring cs) { return cs.len == 0 ? "" : cs.buf; }

OKBAPI struct okb_cstring okb_cstring_init_with_cstr(char const* cstr) {
    assert(cstr);
    struct okb_cstring cs = okb_cstring_init();
    cs.len = strlen(cstr);
    if (cs.len > 0) {
        // Usually this is a cstr clone that won't be modified again, so
        // just reserve the exact amount of bytes needed.
        cs.cap = cs.len + 1;  // +1 for null terminator
        cs.buf = okb_alloc(cs.cap, sizeof(char*));
        strcpy(cs.buf, cstr);
    }
    return cs;
}

OKBAPI struct okb_cstring okb_cstring_clone(struct okb_cstring cs) {
    return okb_cstring_init_with_cstr(okb_cstring_as_cstr(cs));
}

OKBAPI void okb_cstring_strip_file_ext(struct okb_cstring* cs) {
    assert(cs);

    // Find len of string up to extension '.'
    // Do not strip if '.' is first char of basename (e.g. ".foo", "foo/.bar")
    // Pathological cases are not supported (e.g. "..foo")
    for (ptrdiff_t len = cs->len; len >= 2; len--) {
        char c2 = cs->buf[len - 2];
        char c1 = cs->buf[len - 1];
        if (c2 == '\\' || c2 == '/') break;
        if (c1 == '.') {
            if (c2 == '.') break;
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
        bool const use_quotes = !!strchr(argv[i], ' ') || !!strchr(argv[i], '"');

        okb_cstring_push(cs, ' ');
        if (use_quotes) okb_cstring_push(cs, '"');
        okb_cstring_extend_cstr_escaped(cs, argv[i]);
        if (use_quotes) okb_cstring_push(cs, '"');
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

OKBAPI void okb_cslist_extend_cstrs(struct okb_cslist* list, ptrdiff_t n, char** cstrs) {
    assert(list);
    for (ptrdiff_t i = 0; i < n; ++i) {
        okb_cslist_push_cstr(list, cstrs[i]);
    }
}

OKBAPI void
okb_cslist_extend_split_cstr(struct okb_cslist* list, char const* cstr, char const* delims) {
    okb_cslist_push(list, okb_cstring_init());

    for (; *cstr != 0; ++cstr) {
        if (strchr(delims, *cstr)) {
            okb_cslist_push(list, okb_cstring_init());
        } else {
            okb_cstring_push(&list->buf[list->len - 1], *cstr);
        }
    }
}

// Filesystem

OKBAPI char const* okb_fs_basename(char const* path) {
    assert(path);
    static char scratch[260];
    assert(strlen(path) < okb_countof(scratch));
    strncpy(scratch, path, okb_countof(scratch) - 1);

#ifdef _MSC_BUILD
    _splitpath_s(path, NULL, 0, NULL, 0, scratch, okb_countof(scratch), NULL, 0);
    char const* out = strstr(path, scratch);
    if (!out) {
        okb_warn("Could not find basename of %s", path);
        return path;
    }
    return out;
#else
    // libgen.h
    return basename(scratch);
#endif
}

OKBAPI char const* okb_fs_dirname(char const* path) {
    assert(path);
    static char scratch[260];
    assert(strlen(path) < okb_countof(scratch));
    strncpy(scratch, path, okb_countof(scratch) - 1);

#ifdef _MSC_BUILD
    _splitpath_s(path, NULL, 0, scratch, okb_countof(scratch), NULL, 0, NULL, 0);
    char const* out = strstr(path, scratch);
    if (!out) {
        okb_warn("Could not find dirname of %s", path);
        return path;
    }
    return out;
#else
    // libgen.h
    return dirname(scratch);
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

OKBAPI enum okb_err okb_fs_mkdir(char const* path) {
    int mkdir_err;
    errno = 0;

#ifdef _WIN32
    mkdir_err = mkdir(path);
#else
    mkdir_err = mkdir(path, 0755);
#endif

    if (mkdir_err) {
        okb_error("`mkdir(\"%s\")`: %s (errno=%d)", path, strerror(errno), errno);
        return OKB_ERRNO;
    }
    return OKB_OK;
}

OKBAPI bool okb_fs_exists(char const* filename) { return !okb_fs_stat(filename).err; }

OKBAPI bool okb_fs_isdir(char const* path) {
    struct okb_fs_stat_res res = okb_fs_stat(path);
    if (res.err) return false;
    return S_ISDIR(res.stat.st_mode);
}

OKBAPI enum okb_err okb_fs_mkdir_p(char const* path) {
    assert(path);
    if (path[0] == '\0') return OKB_OK;

    enum okb_err err = OKB_OK;
    struct okb_cstring path_tmp = okb_cstring_init_with_cstr(path);

    char* partial_path = path_tmp.buf;
    assert(partial_path);
    for (char* p = partial_path; *p; ++p) {
        if (*p == '/' || *p == '\\') {
            *p = '\0';
            if (!okb_fs_isdir(partial_path)) {
                if ((err = okb_fs_mkdir(partial_path))) goto error;
            }
            *p = '/';
        }
    }

    if (!okb_fs_isdir(partial_path)) {
        if ((err = okb_fs_mkdir(partial_path))) goto error;
    }

error:
    okb_cstring_deinit(&path_tmp);
    return err;
}

OKBAPI enum okb_err okb_fs_remove(char const* filename) {
    assert(filename);
    if (remove(filename)) {
        okb_error("`remove(\"%s\")`: %s (errno=%d)", filename, strerror(errno), errno);
        return OKB_ERRNO;
    }
    return OKB_OK;
}

OKBAPI enum okb_err okb_fs_rmdir(char const* dirname) {
    assert(dirname);
    if (rmdir(dirname)) {
        okb_error("`rmdir(\"%s\")`: %s (errno=%d)", dirname, strerror(errno), errno);
        return OKB_ERRNO;
    }
    return OKB_OK;
}

OKBAPI enum okb_err okb_fs_remove_if_exists(char const* filename) {
    assert(filename);
    if (okb_fs_exists(filename)) return okb_fs_remove(filename);
    return OKB_OK;
}

OKBAPI enum okb_err okb_fs_rename(char const* src, char const* dest) {
    assert(src);
    assert(dest);
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

#ifdef _WIN32
struct okb_glob_node_ {
    int error;
    struct okb_glob_node_* parent;
    char const* pattern_tail;
    struct okb_cstring pattern_dir;
    intptr_t handle;
    struct _finddata_t data;
    bool is_last;
};

OKBAPI void okb_glob_node_get_fullpath_(struct okb_cstring* path, struct okb_glob_node_* node) {
    assert(path);
    assert(node);
    okb_cstring_clear(path);
    if (node->parent) {
        okb_glob_node_get_fullpath_(path, node->parent);
        okb_cstring_push(path, '/');
    }
    okb_cstring_extend_cstr(path, node->data.name);
}

OKBAPI struct okb_glob_node_*
okb_glob_node_init_(struct okb_glob_node_* parent, char const* pattern) {
    assert(pattern);
    char const* p = pattern;

    struct okb_cstring pattern_dir = okb_cstring_init();

    // Start with parent path
    if (parent) {
        okb_glob_node_get_fullpath_(&pattern_dir, parent);
        okb_cstring_push(&pattern_dir, '/');
    }

    // Get dir pattern. e.g. pattern="foo*/*/bar" -> pattern_dir="foo*"
    for (; *p; ++p) {
        if (*p == '/' || *p == '\\') {
            ++p;
            break;
        }
        okb_cstring_push(&pattern_dir, *p);
    }

    struct okb_glob_node_* node = okb_alloc(1, sizeof(struct okb_glob_node_));

    *node = (struct okb_glob_node_){
        .parent = parent,
        .pattern_tail = p,
        .pattern_dir = pattern_dir,
        .handle = -1,
        .is_last = (*p == '\0'),
    };

    return node;
}

OKBAPI enum okb_err okb_glob_node_deinit_(struct okb_glob_node_* node, bool recursive) {
    enum okb_err err = OKB_OK;

    if (recursive && node->parent) err = okb_glob_node_deinit_(node->parent, true);
    if (node->handle != -1) _findclose(node->handle);

    node->handle = -1;

    okb_cstring_deinit(&node->pattern_dir);

    if (node->error) {
        okb_error("glob error: %s", strerror(node->error));
        errno = node->error;
        err = OKB_ERRNO;
    }

    okb_free(node);
    return err;
}
#endif

struct okb_glob {
    int error;
    char const* pattern;
#ifdef _WIN32
    struct okb_glob_node_* node;
    struct okb_cstring path;
#else
    ptrdiff_t i;
    glob_t buf;
#endif
};

OKBAPI struct okb_glob okb_glob_init(char const* pattern) {
    assert(pattern);
    return (struct okb_glob){
        .error = 0,
        .pattern = pattern,
#ifdef _WIN32
        .node = okb_glob_node_init_(NULL, pattern),
        .path = okb_cstring_init(),
#else
        .i = 0,
#endif
    };
}

OKBAPI enum okb_err okb_glob_deinit(struct okb_glob* glob) {
    glob->pattern = NULL;

#ifdef _WIN32
    okb_cstring_deinit(&glob->path);
    return okb_glob_node_deinit_(glob->node, true);
#else
    globfree(&glob->buf);

    if (glob->error) {
        okb_error("glob error: %s", strerror(glob->error));
        errno = glob->error;
        return OKB_ERRNO;
    }
    return OKB_OK;

#endif
}

OKBAPI char const* okb_glob_next(struct okb_glob* glob) {
    assert(glob);
    if (glob->error) return NULL;
    assert(glob->pattern);

#ifdef _WIN32
    if (!glob->node) return NULL;

    // Perhaps there is an easier way to do this in Windows.
    // Nothing I found online correctly handled paths with arbitrary wildcards.
    // I might revisit, but this works well enough for now.

    char const* name;

    do {
        // Find next name
        if (glob->node->handle == -1) {
            // okb_debug(" START %s", okb_cstring_as_cstr(glob->node->pattern_dir));
            glob->node->handle =
                _findfirst(okb_cstring_as_cstr(glob->node->pattern_dir), &glob->node->data);
            if (glob->node->handle == -1) {
                if (errno != ENOENT) {
                    // exit iterator on error
                    glob->node->error = errno;
                    return NULL;
                }
                name = NULL;
            } else {
                name = glob->node->data.name;
            }
        } else {
            if (_findnext(glob->node->handle, &glob->node->data) == -1) {
                if (errno != ENOENT) {
                    // exit iterator on error
                    glob->node->error = errno;
                    return NULL;
                }
                name = NULL;
            } else {
                name = glob->node->data.name;
            }
        }

        // okb_debug(" >>> %s", name);

        if (name == NULL) {
            // No more names in this dir

            // If at root, iterator is done
            if (!glob->node->parent) return NULL;

            // Go back to parent directory
            struct okb_glob_node_* deinit_node = glob->node;
            glob->node = glob->node->parent;
            okb_glob_node_deinit_(deinit_node, false);
        } else if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            // skip
        } else if (glob->node->data.attrib & _A_SUBDIR && !glob->node->is_last) {
            // Go into directory
            glob->node = okb_glob_node_init_(glob->node, glob->node->pattern_tail);
        } else if (glob->node->is_last) {
            // Return matching path

            okb_cstring_clear(&glob->path);
            assert(glob->node);
            if (glob->node->parent) {
                okb_glob_node_get_fullpath_(&glob->path, glob->node->parent);
                okb_cstring_push(&glob->path, '/');
            }
            okb_cstring_extend_cstr(&glob->path, name);

            return okb_cstring_as_cstr(glob->path);
        }

    } while (1);

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
    // okb_debug("Pattern: %s", pattern);
    struct okb_glob glob = okb_glob_init(pattern);
    for (char const* name; (name = okb_glob_next(&glob));) {
        okb_info("Deleting '%s'", name);
        if (okb_fs_isdir(name)) {
            (void)okb_fs_rmdir(name);
        } else {
            (void)okb_fs_remove(name);
        }
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
        case -1073741571:  // Windows 0xC00000FD: Stack Overflow
            okb_error("system(\"%s\"): Stack Overflow", cmd);
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

struct okb_build {
    struct okb_cstring build_c_filename;
    struct okb_cstring build_out_filename;
    struct okb_cstring obj_dir;
    struct okb_cstring cc;
    struct okb_cstring cflags;
    struct okb_cstring lflags;
    struct okb_cstring compile_in_flag;
    struct okb_cstring compile_out_flag;
    struct okb_cstring link_out_flag;
    bool force_rebuild;
    bool target_is_win_exe;
    struct okb_cslist script_deps;
    int argc;
    char** argv;
};

struct okb_settings {
    char const* build_c_filename;
    char const* build_out_filename;
    char const* obj_dir;
    char const* cc;
    char const* cflags;
    char const* lflags;
    char const* compile_in_flag;
    char const* compile_out_flag;
    char const* link_out_flag;
};

OKBAPI void okb_build_set(struct okb_build* build, struct okb_settings settings) {
#define OKB_SET_(x) \
    if (settings.x) okb_cstring_set_cstr(&build->x, settings.x)

    OKB_SET_(build_c_filename);
    OKB_SET_(build_out_filename);
    OKB_SET_(obj_dir);
    OKB_SET_(cc);
    OKB_SET_(cflags);
    OKB_SET_(lflags);
    OKB_SET_(compile_in_flag);
    OKB_SET_(compile_out_flag);
    OKB_SET_(link_out_flag);

#undef OKB_SET_
}

static struct okb_settings const okb_settings_zig_cc = {
    .cc = "zig cc",
    .cflags = "-D__zig_cc__ -Wall -Wextra -pedantic -Werror -g",
    .lflags = "",
    .compile_in_flag = "-c",
    .compile_out_flag = "-o",
    .link_out_flag = "-o",
};

static struct okb_settings const okb_settings_clang = {
    .cc = "clang",
    .cflags = "-Wall -Wextra -pedantic -Werror -g",
    .lflags = "",
    .compile_in_flag = "-c",
    .compile_out_flag = "-o",
    .link_out_flag = "-o",
};

static struct okb_settings const okb_settings_gcc = {
    .cc = "gcc",
    .cflags = "-Wall -Wextra -pedantic -Werror -g",
    .lflags = "",
    .compile_in_flag = "-c",
    .compile_out_flag = "-o",
    .link_out_flag = "-o",
};

static struct okb_settings const okb_settings_msvc = {
    .cc = "cl",
    .cflags = "/Wall /Zi /Zc:preprocessor",
    .lflags = "",
    .compile_in_flag = "",
    .compile_out_flag = "/Fo",
    .link_out_flag = "/link /out:",
};

#define OKB_ENVVAR_REBUILD "OKBUILD_REBUILD"

#if defined(__zig_cc__)
// `__zig_cc__` must be provided manually when running zig cc
#define OKB_DEFAULT_COMPILER_SETTINGS okb_settings_zig_cc
#elif defined(__clang__)
#define OKB_DEFAULT_COMPILER_SETTINGS okb_settings_clang
#elif defined(__GNUC__)
#define OKB_DEFAULT_COMPILER_SETTINGS okb_settings_gcc
#elif defined(_MSC_BUILD)
#define OKB_DEFAULT_COMPILER_SETTINGS okb_settings_msvc
#else
#define OKB_DEFAULT_COMPILER_SETTINGS ((struct okb_settings){0})
#endif

#ifdef _WIN32
#define OKB_DEFAULT_OUT_FILENAME "build.exe"
#define OKB_DEFAULT_IS_WIN_EXE true
#else
#define OKB_DEFAULT_OUT_FILENAME "build"
#define OKB_DEFAULT_IS_WIN_EXE false
#endif

#define OKB_DEFAULT_OBJ_DIR "_build"

OKBAPI struct okb_build* okb_build_init(const char* build_c_filename, int argc, char* argv[]) {
    assert(argc >= 1);
    assert(argv);
    struct okb_build* build = okb_alloc(1, sizeof(struct okb_build));
    *build = (struct okb_build){
        .build_c_filename = okb_cstring_init_with_cstr(build_c_filename),
        .build_out_filename = okb_cstring_init_with_cstr(OKB_DEFAULT_OUT_FILENAME),
        .obj_dir = okb_cstring_init_with_cstr(OKB_DEFAULT_OBJ_DIR),
        .cc = okb_cstring_init(),
        .cflags = okb_cstring_init(),
        .lflags = okb_cstring_init(),
        .compile_in_flag = okb_cstring_init(),
        .compile_out_flag = okb_cstring_init(),
        .link_out_flag = okb_cstring_init(),
        .force_rebuild = false,
        .target_is_win_exe = OKB_DEFAULT_IS_WIN_EXE,
        .script_deps = okb_cslist_init(),
        .argc = argc,
        .argv = argv,
    };

    okb_build_set(build, OKB_DEFAULT_COMPILER_SETTINGS);

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

    struct okb_cstring cmd = okb_cstring_init_with_cstr(okb_cstring_as_cstr(build->cc));
    struct okb_cstring output_filename_owned = okb_cstring_init_with_cstr(output_filename);

    for (ptrdiff_t i = 0; i < input_filenames.len; ++i) {
        okb_cstring_push(&cmd, ' ');
        okb_cstring_extend_cstr(&cmd, okb_cslist_get_cstr(input_filenames, i));
    }

    // Link step may include compile step
    if (build->cflags.len) {
        okb_cstring_push(&cmd, ' ');
        okb_cstring_extend(&cmd, build->cflags);
    }

    if (build->lflags.len) {
        okb_cstring_push(&cmd, ' ');
        okb_cstring_extend(&cmd, build->lflags);
    }

    okb_cstring_push(&cmd, ' ');
    okb_cstring_extend(&cmd, build->link_out_flag);  // e.g. "-o" or "/link /out:"
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

    if ((err = okb_fs_mkdir_p(okb_fs_dirname(output_filename)))) goto error1;

    struct okb_cstring cmd = okb_cstring_init();

    okb_cstring_extend(&cmd, build->cc);

    if (build->compile_in_flag.len) {
        okb_cstring_push(&cmd, ' ');
        okb_cstring_extend(&cmd, build->compile_in_flag);  // e.g. "-c"
    }

    okb_cstring_push(&cmd, ' ');
    okb_cstring_extend_cstr(&cmd, input_filename);

    if (build->cflags.len) {
        okb_cstring_push(&cmd, ' ');
        okb_cstring_extend(&cmd, build->cflags);
    }

    okb_cstring_push(&cmd, ' ');
    okb_cstring_extend(&cmd, build->compile_out_flag);  // e.g. "-o" or "/Fo"
    okb_cstring_extend_cstr(&cmd, output_filename);

    okb_info("Compiling: %s", okb_cstring_as_cstr(cmd));
    if (okb_trace_err(err = okb_run(okb_cstring_as_cstr(cmd)))) goto error2;

error2:
    okb_cstring_deinit(&cmd);
error1:
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

        char const* this_filename = okb_fs_basename(build->argv[0]);

#ifdef _WIN32
        // Windows cleanup
        if (rebuild_state && strcmp(rebuild_state, "2") == 0) {
            // Move .okb_rebuild.pdb -> build.pdb
            {
                // TODO: Clean this up

                struct okb_cstring src = okb_cstring_init_with_cstr(this_filename);
                struct okb_cstring dest = okb_cstring_clone(build->build_out_filename);

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
                    err = okb_fs_remove_if_exists(okb_cstring_as_cstr(build->build_out_filename));
                    if (!err) {
                        err = okb_fs_rename(
                            this_filename, okb_cstring_as_cstr(build->build_out_filename)
                        );
                    }
                    if (!err) break;
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

        okb_cslist_push(&deps, okb_cstring_clone(build->build_c_filename));
        okb_cslist_extend(&deps, build->script_deps);

        struct okb_build_is_old_res res = okb_is_file_older_than_dependencies(
            okb_cstring_as_cstr(build->build_out_filename), deps
        );

        okb_cslist_deinit(&deps);

        if (err || !res.is_old) return err;
    }

    // Rebuild, run, and exit
    {
        char const* const tmp_build_filename =
            okb_cstr_ends_with(okb_cstring_as_cstr(build->build_out_filename), ".exe")
                ? ".okb_rebuild.exe"
                : ".okb_rebuild";

        struct okb_cstring cmd = okb_cstring_init();
        struct okb_cslist link_deps = okb_cslist_init();
        okb_cslist_push(&link_deps, okb_cstring_clone(build->build_c_filename));

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
    enum okb_err err = OKB_OK;

    // Generate .obj filename, and add it to list
    struct okb_cstring obj_filename = okb_cstring_clone(build->obj_dir);
    okb_cstring_push(&obj_filename, '/');
    okb_cstring_extend_cstr(&obj_filename, c_filename);
    okb_cstring_replace_ext(&obj_filename, "obj");
    okb_cslist_push(out_object_filenames, obj_filename);

    char const* const obj_cstr = okb_cstring_as_cstr(obj_filename);

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
