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

#define STR(x) #x
#define STR_VALUE(x) STR(x)
#define VA_FIRST(x, ...) x

#define countof(a) (sizeof(a) / sizeof(a[0]))

// Logging

// All modern compilers support ##__VA_ARGS__
// msvc does not handle __VA_ARGS__ correctly without ##
#ifdef __clang__
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif

#ifndef OKBUILD_LOG_FILE
#define OKBUILD_LOG_FILE stderr
#endif  // OKBUILD_LOG_FILE

#ifndef OKBUILD_LOG
#define OKBUILD_LOG(lvl, fmt, ...) fprintf(OKBUILD_LOG_FILE, "[" lvl "] " fmt "\n", ##__VA_ARGS__)
#endif

#define log_debug(fmt, ...) OKBUILD_LOG("DEBUG", fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) OKBUILD_LOG("INFO", fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) OKBUILD_LOG("WARN", fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) OKBUILD_LOG("ERROR", fmt, ##__VA_ARGS__)
#define log_fatal(fmt, ...) OKBUILD_LOG("FATAL", fmt, ##__VA_ARGS__)

// Error

enum okb_err {
    ERR_OK,
    ERR_PANIC,
    ERR_FILE_DOES_NOT_EXIST,
    ERR_ERRNO,
    ERR_WINDOWS,
    ERR_SUBPROC,
};

OKBAPI char* okb_err_cstr(enum okb_err err) {
    switch (err) {
        case ERR_OK:
            return "No error";
        case ERR_PANIC:
            return "okbuild panic";
        case ERR_FILE_DOES_NOT_EXIST:
            return "File does not exist";
        case ERR_ERRNO:
            return strerror(errno);
        case ERR_WINDOWS:
            return "Windows error";
        case ERR_SUBPROC:
            return "Sub-process error";
        default:
            return "Unknown error";
    }
}

#define okb_trace_err(err) okb_trace_err_((err), __FILE__, __LINE__)
OKBAPI enum okb_err okb_trace_err_(enum okb_err err, char const* file, int line) {
    if (err) {
        log_error("%s:%d %s", file, line, okb_err_cstr(err));
    }
    return err;
}

#define assert_ok(err) okb_assert_ok_((err), __FILE__, __LINE__)
OKBAPI void okb_assert_ok_(enum okb_err err, char const* file, int line) {
    if (err) {
        log_fatal("%s:%d %s", file, line, okb_err_cstr(err));
        assert(false); /* Trigger debugger */
        exit((int)err);
    }
}

#define panic(msg)                                                                           \
    do {                                                                                     \
        fputs("Panic at " __FILE__ ":" STR_VALUE(__LINE__) ": " msg "\n", OKBUILD_LOG_FILE); \
        assert(false); /* Trigger debugger */                                                \
        exit(ERR_PANIC);                                                                     \
    } while (1)

// Util functions

OKBAPI size_t checked_mul(size_t a, size_t b) {
    size_t result = (size_t)(a) * (size_t)(b);
    if (a > 1 && result / a != b) panic("multiply overflow");
    return result;
}

OKBAPI ptrdiff_t next_power_of_2(ptrdiff_t n) {
    ptrdiff_t k = 1;
    while (k < n) k *= 2;
    return k;
}

OKBAPI bool cstr_contains_char(char const* s, char c) {
    while (*s) {
        if (*s == c) return true;
        ++s;
    }
    return false;
}

OKBAPI bool cstr_ends_with(char const* s, char const* end) {
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
    void* ptr = OKBUILD_MALLOC(checked_mul(nelem, elsize));
    if (!ptr) panic("out of memory");
    return ptr;
}

OKBAPI void* okb_realloc(void* ptr, size_t nelem, size_t elsize) {
    void* new_ptr = OKBUILD_REALLOC(ptr, checked_mul(nelem, elsize));
    if (!new_ptr) panic("out of memory");
    return new_ptr;
}

OKBAPI void okb_free(void* ptr) { OKBUILD_FREE(ptr); }

// Dynamic array

struct vec {
    void* buf;
    ptrdiff_t element_size;
    ptrdiff_t len;
    ptrdiff_t cap;
};

#define vec_init(T) vec_init_(sizeof(T))
OKBAPI struct vec vec_init_(ptrdiff_t element_size) {
    assert(element_size > 0);
    return (struct vec){.element_size = element_size};
}

OKBAPI void vec_deinit(struct vec* vec) {
    assert(vec);
    if (vec->buf) okb_free(vec->buf);
}

OKBAPI void vec_clear(struct vec* vec) {
    assert(vec);
    vec->len = 0;
}

OKBAPI void vec_reserve(struct vec* vec, ptrdiff_t additional) {
    assert(vec);
    if (additional <= 0) return;
    ptrdiff_t const initial_capacity = 8;
    ptrdiff_t new_cap = vec->len + additional;
    new_cap = new_cap > initial_capacity ? next_power_of_2(new_cap) : initial_capacity;
    if (new_cap < vec->cap) return;
    vec->buf = okb_realloc(vec->buf, new_cap, vec->element_size);
    vec->cap = new_cap;
}

#define vec_extend(T, vec, n) ((T*)vec_extend_((vec), (n), sizeof(T)))
OKBAPI void* vec_extend_(struct vec* vec, ptrdiff_t n, ptrdiff_t element_size) {
    assert(vec);
    assert(element_size == vec->element_size);
    vec_reserve(vec, n);
    void* out = (void*)((uintptr_t)vec->buf + vec->len * vec->element_size);
    vec->len += n;
    return out;
}

#define vec_push(T, vec) ((T*)vec_push_((vec), sizeof(T)))
OKBAPI void* vec_push_(struct vec* vec, ptrdiff_t element_size) {
    assert(vec);
    assert(element_size == vec->element_size);
    vec_reserve(vec, 1);
    return (void*)((uintptr_t)vec->buf + (vec->len++) * vec->element_size);
}

#define vec_pop(T, vec) ((T*)vec_pop_((vec), sizeof(T)))
OKBAPI void* vec_pop_(struct vec* vec, ptrdiff_t element_size) {
    assert(vec);
    assert(element_size == vec->element_size);
    if (vec->len == 0) return 0;
    return (void*)((uintptr_t)vec->buf + (--vec->len) * vec->element_size);
}

// Slice

struct slice {
    void const* ptr;
    ptrdiff_t element_size;
    ptrdiff_t len;
};

OKBAPI struct slice slice_from_vec(struct vec vec) {
    return (struct slice){
        .ptr = vec.buf,
        .element_size = vec.element_size,
        .len = vec.len,
    };
}

#define slice_from_array(a) slice_from_array_((a), countof(a), sizeof(a[0]))
OKBAPI struct slice slice_from_array_(void const* arr, ptrdiff_t len, ptrdiff_t size) {
    assert(arr);
    assert(len >= 0);
    assert(size > 0);
    return (struct slice){
        .ptr = arr,
        .element_size = size,
        .len = len,
    };
}

#define slice_of_one(x) slice_of_one_((x), sizeof(*(x)))
OKBAPI struct slice slice_of_one_(void const* item, ptrdiff_t size) {
    assert(item);
    assert(size > 0);
    return (struct slice){
        .ptr = item,
        .element_size = size,
        .len = 1,
    };
}

#define slice_pop_front(T, slice) ((T*)slice_pop_front_((slice), sizeof(T)))
OKBAPI void const* slice_pop_front_(struct slice* slice, ptrdiff_t element_size) {
    assert(slice);
    assert(element_size == slice->element_size);
    if (slice->len == 0) return 0;
    void const* out = slice->ptr;
    slice->ptr = (void*)((uintptr_t)slice->ptr + slice->element_size);
    --slice->len;
    return out;
}

#define slice_pop_back(T, slice) ((T*)slice_pop_back_((slice), sizeof(T)))
OKBAPI void const* slice_pop_back_(struct slice* slice, ptrdiff_t element_size) {
    assert(slice);
    assert(element_size == slice->element_size);
    if (slice->len == 0) return 0;
    return (void const*)((uintptr_t)slice->ptr + (--slice->len) * slice->element_size);
}

// String Slice

struct str {
    char const* ptr;
    ptrdiff_t len;
};

OKBAPI struct str str_from_cstr(char const* cstr) {
    return (struct str){.ptr = cstr, .len = strlen(cstr)};
}

OKBAPI struct str str_strip_file_ext(struct str path) {
    ptrdiff_t len = path.len;
    // Condition is `len > 1` to not strip extension-less filenames starting with '.'
    for (; len > 1; len--) {
        if (path.ptr[len - 1] == '.') {
            len = len - 1;
            break;
        }
    }

    // Filenames starting with '.' are extension-less.
    char last_char = len > 0 ? path.ptr[len - 1] : 0;
    if (!last_char || last_char == '\'' || last_char == '/') {
        len = path.len;
    }

    return (struct str){
        .ptr = path.ptr,
        .len = len,
    };
}

// Dynamic string buffer

struct strbuf {
    struct vec vec;
};

OKBAPI struct strbuf strbuf_init(void) {
    return (struct strbuf){
        .vec = vec_init(char),
    };
}

OKBAPI void strbuf_deinit(struct strbuf* strbuf) { vec_deinit(&strbuf->vec); }

OKBAPI ptrdiff_t strbuf_len(struct strbuf strbuf) {
    return strbuf.vec.len == 0 ? 0 : strbuf.vec.len - 1;
}

OKBAPI char const* strbuf_as_cstr(struct strbuf strbuf) {
    if (strbuf_len(strbuf) == 0) return "";
    return (char const*)strbuf.vec.buf;
}

OKBAPI void strbuf_clear(struct strbuf* strbuf) { vec_clear(&strbuf->vec); }

OKBAPI void strbuf_reserve(struct strbuf* strbuf, ptrdiff_t additional) {
    // If string is currently empty, add 1 for the null terminator.
    if (strbuf->vec.len == 0) additional += 1;
    vec_reserve(&strbuf->vec, additional);
}

OKBAPI char const* strbuf_pop(struct strbuf* strbuf) {
    if (strbuf_len(*strbuf) == 0) return 0;
    return vec_pop(char const, &strbuf->vec);
}

OKBAPI void strbuf_push(struct strbuf* strbuf, char c) {
    // Remove null terminator
    (void)vec_pop(char, &strbuf->vec);

    // Add char
    *vec_push(char, &strbuf->vec) = c;

    // Add null terminator
    *vec_push(char, &strbuf->vec) = '\0';
}

OKBAPI void strbuf_extend(struct strbuf* strbuf, struct str str) {
    // Remove null terminator
    (void)vec_pop(char, &strbuf->vec);

    // Add str
    memmove(vec_extend(char, &strbuf->vec, str.len), str.ptr, str.len);

    // Add null terminator
    *vec_push(char, &strbuf->vec) = '\0';
}

OKBAPI void strbuf_extend_cstr(struct strbuf* strbuf, char const* cstr) {
    strbuf_extend(strbuf, str_from_cstr(cstr));
}

OKBAPI void strbuf_extend_cli_args(struct strbuf* cmd, int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        strbuf_extend_cstr(cmd, " \"");
        strbuf_extend_cstr(cmd, argv[i]);
        strbuf_push(cmd, '"');
    }
}

// Filesystem

OKBAPI char const* okb_fs_basename(char const* path) {
#ifdef _MSC_BUILD
    static char scratch[100];
    _splitpath_s(path, NULL, 0, NULL, 0, scratch, sizeof(scratch), NULL, 0);
    char const* out = strstr(path, scratch);
    if (!out) {
        log_warn("Could not find basename of %s", path);
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
    struct stat st;
    if (stat(filename, &st)) {
        if (errno == ENOENT) return (struct okb_fs_stat_res){.err = ERR_FILE_DOES_NOT_EXIST};

        log_error("`stat(\"%s\")`: %s (errno=%d)", filename, strerror(errno), errno);
        return (struct okb_fs_stat_res){.err = ERR_ERRNO};
    }
    return (struct okb_fs_stat_res){.stat = st};
}

OKBAPI bool okb_fs_exists(char const* filename) { return !okb_fs_stat(filename).err; }

OKBAPI enum okb_err okb_fs_remove(char const* filename) {
    // log_debug("`remove(\"%s\")`", filename);
    if (remove(filename)) {
        log_error("`remove(\"%s\")`: %s (errno=%d)", filename, strerror(errno), errno);
        return ERR_ERRNO;
    }
    return ERR_OK;
}

OKBAPI enum okb_err okb_fs_remove_if_exists(char const* filename) {
    // log_debug("`okb_fs_remove_if_exists(\"%s\")`", filename);
    if (okb_fs_exists(filename)) return okb_fs_remove(filename);
    return ERR_OK;
}

OKBAPI enum okb_err okb_fs_rename(char const* src, char const* dest) {
    // log_debug("`rename(\"%s\", \"%s\")`", src, dest);
    if (rename(src, dest)) {
        log_error("`rename(\"%s\", \"%s\")`: %s (errno=%d)", src, dest, strerror(errno), errno);
        return ERR_ERRNO;
    }
    return ERR_OK;
}

struct okb_fs_fopen_res {
    FILE* file;
    enum okb_err err;
};

OKBAPI struct okb_fs_fopen_res okb_fs_open(char const* filename, char const* mode) {
    FILE* fp = fopen(filename, mode);
    if (!fp) {
        log_error("fopen(\"%s\", \"%s\"): %s (errno=%d)", filename, mode, strerror(errno), errno);
        return (struct okb_fs_fopen_res){.err = ERR_ERRNO};
    }
    return (struct okb_fs_fopen_res){.file = fp};
}

OKBAPI enum okb_err okb_fs_close(FILE* fp) {
    if (fclose(fp)) {
        log_error("Could not close: %s (errno=%d)", strerror(errno), errno);
        return ERR_ERRNO;
    }
    return ERR_OK;
}

OKBAPI enum okb_err okb_fs_puts(char const* s, FILE* fp) {
    if (fputs(s, fp) == EOF) {
        log_error("File write: %s (errno=%d)", strerror(errno), errno);
        return ERR_ERRNO;
    }
    return ERR_OK;
}

OKBAPI enum okb_err okb_fs_printf(FILE* fp, char const* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int bytes = vfprintf(fp, fmt, args);
    va_end(args);
    if (bytes < 0) {
        if (fp != stderr) {
            log_error("File write: %s (errno=%d)", strerror(errno), errno);
        }
        return ERR_ERRNO;
    }
    return ERR_OK;
}

OKBAPI enum okb_err okb_fs_copy(char const* src, char const* dest) {
#if defined(_WIN32)
    if (!CopyFileA(src, dest, 0)) {
        log_error("`CopyFile(\"%s\", \"%s\", 0)` failed (error=%lu)", src, dest, GetLastError());
        return ERR_WINDOWS;
    }
    return ERR_OK;
#elif defined(FICLONE)
    enum okb_err err = ERR_OK;

    int fd_src = -1;
    int fd_dest = -1;

    fd_src = open(src, O_RDONLY);
    if (fd_src < 0) {
        log_error("open(\"%s\", O_RDONLY): %s (errno=%d)", src, strerror(errno), errno);
        err = ERR_ERRNO;
        goto error;
    }
    fd_dest = open(dest, O_WRONLY | O_CREAT);
    if (fd_dest < 0) {
        log_error("open(\"%s\", O_WRONLY): %s (errno=%d)", dest, strerror(errno), errno);
        err = ERR_ERRNO;
        goto error;
    }
    if (ioctl(dest_fd, FICLONE, src_fd)) {
        log_error("ioctl(%s, FICLONE, %s): %s (errno=%d)", dest, src, strerror(errno), errno);
        err = ERR_ERRNO;
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
            log_error("%s: write error during copy", dest);
            res.err = ERR_ERRNO;
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

struct glob_handle {
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

OKBAPI struct glob_handle glob_init(char const* const pattern) {
    return (struct glob_handle){
        .error = 0,
        .pattern = pattern,
#ifdef _WIN32
        .handle = -1,
#else
        .i = 0,
#endif
    };
}

OKBAPI enum okb_err glob_deinit(struct glob_handle* glob) {
    glob->pattern = NULL;

#ifdef _WIN32
    if (glob->handle != -1) _findclose(glob->handle);
    glob->handle = -1;

    if (glob->error) {
        log_error("glob error: %s", strerror(glob->error));
        return ERR_ERRNO;
    }
#else
    globfree(&glob->buf);

    if (glob->error) {
        log_error("glob error (%d)", glob->error);
        errno = glob->error;
        return ERR_ERRNO;
    }
#endif

    return ERR_OK;
}

OKBAPI char const* glob_next(struct glob_handle* glob) {
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

OKBAPI enum okb_err glob_delete(char const* const pattern) {
    struct glob_handle glob = glob_init(pattern);
    for (char const* fname; (fname = glob_next(&glob));) {
        log_info("Deleting '%s'", fname);
        (void)okb_fs_remove(fname);
    }
    return glob_deinit(&glob);
}

// System command

struct okb_system_res {
    ptrdiff_t exit_code;
    enum okb_err err;
};

OKBAPI struct okb_system_res okb_system(char const* cmd) {
    ptrdiff_t cmd_err = system(cmd);
    switch (cmd_err) {
        case -1:
            log_error("system(\"%s\"): %s (errno=%d)", cmd, strerror(errno), errno);
            return (struct okb_system_res){.err = ERR_ERRNO};
        case -1073741819:  // Windows 0xC0000005: Access Violation
            log_error("system(\"%s\"): Segmentation Fault", cmd);
            return (struct okb_system_res){.err = ERR_SUBPROC};
        case -1073740940:  // Windows 0xC0000374: Heap Corruption
            log_error("system(\"%s\"): Heap Corruption", cmd);
            return (struct okb_system_res){.err = ERR_SUBPROC};
        default:
            if (cmd_err < 0) {
                log_error("system(\"%s\") returned %lld", cmd, cmd_err);
                return (struct okb_system_res){.err = ERR_SUBPROC};
            }
            return (struct okb_system_res){.exit_code = cmd_err};
    }
}

OKBAPI enum okb_err run_command(char const* cmd) {
    struct okb_system_res res = okb_system(cmd);
    if (res.err) return res.err;
    if (res.exit_code != 0) {
        log_error("Command returned non-zero exit code: %lld", res.exit_code);
        return ERR_SUBPROC;
    }
    return ERR_OK;
}

// Build

enum build_compiler_kind {
    COMPILER_UNKNOWN,
    COMPILER_CLANG,
    COMPILER_GCC,
    COMPILER_MSVC,
};

#define OKB_ENVVAR_REBUILD "OKBUILD_REBUILD"

#define DEFAULT_CONFIG_FILE "config.txt"
#define DEFAULT_BUILD_C "build.c"

#if defined(__zig_cc__)
// `__zig_cc__` must be provided manually when running zig cc
#define DEFAULT_COMPILER "zig cc"
#define DEFAULT_COMPILER_KIND COMPILER_CLANG
#elif defined(__clang__)
#define DEFAULT_COMPILER "clang"
#define DEFAULT_COMPILER_KIND COMPILER_CLANG
#elif defined(__GNUC__)
#define DEFAULT_COMPILER "gcc"
#define DEFAULT_COMPILER_KIND COMPILER_GCC
#elif defined(_MSC_BUILD)
#define DEFAULT_COMPILER "cl"
#define DEFAULT_COMPILER_KIND COMPILER_MSVC
#else
#define DEFAULT_COMPILER ""
#define DEFAULT_COMPILER_KIND COMPILER_UNKNOWN
#endif

#if defined(_MSC_BUILD)
#define DEFAULT_CFLAGS "/D /Wall /Zi /Zc:preprocessor"
#elif defined(__zig_cc__)
// `__zig_cc__` must be provided manually when running zig cc
#define DEFAULT_CFLAGS "-D__zig_cc__ -Wall -Wextra -pedantic -Werror -g"
#else
#define DEFAULT_CFLAGS "-Wall -Wextra -pedantic -Werror -g"
#endif

#ifdef _WIN32
#define DEFAULT_OUT_FILENAME "build.exe"
#define DEFAULT_IS_WIN_EXE true
#else
#define DEFAULT_OUT_FILENAME "build"
#define DEFAULT_IS_WIN_EXE false
#endif

struct build {
    char const* config_filename;
    char const* build_c_filename;
    char const* build_out_filename;
    char const* compiler;
    char const* cflags;
    enum build_compiler_kind compiler_kind;
    bool force_rebuild;
    bool target_is_win_exe;
    struct vec build_c_deps;
};

OKBAPI struct build build_init(void) {
    return (struct build){
        .config_filename = DEFAULT_CONFIG_FILE,
        .build_c_filename = DEFAULT_BUILD_C,
        .build_out_filename = DEFAULT_OUT_FILENAME,
        .compiler = DEFAULT_COMPILER,
        .cflags = DEFAULT_CFLAGS,
        .compiler_kind = DEFAULT_COMPILER_KIND,
        .force_rebuild = false,
        .target_is_win_exe = DEFAULT_IS_WIN_EXE,
        .build_c_deps = vec_init(char*),
    };
}

OKBAPI void build_deinit(struct build* build) { vec_deinit(&build->build_c_deps); }

#define exe_filename(build, basename) ((build).target_is_win_exe ? (basename ".exe") : (basename))

OKBAPI void build_add_script_dependency(struct build* build, char const* filename) {
    *vec_push(char const*, &build->build_c_deps) = filename;
}

OKBAPI void path_replace_ext(struct strbuf* strbuf, char const* filename, char const* new_ext) {
    strbuf_clear(strbuf);
    strbuf_extend(strbuf, str_strip_file_ext(str_from_cstr(filename)));
    strbuf_push(strbuf, '.');
    strbuf_extend(strbuf, str_from_cstr(new_ext));
}

struct build_is_old_res {
    bool is_old;
    enum okb_err err;
};

OKBAPI struct build_is_old_res is_file_older_than_time(char const* filename, time_t mtime) {
    struct okb_fs_stat_res stat_res = okb_fs_stat(filename);
    if (stat_res.err == ERR_FILE_DOES_NOT_EXIST) log_error("File does not exist: %s", filename);
    if (stat_res.err) return (struct build_is_old_res){.err = stat_res.err};
    return (struct build_is_old_res){.is_old = stat_res.stat.st_mtime > mtime};
}

OKBAPI struct build_is_old_res
is_file_older_than_dependencies(char const* filename, struct slice dependencies) {
    assert(dependencies.len > 0);
    assert(dependencies.element_size == sizeof(char*));

    struct okb_fs_stat_res stat_res = okb_fs_stat(filename);
    if (stat_res.err == ERR_FILE_DOES_NOT_EXIST) return (struct build_is_old_res){.is_old = true};
    if (okb_trace_err(stat_res.err)) return (struct build_is_old_res){.err = stat_res.err};

    time_t filename_mtime = stat_res.stat.st_mtime;

    struct build_is_old_res res = (struct build_is_old_res){.is_old = false};

    for (char const** dep; (dep = slice_pop_front(char const*, &dependencies));) {
        if (cstr_contains_char(*dep, '*')) {
            // Compare all files matching glob pattern
            struct glob_handle glob = glob_init(*dep);
            for (char const* fname; (fname = glob_next(&glob));) {
                res = is_file_older_than_time(fname, filename_mtime);
                if (res.err || res.is_old) break;
            }
            enum okb_err err = okb_trace_err(glob_deinit(&glob));
            if (err) {
                res.err = err;
                break;
            }
            if (res.is_old) break;
        } else {
            // Compare single file
            res = is_file_older_than_time(*dep, filename_mtime);
            if (res.err || res.is_old) break;
        }
    }

    return res;
}

OKBAPI enum okb_err
build_link(struct build const* build, char const* output_filename, struct slice input_filenames) {
    assert(input_filenames.len > 0);
    assert(input_filenames.element_size == sizeof(char*));

    enum okb_err err = ERR_OK;

    struct strbuf cmd = strbuf_init();
    struct strbuf stale_filename = strbuf_init();

    strbuf_extend_cstr(&cmd, build->compiler);

    for (char const** fname; (fname = slice_pop_front(char const*, &input_filenames));) {
        strbuf_push(&cmd, ' ');
        strbuf_extend_cstr(&cmd, *fname);
    }

    strbuf_push(&cmd, ' ');
    strbuf_extend_cstr(&cmd, build->cflags);

    if (build->compiler_kind == COMPILER_MSVC) {
        strbuf_extend_cstr(&cmd, " /link /out:");
    } else {
        strbuf_extend_cstr(&cmd, " -o");
    }
    strbuf_extend_cstr(&cmd, output_filename);

    // Remove stale .pdb file
    path_replace_ext(&stale_filename, output_filename, "pdb");
    if (okb_trace_err(err = okb_fs_remove_if_exists(strbuf_as_cstr(stale_filename)))) goto error;

    // Remove stale .ilk file
    path_replace_ext(&stale_filename, output_filename, "ilk");
    if (okb_trace_err(err = okb_fs_remove_if_exists(strbuf_as_cstr(stale_filename)))) goto error;

    log_info("Linking: %s", strbuf_as_cstr(cmd));
    if (okb_trace_err(err = run_command(strbuf_as_cstr(cmd)))) goto error;

error:
    strbuf_deinit(&stale_filename);
    strbuf_deinit(&cmd);

    return err;
}

OKBAPI enum okb_err
build_compile(struct build const* build, char const* output_filename, char const* input_filename) {
    enum okb_err err = ERR_OK;

    struct strbuf cmd = strbuf_init();

    strbuf_extend_cstr(&cmd, build->compiler);

    if (build->compiler_kind != COMPILER_MSVC) {
        strbuf_extend_cstr(&cmd, " -c");
    }

    strbuf_push(&cmd, ' ');
    strbuf_extend_cstr(&cmd, input_filename);

    strbuf_push(&cmd, ' ');
    strbuf_extend_cstr(&cmd, build->cflags);

    if (build->compiler_kind == COMPILER_MSVC) {
        strbuf_extend_cstr(&cmd, " /Fo");
    } else {
        strbuf_extend_cstr(&cmd, " -o");
    }
    strbuf_extend_cstr(&cmd, output_filename);

    log_info("Compiling: %s", strbuf_as_cstr(cmd));
    if (okb_trace_err(err = run_command(strbuf_as_cstr(cmd)))) goto error;

error:
    strbuf_deinit(&cmd);

    return err;
}

OKBAPI enum okb_err build_rebuild_script(struct build* build, int argc, char* argv[]) {
    enum okb_err err = ERR_OK;

    // Check if we are in a child process
    {
        char const* rebuild_state = getenv(OKB_ENVVAR_REBUILD);

        // If already rebuilt, then return
        if (rebuild_state && strcmp(rebuild_state, "1") == 0) goto done;

        char const* this_filename = okb_fs_basename((char*)argv[0]);

#ifdef _WIN32
        // Windows cleanup
        if (rebuild_state && strcmp(rebuild_state, "2") == 0) {
            // Move .okb_rebuild.pdb -> build.pdb
            {
                struct strbuf src = strbuf_init();
                struct strbuf dest = strbuf_init();

                path_replace_ext(&src, this_filename, "pdb");
                path_replace_ext(&dest, build->build_out_filename, "pdb");

                // delete old build.pdb
                if ((err = okb_fs_remove_if_exists(strbuf_as_cstr(dest)))) goto win_cleanup_error;

                // rename .okb_rebuild.pdb -> build.pdb
                if (okb_fs_exists(strbuf_as_cstr(src))) {
                    if ((err = okb_fs_rename(strbuf_as_cstr(src), strbuf_as_cstr(dest))))
                        goto win_cleanup_error;
                }

                path_replace_ext(&src, this_filename, "ilk");
                path_replace_ext(&dest, build->build_out_filename, "ilk");

                // delete old build.ilk
                if ((err = okb_fs_remove_if_exists(strbuf_as_cstr(dest)))) goto win_cleanup_error;

                // rename .okb_rebuild.ilk -> build.ilk
                if (okb_fs_exists(strbuf_as_cstr(src))) {
                    if ((err = okb_fs_rename(strbuf_as_cstr(src), strbuf_as_cstr(dest))))
                        goto win_cleanup_error;
                }

            win_cleanup_error:
                strbuf_deinit(&dest);
                strbuf_deinit(&src);

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
        struct build_is_old_res res;
        struct vec deps = vec_init(char const*);

        // Check if main build script is out of date
        res = is_file_older_than_dependencies(
            build->build_out_filename, slice_of_one(&build->build_c_filename)
        );
        if ((err = res.err) || res.is_old) goto outdated_check_done;

        // Check if other build script dependencies are out of date
        res = is_file_older_than_dependencies(
            build->build_out_filename, slice_from_vec(build->build_c_deps)
        );
        if ((err = res.err) || res.is_old) goto outdated_check_done;

    outdated_check_done:
        vec_deinit(&deps);

        if (err || !res.is_old) return err;
    }

    // Rebuild, run, and exit
    {
        char const* const tmp_build_filename =
            cstr_ends_with(build->build_out_filename, ".exe") ? ".okb_rebuild.exe" : ".okb_rebuild";

        struct strbuf cmd = strbuf_init();

        log_info("Rebuilding build script");

        // Build temporary build binary
        if (okb_trace_err(
                err = build_link(build, tmp_build_filename, slice_of_one(&build->build_c_filename))
            ))
            goto rebuild_error;

        // Run temporary build binary
        putenv(OKB_ENVVAR_REBUILD "=1");
        strbuf_extend_cstr(&cmd, tmp_build_filename);

        // Add CLI arguments
        strbuf_extend_cli_args(&cmd, argc, argv);

        if (okb_trace_err(err = run_command(strbuf_as_cstr(cmd)))) goto rebuild_error;

#ifdef _WIN32
        // Spawn another process to overwrite real build binary with temporary
        putenv(OKB_ENVVAR_REBUILD "=2");
        strbuf_clear(&cmd);
        strbuf_extend_cstr(&cmd, "start /b ");
        strbuf_extend_cstr(&cmd, tmp_build_filename);
        if (okb_trace_err(err = run_command(strbuf_as_cstr(cmd)))) goto rebuild_error;
#else
        // Overwrite real build binary with temporary
        if (okb_trace_err(err = okb_fs_remove_if_exists(build->build_out_filename)))
            goto rebuild_error;
        if (okb_trace_err(err = okb_fs_rename(this_filename, build->build_out_filename)))
            goto rebuild_error;
#endif
        exit(0);

    rebuild_error:
        strbuf_deinit(&cmd);
    }

done:
    return err;
}

OKBAPI enum okb_err compile_rule(
    struct build const* build,
    char const* obj_filename,
    char const* c_filename,
    struct slice dependency_filenames
) {
    if (!build->force_rebuild) {
        struct build_is_old_res res =
            is_file_older_than_dependencies(obj_filename, slice_of_one(&c_filename));
        if (res.err) return res.err;

        if (!res.is_old) res = is_file_older_than_dependencies(obj_filename, dependency_filenames);
        if (res.err) return res.err;

        if (!res.is_old) return ERR_OK;
    }
    return build_compile(build, obj_filename, c_filename);
}

OKBAPI enum okb_err
link_rule(struct build const* build, char const* exe_filename, struct slice obj_filenames) {
    if (!build->force_rebuild) {
        struct build_is_old_res res = is_file_older_than_dependencies(exe_filename, obj_filenames);
        if (res.err) return res.err;
        if (!res.is_old) return ERR_OK;
    }
    return build_link(build, exe_filename, obj_filenames);
}

OKBAPI bool subcmd(char const* const cmd, int argc, char* argv[]) {
    if (argc < 2) return false;
    return strcmp(cmd, argv[1]) == 0;
}

#endif  // OKBUILD_H_
