/**
 * @file build.c
 * @author your name (you@domain.com)
 * @brief Project build script
 * @version 0.1
 * @date 2023-11-04
 *
 * @copyright Copyright (c) 2023
 *
 */

#include "okbuild.h"

#define APP_NAME "example"

static void clean(void) {
    okb_info("Cleaning build files");

    okb_assert_ok(okb_fs_delete_glob("*.ilk"));
    okb_assert_ok(okb_fs_delete_glob("*.obj"));
    okb_assert_ok(okb_fs_delete_glob("*.pdb"));
    okb_assert_ok(okb_fs_delete_glob("*.d"));
}

static void run(char const* exe_filename, int argc, char* argv[]) {
    struct okb_cstring cmd = okb_cstring_init_with_cstr(exe_filename);
    okb_cstring_extend_cli_args(&cmd, argc, argv);
    (void)okb_run(okb_cstring_as_cstr(cmd));
    okb_cstring_deinit(&cmd);
}

int main(int argc, char* argv[]) {
    struct okb_build* build = okb_build_init(__FILE__, argc, argv);
    struct okb_cslist example_object_files = okb_cslist_init();

    if (okb_subcmd(build, "rebuild")) {
        build->force_rebuild = true;
    }

    // Rebuild build script if okbuild.h changes
    okb_build_add_script_dependency(build, "okbuild.h");
    okb_assert_ok(okb_rebuild_script(build));

    // Clean project directory
    if (okb_subcmd(build, "clean")) {
        clean();
        goto done;
    }

    // Compile project
    struct okb_cslist app_deps = okb_cslist_init();
    okb_cslist_push_cstr(&app_deps, APP_NAME ".h");
    okb_assert_ok(okb_compile_rule(&example_object_files, build, APP_NAME ".c", app_deps));
    okb_cslist_deinit(&app_deps);

    // Link project
    okb_assert_ok(okb_link_rule(build, APP_NAME, example_object_files));

    // Run project
    if (okb_subcmd(build, "run")) {
        run(APP_NAME, argc - 1, &argv[1]);
        goto done;
    }

done:
    okb_cslist_deinit(&example_object_files);
    okb_build_deinit(build);
}
