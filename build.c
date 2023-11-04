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

static void clean(void) {
    log_info("Cleaning build files");

    assert_ok(glob_delete("*.ilk"));
    assert_ok(glob_delete("*.obj"));
    assert_ok(glob_delete("*.pdb"));
    assert_ok(glob_delete("*.d"));
}

static void run(char const* exe_filename, int argc, char* argv[]) {
    struct strbuf cmd = strbuf_init();
    strbuf_extend_cstr(&cmd, exe_filename);
    strbuf_extend_cli_args(&cmd, argc, argv);
    (void)run_command(strbuf_as_cstr(cmd));
    strbuf_deinit(&cmd);
}

int main(int argc, char* argv[]) {
    struct build build = build_init();

    if (subcmd("rebuild", argc, argv)) {
        build.force_rebuild = true;
    }

    // Rebuild build script if okbuild.h changes
    build_add_script_dependency(&build, "okbuild.h");
    assert_ok(build_rebuild_script(&build, argc, argv));

    // Clean project directory
    if (subcmd("clean", argc, argv)) {
        clean();
        goto done;
    }

    // Compile project
    char const* example_obj = "example.obj";
    char const* example_c_deps[] = {"build.exe", "build.c"};
    assert_ok(compile_rule(&build, example_obj, "example.c", slice_from_array(example_c_deps)));

    // Link project
    char const* example_exe = exe_filename(build, "example");
    char const* example_exe_deps[] = {example_obj};
    assert_ok(link_rule(&build, example_exe, slice_from_array(example_exe_deps)));

    // Run project
    if (subcmd("run", argc, argv)) {
        run(example_exe, argc - 1, &argv[1]);
        goto done;
    }

done:
    build_deinit(&build);
}
