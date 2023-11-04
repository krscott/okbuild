// Example build.c

#include "okbuild.h"

int main(int argc, char* argv[]) {
    struct build build = build_init();

    if (subcmd("rebuild", argc, argv)) {
        build.force_rebuild = true;
    }

    // Rebuild build script if okbuild.h changes
    build_add_script_dependency(&build, "okbuild.h");
    assert_ok(build_rebuild_script(&build, argc, argv));

    build_deinit(&build);
}
