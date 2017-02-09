#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "elf_loader.h"
#include "wheelc/wheelc.h"

static bool read_file(const char *fname, void **buf, size_t *len)
{
    int fd = -1;
    struct stat st;
    char *tmp_buf;
    off_t pos;
    ssize_t read_bytes;

    if (stat(fname, &st) == -1) {
        LOG_ERR("fstat: error - %s", strerror(errno));
        return false;
    }
    if (st.st_size == 0) {
        LOG_ERR("fstat: error - st.st_size = 0");
        return false;
    }

    tmp_buf = malloc(st.st_size);
    if (tmp_buf == NULL) {
        LOG_ERR("out of memory when alloc size=%lu", st.st_size);
        return false;
    }

    fd = open(fname, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        LOG_ERR("open file %s error, %s", fname, strerror(errno));
        goto out_free;
    }

    pos = 0;
    while (pos < st.st_size) {
        read_bytes = read(fd, tmp_buf + pos, st.st_size - pos);
        if (read_bytes < 0) {
            LOG_ERR("read error - %s", strerror(errno));
            goto out_free;
        }
        if (read_bytes == 0)
            break;
        pos += read_bytes;
    }

    if (pos != st.st_size) {
        LOG_ERR("read file incomplete, read %lu, size=%lu", pos, st.st_size);
        goto out_free;
    }

    *buf = tmp_buf;
    *len = st.st_size;
    return true;

out_free:
    free(tmp_buf);
    if (fd >= 0)
        close(fd);
    return false;
}

int main(int argc, char *argv[])
{
    struct elf_module *m;
    void *bin;
    size_t len;
    const char *fname;
    const char *bname;

    if (argc != 3) {
        LOG_ERR("need one param");
        return 0;
    }

    fname = argv[1];
    bname = filename_from_path(fname);

    if (!read_file(fname, &bin, &len)) {
        free(bin);
        return 0;
    }

    m = load_elf_module(bname, bin, len);
    if (m == NULL) {
        free(bin);
        LOG_ERR("load_elf_module %s failed", bname);
        return 0;
    }

    free(bin);

    run_elf_module(m, argv[2]);

    LOG_INFO("module %s run done", m->name);

    return 0;
}
