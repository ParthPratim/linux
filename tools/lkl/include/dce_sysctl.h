#include "dce-types.h"


void dce_sys_iterate_files(const struct SimSysIterator *iter);

int dce_sys_file_read(const struct SimSysFile *file, char *buffer, int size, int offset);

int dce_sys_file_write(const struct SimSysFile *file, const char *buffer, int size, int offset);