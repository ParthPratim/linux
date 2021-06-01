#ifndef _DCE_TYPES_H_
#define _DCE_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

struct SimTask;

struct SimSysFile {
};

/* Add structure list */
enum SimDevFlags {
  SIM_DEV_NOARP         = (1 << 0),
  SIM_DEV_POINTTOPOINT  = (1 << 1),
  SIM_DEV_MULTICAST     = (1 << 2),
  SIM_DEV_BROADCAST     = (1 << 3),
};

enum SimSysFileFlags {
	SIM_SYS_FILE_READ  = 1 << 0,
	SIM_SYS_FILE_WRITE = 1 << 1,
};

struct SimSysIterator {
  void (*report_start_dir)(const struct SimSysIterator *iter,
        const char *dirname);
  void (*report_end_dir)(const struct SimSysIterator *iter);
  void (*report_file)(const struct SimSysIterator *iter,
      const char *filename,
      int flags, struct SimSysFile *file);
};

struct SimDevicePacket {
 void *buffer;
 void *token;
};

#ifdef __cplusplus
}
#endif

struct DceKernel;
struct DceSocket;
#endif /* DCE_TYPES_SEEN*/

