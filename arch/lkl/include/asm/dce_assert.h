#include <asm/host_ops.h>

#ifndef DCE_ASSERT_H
#define DCE_ASSERT_H

#define lib_assert(v) {							\
		while (!(v)) {						\
			lkl_printf("Assert failed %s:%u \"" #v "\"\n",	\
				__FILE__, __LINE__);			\
			char *p = 0;					\
			*p = 1;						\
		}							\
	}


#endif /* DCE_ASSERT_H */