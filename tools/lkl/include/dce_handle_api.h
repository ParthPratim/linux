#ifndef DCE_HANDLE_API_H
#define DCE_HANDLE_API_H

#include <linux/types.h>
#include "dce-types.h"

/*
 * APIs to access DceHandle function
 * from Linux kernel.
 *
 * These APIs helps to avoid the use
 * global DceHandle (g_dceHandle) object
 * inside LKL.
 *
 * The objective of these APIs is
 * provide access to DceHandle functions
 * all across the Dce file inside the LKL.
 */

int lib_vprintf(const char *str, va_list args);
void *lib_malloc(unsigned long size);
void lib_free(void *buffer);
void *lib_memcpy(void *dst, const void *src, unsigned long size);
void *lib_memset(void *dst, char value, unsigned long size);
int dce_sem_init (sem_t *sem, int pshared, unsigned int value);
void dce_sem_destroy (sem_t *sem);
void dce_sem_post (sem_t *sem);
int dce_sem_wait (sem_t *sem);
void dce_panic ();
int dce_pthread_mutexattr_init (pthread_mutexattr_t *attr);
int dce_pthread_mutexattr_settype (pthread_mutexattr_t *attribute, int  kind);
int dce_pthread_mutex_unlock (pthread_mutex_t *mutex);
int dce_pthread_mutex_lock (pthread_mutex_t *mutex);
int dce_pthread_mutex_destroy (pthread_mutex_t *mutex);
int dce_pthread_mutex_init (pthread_mutex_t *mutex, const pthread_mutexattr_t *attribute);


#endif /* DCE_HANDLE_API_H */

