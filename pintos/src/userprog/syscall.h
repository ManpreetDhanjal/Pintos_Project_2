#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void
verifyAddress(const void *uaddr);
typedef int pid_t;
#endif /* userprog/syscall.h */
