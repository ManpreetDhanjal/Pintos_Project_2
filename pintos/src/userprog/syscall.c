#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
static void syscall_handler (struct intr_frame *);
struct lock syscall_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&(syscall_lock));
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  if(esp==NULL || esp <= PHYS_BASE){
  	  exit(-1);
  }
  lock_acquire(&syscall_lock);
  int sys_code = *(int*)f->esp;
  switch(sys_code)
   {
   	case SYS_HALT: 
   	shutdown_power_off();
   	printf("Choice is 1");
    break;

    case SYS_EXIT: 
    printf("Choice is 2");
    break;

    case SYS_WAIT: 
    printf("Choice is 3");
    break;

    case SYS_CREATE: 
    printf("Choice is 3");
    break;

    case SYS_REMOVE: 
    printf("Choice is 3");
    break;

    case SYS_FILESIZE: 
    printf("Choice is 3");
    break;

    case SYS_WRITE: 
    printf("Choice is 3");
    break;

    case SYS_SEEK: 
    printf("Choice is 3");
    break;

    case SYS_TELL: 
    printf("Choice is 3");
    break;

    case SYS_CLOSE: 
    printf("Choice is 3");
    break;

    default: 
    exit(-1);
    break;  
   }

   lock_release(&syscall_lock);

}

static void 
exit(int status){
  struct thread *cur = thread_current ();
  cur->
  if(cur->parent_sema_ref != NULL){
  	sema_up(&(cur->parent_sema_ref->sema));
  	cur->parent_sema_ref = NULL;
  }
  if(cur->parent_ref != NULL){
   struct list child_list=cur->parent_ref->child_list;
   struct list_elem* e;
   tid_t thread_current_id = cur->tid;
   for (e = list_begin (&child_list); e != list_end (&child_list); e = list_next (e)){
            struct child_status* temp = list_entry(e, struct child_status, elem);
            if(temp->child_id == thread_current_id){
              temp->exit_status = status;
              break;
            }
   }
  }

  lock_release(&syscall_lock); 

  thread_exit();
}