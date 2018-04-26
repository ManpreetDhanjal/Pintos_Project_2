#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
static void syscall_handler (struct intr_frame *);

void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

struct lock syscall_lock;


void
verifyAddress(const void *uaddr){
 printf("in verify\n");
	if(uaddr == NULL || is_kernel_vaddr(uaddr) || is_kernel_vaddr(uaddr+4)
			|| pagedir_get_page (thread_current()->pagedir, uaddr) == NULL){
      //|| is_kernel_vaddr(pagedir_get_page (thread_current()->pagedir, uaddr))){
      printf("exit called\n");
  	  exit(-1);
  }
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&(syscall_lock));
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf("----------syscall------\n");
  verifyAddress(f->esp);
  uint32_t* esp = (uint32_t*)f->esp;
  
  //lock_acquire(&syscall_lock);
  
  int sys_code = *(int*)f->esp;
  int intArg=1;
  
  switch(sys_code){
		case SYS_HALT:
			halt();
    	break;

    case SYS_EXIT:
			intArg = *((int*)f->esp+1);
			exit(intArg);
			break;

    case SYS_WAIT: 
      printf("wait--------\n");
			f->eax = wait((pid_t)*((int*)f->esp+1));
			break;

    case SYS_EXEC: 
      printf("exce--------\n");
			f->eax = exec((char *)*((int*)f->esp+1));
			break;

    case SYS_CREATE: 
    	printf("Choice is create");
    	break;

    case SYS_REMOVE: 
    	printf("Choice is 3");
    		break;

    case SYS_FILESIZE: 
    	printf("Choice is 3");
    break;

    case SYS_WRITE: 
    	esp = esp+1;
    	uint32_t fd = *esp;
    	esp = esp+1;
    	char* buffer = (char*)(*esp);
    	esp = esp+1;
      verifyAddress((void*)esp);
    	uint32_t size = *esp;
    	f->eax = write(fd, buffer, size);
    	break;

    case SYS_SEEK: 
    	printf("Choice is seek");
    	break;

    case SYS_TELL: 
    	printf("Choice is 3");
    	break;

    case SYS_CLOSE: 
    	printf("Choice is 3");
    	break;
  
    case SYS_OPEN:
    	printf("choice is open");
    	break;

    default: 
    	exit(-1);
    	break;  
   }

   //lock_release(&syscall_lock);

}

void 
halt (){
  shutdown_power_off();
}

void 
exit(int status){
  printf ("%s: exit(%d)\n", thread_current()->name, status);
  struct thread *cur = thread_current();
  

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
   if(cur->parent_sema_ref != NULL){
  	sema_up(&(cur->parent_sema_ref->sema));
  	cur->parent_sema_ref = NULL;
  }
  }/*
  if(syscall_lock.holder != NULL && syscall_lock.holder == thread_current()){
  	lock_release(&syscall_lock); 
  }*/
  thread_exit();
}


int 
wait(pid_t pid){
  if(pid == -1)return -1;
  return process_wait(pid);
}


pid_t
exec(const char *cmd_line){
  return process_execute(cmd_line);
}

int 
write(int fd, const void *buffer, unsigned size){
	// convert fd to file struct pointer
	if(fd == 1){ // print to console
		putbuf(buffer, size);
    return size;
	}
	return 0;
}










