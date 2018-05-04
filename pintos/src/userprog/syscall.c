#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdlib.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"


#define STACK_BOUND 0x08048000
static void syscall_handler (struct intr_frame *);

void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, const void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
struct file_details* list_itr(int fd);

struct lock syscall_lock;


void
verifyAddress(const void *uaddr){
  
  //printf("uaddr %p\n", uaddr);
  //printf("*uaddr ---%c----\n", *(char*)uaddr);
	if(uaddr == NULL || !is_user_vaddr(uaddr) || uaddr <= STACK_BOUND || is_kernel_vaddr(uaddr) || is_kernel_vaddr(uaddr+3)
		|| pagedir_get_page (thread_current()->pagedir, uaddr) == NULL 
		|| pagedir_get_page (thread_current()->pagedir, uaddr+3) == NULL){
     
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
  uint32_t fd;
  uint32_t size;
  uint32_t position;
  char* file;
  char* buffer;
  
  
  int sys_code = *(int*)f->esp;
  int intArg=1;
  
  switch(sys_code){
		case SYS_HALT:
    lock_acquire(&syscall_lock);
			halt();
      lock_release(&syscall_lock);
    	break;

    case SYS_EXIT:
    //printf("----exit\n");
      lock_acquire(&syscall_lock);
      verifyAddress((void *)f->esp+1);
			intArg = *((int*)f->esp+1);
			exit(intArg);
			break;

    case SYS_WAIT: 
      //printf("wait--------\n");
			f->eax = wait((pid_t)*((int*)f->esp+1));

			break;

    case SYS_EXEC: 
      lock_acquire(&syscall_lock);
      	esp = esp + 1;
    	verifyAddress((void*)esp);
    	char* str = (char*)*esp;
    	verifyAddress((void*)str);
    	f->eax = exec((char *)*esp);
      lock_release(&syscall_lock);
	break;

    case SYS_CREATE: 
      lock_acquire(&syscall_lock);
      esp = esp+1;
      verifyAddress((void*)esp);
      file = (char *)*esp;
      verifyAddress((void*)file);
      esp = esp+1;
      size = *esp;
      f->eax = create(file, size);
      lock_release(&syscall_lock);
    	break;

    case SYS_REMOVE: 
    	//printf("Choice is 3");
      lock_acquire(&syscall_lock);
      esp = esp+1;
      verifyAddress((void*)esp);
      file = (char *)*esp;
      f->eax = remove(file);
      lock_release(&syscall_lock);
      break;

    case SYS_FILESIZE: 
    	//printf("Choice is 3");
      lock_acquire(&syscall_lock);
      esp = esp+1;
      verifyAddress((void*)esp);
      fd = *esp;
      f->eax = filesize(fd);
      lock_release(&syscall_lock);
    break;

    case SYS_WRITE: 
      //printf("write--------\n");
      lock_acquire(&syscall_lock);
    	esp = esp+1;
      verifyAddress((void*)esp);
    	fd = *esp;
    	esp = esp+1;
      verifyAddress((void*)esp);
      buffer = (char*)(*esp);
      verifyAddress((void*)buffer);
    	esp = esp+1;
      verifyAddress((void*)esp);
      size = *esp;
      for(int i=0; i<size; i++){
    	verifyAddress(buffer+i);
      }
    	f->eax = write(fd, buffer, size);
      lock_release(&syscall_lock);
    	break;
    case SYS_READ: 
      //printf("read--------\n");
      lock_acquire(&syscall_lock);
      esp = esp+1;
      verifyAddress((void*)esp);
      fd = *esp;
      //printf("fd is %d\n", fd);
      esp = esp+1;
      verifyAddress((void*)esp);
      buffer = (char*)(*esp);
      verifyAddress((void*)buffer);
      esp = esp+1;
      verifyAddress((void*)esp);
      size = *esp;
for(int i=0; i<size; i++){
    	verifyAddress(buffer+i);
      }
      f->eax = read(fd, buffer, size);
      lock_release(&syscall_lock);
      break;

    case SYS_SEEK: 
    	//printf("Choice is seek");
      lock_acquire(&syscall_lock);
      esp = esp+1;
      verifyAddress((void*)esp);
      fd = *esp;
      esp = esp+1;
      verifyAddress((void*)esp);
      position = (*esp);
      seek(fd, position);
      lock_release(&syscall_lock);
    	break;

    case SYS_TELL: 
    	//printf("Choice is 3");
      lock_acquire(&syscall_lock);
      esp = esp+1;
      verifyAddress((void*)esp);
      fd = *esp;
      f->eax = tell(fd);
      lock_release(&syscall_lock);
    	break;

    case SYS_CLOSE: 
      lock_acquire(&syscall_lock);
      esp = esp+1;
      verifyAddress((void*)esp);
      fd = *esp;
      close(fd);
      lock_release(&syscall_lock);
    	//printf("Choice is 3");
    	break;
  
    case SYS_OPEN:
      //printf("opening file.....\n");
    	lock_acquire(&syscall_lock);
      esp = esp+1;
      verifyAddress((void*)esp);
      file = (char *)*esp;
      verifyAddress((void*)file);
      f->eax = open(file);
      lock_release(&syscall_lock);
    	break;

    default: 
    	exit(-1);
    	break; 
   }
     

   //

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
  }
  
  //close all the file descriptors
  struct list_elem* e;
  struct file_details* prev = NULL;
  for (e = list_begin (&thread_current()->files_list); e != list_end(&thread_current()->files_list); e = list_next(e)){
      struct file_details* temp = list_entry(e, struct file_details, elem);
      if(prev != NULL){
	free(prev);
      }
      file_close(temp->file_ref);
      list_remove(&temp->elem);
      prev = temp;
  } 
  if(prev != NULL){
	free(prev);
  }
  if(syscall_lock.holder != NULL && syscall_lock.holder == thread_current()){
    lock_release(&syscall_lock); 
  } 
  
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
read(int fd, const void *buffer, unsigned size){
  // convert fd to file struct pointer
  if(fd == STDOUT_FILENO || fd < STDIN_FILENO || (buffer + size - 1) >= PHYS_BASE){
    return -1;
  }
  else if(fd == STDIN_FILENO){ // read from console
    int i = 0;
    while(--size > 0){
      buffer = ((void *)input_getc());
      buffer++;
    }
    return size;
  }else{
    struct file_details* detail = list_itr(fd);
    if(detail != NULL){
      return file_read (detail->file_ref, buffer, size);
    }
  }
  return -1;
}

int 
write(int fd, const void *buffer, unsigned size){
	// convert fd to file struct pointer
  
  if(fd <= STDIN_FILENO || (buffer + size - 1) >= PHYS_BASE){
    return -1;
  }else if(fd == STDOUT_FILENO){ // print to console
    verifyAddress((void*)(buffer));
    verifyAddress((void*)(buffer+size-1));
    
		putbuf(buffer, size);
    return size;
	}else{
    struct file_details* detail = list_itr(fd);
    if(detail != NULL){
      return file_write (detail->file_ref, buffer, size);
    }
  }
	return -1;
}

bool create(const char *file, unsigned initial_size){
  if(file == NULL)exit(-1);
  return filesys_create(file,initial_size);
}

int open(const char *file){
  struct file *ref = filesys_open(file);
  int fd;
  if(ref == NULL){
    return -1;
  }else{

    struct file_details* fileList = (struct file_details*)malloc(sizeof(struct file_details));
    fd = thread_current()->max_fd++;
    fileList->fd = fd;
    
    fileList->file_ref = ref;
    list_push_back(&thread_current()->files_list,&fileList->elem);
  }

  return fd;
}

void close(int fd){
  if(fd <= 1){
    exit(-1);
  }else{
    struct file_details* detail = list_itr(fd);
    if(detail != NULL){
      file_close(detail->file_ref);
      list_remove(&detail->elem);
    }
  }
}

int filesize(int fd){
  
  if(fd <= 1) {
    exit(-1);
  }
  struct file_details* detail = list_itr(fd);
  if(detail != NULL){
    return file_length(detail->file_ref);
  }
  exit(-1);
  return 0;
}

struct file_details* list_itr(int fd){
  struct list_elem* e;
  for (e = list_begin (&thread_current()->files_list); e != list_end(&thread_current()->files_list); e = list_next(e)){
      struct file_details* temp = list_entry(e, struct file_details, elem);
      if(temp->fd == fd){
        return temp;
      }
  }
  return NULL;
}

bool remove(const char *file){
  return filesys_remove(file);
}


void seek(int fd, unsigned position){
  struct file_details* detail = list_itr(fd);
  if(detail != NULL){
    return file_seek(detail->file_ref,position);
  }
}

unsigned tell(int fd){
  struct file_details* detail = list_itr(fd);
  if(detail != NULL){
    return file_tell(detail->file_ref);
  }
  return 0;
}




