#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/off_t.h"
#include "userprog/process.h"
#include "string.h"

struct file{
  struct inode *inode;
  off_t pos;
  bool deny_write;
};

struct lock read_and_write_lock;

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&read_and_write_lock);
}

void check_user_addr(const void *addr){
  if(!is_user_vaddr(addr)){
    exit(-1);
  }
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf("syscall num : %d\n", *(uint32_t *)(f->esp));
  //printf ("system call!\n");
  //hex_dump(f->esp, f->esp, 100, 1);
  //check_user_addr(f->esp);
  int offset = 0;

  switch(*(uint32_t *)(f->esp)){
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      check_user_addr(f->esp + 4);
      exit(*(uint32_t *)(f->esp + 4));
      break;
    case SYS_EXEC:
      check_user_addr(f->esp + 4);
      f->eax = exec(*(uint32_t *)(f->esp + 4));
      break;
    case SYS_WAIT:
      check_user_addr(f->esp + 4);
      f->eax = wait((pid_t)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_CREATE:
      check_user_addr(f->esp + 4);
      check_user_addr(f->esp + 8);
      f->eax = create((const char *)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
      break;
    case SYS_REMOVE:
      check_user_addr(f->esp + 4);
      f->eax = remove((const char *)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_OPEN:
      check_user_addr(f->esp + 4);
      f->eax = open((const char *)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_FILESIZE:
      check_user_addr(f->esp + 4);
      f->eax = filesize((int)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_READ:
      check_user_addr(f->esp + 4 + offset);
      check_user_addr(f->esp + 8 + offset);
      check_user_addr(f->esp + 12 + offset);
      f->eax = read((int)*(uint32_t *)(f->esp + 4+ offset), (void *)*(uint32_t *)(f->esp + 8 + offset), (unsigned)*((uint32_t *)(f->esp + 12 + offset)));
      break;
    case SYS_WRITE:
      check_user_addr(f->esp + 4 + offset);
      check_user_addr(f->esp + 8 + offset);
      check_user_addr(f->esp + 12 + offset);
      f->eax = write((int)*(uint32_t *)(f->esp + 4 + offset), (void *)*(uint32_t *)(f->esp + 8 + offset), (unsigned)*((uint32_t *)(f->esp + 12 + offset)));
      break;
    case SYS_SEEK:
      check_user_addr(f->esp + 4);
      check_user_addr(f->esp + 8);
      seek((int)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
      break;
    case SYS_TELL:
      check_user_addr(f->esp + 4);
      f->eax = tell((int)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_CLOSE:
      check_user_addr(f->esp + 4);
      close((int)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_FIB:
      check_user_addr(f->esp + 4);
      f->eax = fibonacci((int)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_MOFI:
      check_user_addr(f->esp + 4);
      check_user_addr(f->esp + 8);
      check_user_addr(f->esp + 12);
      check_user_addr(f->esp + 16);
      f->eax = max_of_four_int((int)*(uint32_t *)(f->esp + 4), (int)*(uint32_t *)(f->esp + 8), (int)*(uint32_t *)(f->esp + 12), (int)*(uint32_t *)(f->esp + 16));
      break;
  }

 // thread_exit ();
}

void halt (void) {
  shutdown_power_off();
}

void exit (int status) {
  thread_current()->exit_status = status;
  printf("%s: exit(%d)\n", thread_name(), status);
  for(int i = 3; i < 128; i++){
    if(thread_current()->fd[i] != NULL){
      close(i);
    }
  }
  thread_exit();
}

pid_t exec (const char *cmd_line) {
  return process_execute(cmd_line);
}

int wait (pid_t pid) {
  return process_wait(pid);
}

bool create(const char *file, unsigned initial_size){
  if(file == NULL){
    exit(-1);
  }
  check_user_addr(file);
  return filesys_create(file, initial_size);
}

bool remove(const char *file){
  if(file == NULL){
    exit(-1);
  }
  check_user_addr(file);
  return filesys_remove(file);
}

int open(const char *file){
  int ret = -1;
  if(file == NULL){
    exit(-1);
  }
  check_user_addr(file);
  lock_acquire(&read_and_write_lock);
  struct file *fp = filesys_open(file);
  if(fp == NULL){
    ret = -1;
  }
  else{
    for(int i = 3; i < 128; i++){
      if(thread_current()->fd[i] == NULL && strcmp(thread_current()->name, file) == 0){
        file_deny_write(fp);
      }
      if(thread_current()->fd[i] == NULL){  
        thread_current()->fd[i] = fp;
        ret = i;
        break;
      }
    }
  }
  lock_release(&read_and_write_lock);
  return ret;
}

int filesize(int fd){
  if(thread_current()->fd[fd] == NULL){
    exit(-1);
  }
  return file_length(thread_current()->fd[fd]);
}

int read (int fd, void *buffer, unsigned size) {
  int i = 0;
  int res = -1;
  check_user_addr(buffer);
  lock_acquire(&read_and_write_lock);
  if (fd == 0) {
    for (i = 0; i < size; i++) {
      if(input_getc() == '\0') {
        break;
      }
    }
    res = i;
  }
  else if(fd > 2){
    if(thread_current()->fd[fd] == NULL){
      exit(-1);
    }
    res = file_read(thread_current()->fd[fd], buffer, size);
  }
  lock_release(&read_and_write_lock);
  return res;
}

int write(int fd, const void *buffer, unsigned size) {
  int res = -1;
  check_user_addr(buffer);
  lock_acquire(&read_and_write_lock);
  if (fd == 1) {
    putbuf(buffer, size);
    res = size;
  }
  else if(fd > 2){
    if(thread_current()->fd[fd] == NULL){
      exit(-1);
    }
    if(thread_current()->fd[fd]->deny_write){
      file_deny_write(thread_current()->fd[fd]);
    }
    res = file_write(thread_current()->fd[fd], buffer, size);
  }
  lock_release(&read_and_write_lock);
  return res;
}

int fibonacci (int n) {
  if (n < 0)
    return -1;
  else if (n < 2)
    return n;
  else {
    int a = 0;
    int b = 1;
    int temp;
    for (int i = 0; i < n - 1; i++) {
      temp = a;
      a = b;
      b = b + temp;
    }
    return b;
  }
}

int max_of_four_int (int a, int b, int c, int d) {
  int max = a;
  if (b > max)
    max = b;
  if (c > max)
    max = c;
  if (d > max)
    max = d;
  return max;
}

void seek(int fd, unsigned position){
  if(thread_current()->fd[fd] == NULL){
    exit(-1);
  }
  file_seek(thread_current()->fd[fd], position);
}

unsigned tell(int fd){
  if(thread_current()->fd[fd] == NULL){
    exit(-1);
  }
  return file_tell(thread_current()->fd[fd]);
}

void close(int fd){
  if(thread_current()->fd[fd] == NULL){
    exit(-1);
  }
  struct file *fp = thread_current()->fd[fd];
  thread_current()->fd[fd] = NULL;
  file_close(fp);
}
