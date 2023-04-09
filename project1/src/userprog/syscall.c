#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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
  check_user_addr(f->esp);

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
      break;
    case SYS_REMOVE:
      break;
    case SYS_OPEN:
      break;
    case SYS_FILESIZE:
      break;
    case SYS_READ:
      check_user_addr(f->esp + 4);
      check_user_addr(f->esp + 8);
      check_user_addr(f->esp + 12);
      read((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
      break;
    case SYS_WRITE:
      check_user_addr(f->esp + 4);
      check_user_addr(f->esp + 8);
      check_user_addr(f->esp + 12);
      write((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
      break;
    case SYS_SEEK:
      break;
    case SYS_TELL:
      break;
    case SYS_CLOSE:
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
  thread_exit();
}

pid_t exec (const char *cmd_line) {
  return process_execute(cmd_line);
}

int wait (pid_t pid) {
  return process_wait(pid);
}

int read (int fd, void *buffer, unsigned size) {
  //int i;
  int res;
  if (fd == 0) {
   /* for (i = 0; i < size; i++) {
      if(((char *)buffer)[i] == '\0') {
        break;
      }
    }*/
    res = input_getc();
    return res;
  }
  return -1;
}

int write(int fd, const void *buffer, unsigned size) {
  if (fd == 1) {
    putbuf(buffer, size);
    return size;
  }
  return -1;
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
