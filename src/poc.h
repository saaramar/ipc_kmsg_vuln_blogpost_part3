#ifndef poc_h
#define poc_h

#include <stdio.h>
#include <pthread.h>
#include "iosurface.h"

#define _countof(array) (sizeof(array) / sizeof(array[0]))

typedef struct {
  mach_msg_header_t header;
  char bodyStr[32];
  int bodyInt;
} Message;

kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);
mach_port_name_t mk_timer_create(void);
kern_return_t mk_timer_destroy(mach_port_name_t name);
kern_return_t IOConnectSetNotificationPort(io_connect_t connect, uint32_t type, mach_port_t port, uintptr_t reference);
kern_return_t mach_port_peek(ipc_space_t task, mach_port_name_t name, mach_msg_trailer_type_t trailer_type, mach_port_seqno_t *request_seqnop, mach_msg_size_t *msg_sizep, mach_msg_id_t *msg_idp, mach_msg_trailer_info_t trailer_infop, mach_msg_type_number_t *trailer_infopCnt);

void poc(void);

#endif /* poc_h */
