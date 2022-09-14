# ipc_kmsg_get_from_kernel, part 3 - more overlaps

This is the third blogpost in the series about the `ipc_kmsg_get_from_kernel` vulnerability, patched in iOS 15.4 [security update](https://support.apple.com/en-gb/HT213182). Before keep reading, it's highly encourged to read the first two blogposts:

* [ipc_kmsg_get_from_kernel, iOS 15.4 - root cause analysis](https://saaramar.github.io/ipc_kmsg_vuln_blogpost/) - which details the root cause of the bug, the involved structures and the vulnerable flow
* [ipc_kmsg_get_from_kernel - part 2, exploitation primitive](https://saaramar.github.io/ipc_kmsg_blogpost_part2/) - which takes advantage of another mach message that gives a better overlap, and presents a primitive we can exploit (an OOB write). Unlike the overlap in the first blog, this one is exploitable (even though, not elegant).

In this blogpost we will see another mach message (not in exceptions) that gives a different structures overlap.

Some notes:

* All the tests/demos here are on virtual iPhone 13, iOS 15.3.1 (19D52), [Corellium](https://www.corellium.com/).
* This blogpost does NOT contain an exploit. The purpose of this blogpost, as the first and second parts, is to spread knowledge in the community and encourage more folks to get their hands dirty in low level and iOS/macOS internals.

## A better message

### A reminder - what is a "good" message for us

Again, it's highly encouraged to read the last two blogposts. However, just as a reminder, a quote from part 2:

"*As we saw in the previous blogpost, we shifted `ikm_header` backward, so it’ll point to the middle of `ipc_kmsg`. The scenario we created here is that **`ikm_header` overlaps with a part of the `ipc_kmsg` structure.** Therefore, when we speak about “different/better mach messages”, we basically mean “a message with size that gives a better overlap”.*

*For instance, the use of `EXCEPTION_STATE` and `ARM_THREAD_STATE64` gave a really bad overlap - we corrupted and immediately dereferenced `kmsg->ikm_header`. Without a PAC bypass, this is not exploitable.*

*Now, with `EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES`, we get a different overlap (in which we do not corrupt `kmsg->ikm_header`). And this is the interesting part - the code that modifies `kmsg->ikm_header->msgh_size` doesn’t intend to change `msgh_size` to this huge value, it intends to change another thing. **Actually, two things. From two different structures.***"

Indeed, the use of `EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES` gave a better overlap than `EXCEPTION_STATE`, but still, not elegant enough. And as we keep pointing out, there are other things we can send from kernel to user besides exceptions.

### IOKit

At the end of our previous blogpost, I quoted [Ian](https://twitter.com/i41nbeer)'s text from his [blogpost](https://googleprojectzero.blogspot.com/2017/04/exception-oriented-exploitation-on-ios.html), and mentioned again that there are some interesting places in IOKit services that send messages from kernelmode. However, we have a few requirements:

0. we need the message to have a "good" size (or a size we have partial control over). A "good" size means:
   * Not too large, so we won't corrupt `ikm_header` and crash on the `str` instruction right after the corrupting `memcpy`.
   * Not to small so we could get a good overlap.
1. the userclient has to be accessible from the app sandbox

Now - how can we send a mach message from IOKit to userspace?

### IOUserClient::sendAsyncResult64

The functions `IOUserClient::sendAsyncResult64WithOptions` and `IOUserClient::sendAsyncResult64` call `IOUserClient::_sendAsyncResult64`:

```c
IOReturn
IOUserClient::sendAsyncResult64WithOptions(OSAsyncReference64 reference,
    IOReturn result, io_user_reference_t args[], UInt32 numArgs, IOOptionBits options)
{
	return _sendAsyncResult64(reference, result, args, numArgs, options);
}

IOReturn
IOUserClient::sendAsyncResult64(OSAsyncReference64 reference,
    IOReturn result, io_user_reference_t args[], UInt32 numArgs)
{
	return _sendAsyncResult64(reference, result, args, numArgs, 0);
}
```

Which looks as follows:

```c
IOReturn
IOUserClient::_sendAsyncResult64(OSAsyncReference64 reference,
    IOReturn result, io_user_reference_t args[], UInt32 numArgs, IOOptionBits options)
{

...
...
...

	if ((options & kIOUserNotifyOptionCanDrop) != 0) {
		kr = mach_msg_send_from_kernel_with_options( &replyMsg.msgHdr,
		    replyMsg.msgHdr.msgh_size, MACH_SEND_TIMEOUT, MACH_MSG_TIMEOUT_NONE);
	} else {
		/* Fail on full queue. */
		kr = mach_msg_send_from_kernel_proper( &replyMsg.msgHdr,
		    replyMsg.msgHdr.msgh_size);
	}
	if ((KERN_SUCCESS != kr) && (MACH_SEND_TIMED_OUT != kr) && !(kIOUCAsyncErrorLoggedFlag & reference[0])) {
		reference[0] |= kIOUCAsyncErrorLoggedFlag;
		IOLog("%s: mach_msg_send_from_kernel_proper(0x%x)\n", __PRETTY_FUNCTION__, kr );
	}
	return kr;
}
```

Awesome, this function sends a mach message from kernelmode. Let's start by looking at xrefs of `IOUserClient::sendAsyncResult64`. After ruling some (most) of the options, I saw some relevant candidates. One is `IOSurfaceRootUserClient::notify_surface`.

### IOSurface

 I love coffee, whiskey, and IOSurface.

`IOSurfaceRoot` is fantastic - it's accessible from the app sandbox and it has great functionalities. By going up the callstack from `IOUserClient::sendAsyncResult64`, we see the following flow from `IOSurfaceRootUserClient::s_release_surface`:

```
IOSurfaceRootUserClient::s_release_surface
	IOSurfaceRootUserClient::release_surface
		IOSurface::decrement_use_count
			IOSurfaceRoot::notifySurface
				IOSurfaceRootUserClient::notify_surface
					IOUserClient::sendAsyncResult64
```

### New POC, new panic

Well, we know what we have to do:

* create iosurface, by calling `s_create_surface` (method 0)
* set notification, by calling `s_set_surface_notify` (method 17) with our mktimer's port
* increasing the use count, by calling `s_increment_surface_use_count` (method 14)
* drop use count, by calling `s_release_surface` (method 1)

By running our new POC, we get a panic! This is our new panic (deterministic):

```
panic(cpu 0 caller 0xfffffff00833b67c): Invalid waitq: 0xffffffe21b45a620 @waitq.c:3512
Debugger message: panic
Device: D17
Hardware Model: iPhone14,5
```

Interesting. Of course, if instead of using the mktimer's port with the preallocated buffer we would use another mach port (i.e., call `mach_port_allocate` with `MACH_PORT_RIGHT_RECEIVE`, and then `mach_port_insert_right` with `MACH_MSG_TYPE_MAKE_SEND`), everything works fine, as expected. This has to be the result of a new overlap. And as always, it's important to understand the flow and see exactly the overlap we get here.

## Analysis

### The overlap

Let's debug and see the mach message sent to the mktimer's port.

Just as we did in the [previous blogpost](https://saaramar.github.io/ipc_kmsg_blogpost_part2/), let's break in the function `ipc_kmsg_get_from_kernel` (in the `ikm_set_header` inlined part), and see the length of the received message vs the preallocated buffer. As a reminder:

* `EXCEPTION_STATE` gave us `0x194`
* `EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES` gave us `0xa8`

While the preallocated buffer is always of size `0xa0`.

Let's try out our new poc, with `notify_surface`:

```
* thread #5, stop reason = breakpoint 2.1
    frame #0: 0xfffffff007bd00fc
->  0xfffffff007bd00fc: add    x10, x22, x10
    0xfffffff007bd0100: sub    x8, x10, x8
    0xfffffff007bd0104: add    x8, x8, #0x5c
    0xfffffff007bd0108: movk   x9, #0x3ca5, lsl #48
Target 0: (No executable module.) stopped.
(lldb) reg read x10
     x10 = 0x00000000000000a0
(lldb) reg read x8
      x8 = 0x00000000000000c4
```

**Fantastic!** Let's view the overlap. Setting a breaking on the `memcpy` call itself:

```
* thread #6, stop reason = breakpoint 2.1
    frame #0: 0xfffffff007bd0164
->  0xfffffff007bd0164: bl     -0xff634e7f0
    0xfffffff007bd0168: mov    w23, #0x0
    0xfffffff007bd016c: ldr    x16, [x22, #0x18]
    0xfffffff007bd0170: b      -0xff59ebe38
Target 0: (No executable module.) stopped.
(lldb) reg read x0
      x0 = 0xffffffe4cc71ee38
(lldb) reg read x2
      x2 = 0x0000000000000080
(lldb) reg read x22
     x22 = 0xffffffe4cc71ee00
(lldb) x/14gx $x22
0xffffffe4cc71ee00: 0x0000000000000000 0x0000000000000000
0xffffffe4cc71ee10: 0xff92fee3e88a7660 0xfff1dce4cc71ee38 <-- ikm_header
0xffffffe4cc71ee20: 0x0000000000000000 0x0000000000000000
0xffffffe4cc71ee30: 0x0000000000000000 0x0000000000000000
0xffffffe4cc71ee40: 0x0000000000000000 0x00000000000000a0
0xffffffe4cc71ee50: 0x0000000000000000 0x0000000000000000
0xffffffe4cc71ee60: 0x0000000000000000 0x0000000000000000
(lldb) 
```

`x22` is our vulnerable `ipc_kmsg`. Note that:

* The `ikm_header` pointer points to the middle of the kmsg (offset `+0x38`)
* The length of the copy is `0x80` (makes sense, 0xc4-0x44), and we start to corrupt from offset `+0x38`

But the important question is - what's the overlap?

Again, `ipc_kmsg`:

```c
struct ipc_kmsg {
	struct ipc_kmsg            *ikm_next;        /* next message on port/discard queue */
	struct ipc_kmsg            *ikm_prev;        /* prev message on port/discard queue */
	union {
		ipc_port_t XNU_PTRAUTH_SIGNED_PTR("kmsg.ikm_prealloc") ikm_prealloc; /* port we were preallocated from */
		void      *XNU_PTRAUTH_SIGNED_PTR("kmsg.ikm_data")     ikm_data;
	};
	mach_msg_header_t          *XNU_PTRAUTH_SIGNED_PTR("kmsg.ikm_header") ikm_header;
	ipc_port_t                 XNU_PTRAUTH_SIGNED_PTR("kmsg.ikm_voucher_port") ikm_voucher_port;   /* voucher port carried */
	struct ipc_importance_elem *ikm_importance;  /* inherited from */
	queue_chain_t              ikm_inheritance;  /* inherited from link */
	struct turnstile           *ikm_turnstile;   /* send turnstile for ikm_prealloc port */
#if MACH_FLIPC
	struct mach_node           *ikm_node;        /* Originating node - needed for ack */
#endif
	mach_msg_size_t            ikm_size;
	uint32_t                   ikm_ppriority;    /* pthread priority of this kmsg */
#if IKM_PARTIAL_SIG
	uintptr_t                  ikm_header_sig;   /* sig for just the header */
	uintptr_t                  ikm_headtrail_sig;/* sif for header and trailer */
#endif
	uintptr_t                  ikm_signature;    /* sig for all kernel-processed data */
	ipc_object_copyin_flags_t  ikm_flags;
	mach_msg_qos_t             ikm_qos_override; /* qos override on this kmsg */
	mach_msg_type_name_t       ikm_voucher_type : 8; /* disposition type the voucher came in with */

	uint8_t                    ikm_inline_data[] __attribute__((aligned(4)));
};
```

And the offsets:

```
+0x38 - ikm_turnstile
+0x40 - ikm_node
+0x48 - ikm_size
+0x4c - ikm_ppriority
+0x50 - ikm_signature
+0x58 - ikm_flags
+0x5a - ikm_qos_override
+0x5b - ikm_voucher_type
+0x5c - ikm_inline_data
```

Fun! New overlap. Looks like a lot of interesting fields just got in the game!

## Let's play

### Receive the message

Instead of just letting our program exit, let's try to receive the message. We can do that by calling `mach_msg` with `MACH_RCV_MSG`:

```c
    mach_msg_return_t ret = mach_msg((mach_msg_header_t *)&message,
                                        MACH_RCV_MSG,
                                        0,
                                        sizeof(message),
                                        recvPort,
                                        MACH_MSG_TIMEOUT_NONE,
                                        MACH_PORT_NULL);
```

And as we can expect, we get the following interesting panic, deterministically:

```
panic(cpu 4 caller 0xfffffff007bd361c): ikm_validate_sig: full signature mismatch: kmsg=0x0xffffffe135c22f00, id=1226053470, sig=0xa6eb659200000000 (expected 0x4914175e00000000) @ipc_kmsg.c:525
Debugger message: panic
Device: D17
Hardware Model: iPhone14,5
```

We hit the following panic in `ikm_validate_sig`, which does exactly what its name suggests:

```c
static void
ikm_validate_sig(
	ipc_kmsg_t kmsg)
{
	ikm_sig_scratch_t scratch;
	uintptr_t expected;
	uintptr_t sig;
	char *str;

	zone_require(ipc_kmsg_zone, kmsg);

	ikm_init_sig(kmsg, &scratch);

	ikm_header_sig(kmsg, &scratch);

  ...
  ...

	if (sig != expected) {
		ikm_signature_failures++;
		str = "full";

	...
  ...

			panic("ikm_validate_sig: %s signature mismatch: kmsg=0x%p, id=%d, sig=0x%zx (expected 0x%zx)",
			    str, kmsg, id, sig, expected);
		}
	}
}
```

And the callstack is:

```
...
	_mach_msg_overwrite_trap
		_mach_msg_receive_results
			ipc_kmsg_copyout
				ikm_validate_sig
```

Well, makes sense - `ipc_kmsg_copyout` validates the kmsg signature. And we panic on an incorrect signature.

By debugging the flow, you can see the kmsg actually doesn't change between the `ikm_sign` call (which legitimately signs our kmsg) and `ipc_kmsg_copyout` (which calls `ikm_validate_sig`). So, why is the signature incorrect? Well, that's actually funny.

The `ikm_header` is part of the signature. And right now, `ikm_header` overlaps with our kmsg. Note that in our overlap, `ikm_header` points to offset `+0x38` in our kmsg. Let's take a look at `mach_msg_header_t` (the type of `ikm_header`):

 ```c
 typedef struct{
 	mach_msg_bits_t               msgh_bits;
 	mach_msg_size_t               msgh_size;
 	mach_port_t                   msgh_remote_port;
 	mach_port_t                   msgh_local_port;
 	mach_port_name_t              msgh_voucher_port;
 	mach_msg_id_t                 msgh_id;
 } mach_msg_header_t;
 ```

**This means `ikm_header->msgh_id` aliases with the `kmsg->ikm_signature`**. Yes. The very `str` instruction that writes the signature to `kmsg->ikm_signature` changes the `ikm_header->msgh_id`, which means the signature is invalid.

### Leaking the signature - mach_port_peek

Well, simply receiving the message using `mach_msg` is obviously problematic. Just by looking for more traps/functionalities that copy kmsg content to userspace, one can't miss `mach_port_peek`.

The nice thing about `mach_port_peek` is that it doesn't do drastic operations (i.e., it doesn't call `ipc_kmsg_free`, etc.), and it doesn't validate any signature. It simply "peeks" at the first message on a port’s receive queue. As was done [before](https://blog.ret2.io/2022/06/29/pwn2own-2021-safari-sandbox-intel-graphics-exploit/), we can use it for information disclosure. True, we are pretty limited with what we can read using `mach_port_peek`, but it may be enough. For example, we can try to leak the `ikm_signature`, since it overlaps with `ikm_header->msgh_id`.

<u>Interesting note:</u> I didn't investigate this further yet, but I've seen some modifications to this in recent kernelcaches. It looks like there is some new signature verification in this flow (see additional calls to `ikm_validate_sig`, specifically from `_ipc_mqueue_peek_locked`). In any case, we are working on 15.3.1 (the last vulnerable version). Therefore, for this blogpost, there is no signature verification in `mach_port_peek`.

Let's try to leak the signature, for fun. This is mainly to prove to ourselves that we have some way to leak things using the overlap. First, let's break again in `ipc_kmsg_get_from_kernel`, to get the address of our kmsg. Let's break right AFTER the corrupting `memcpy`:

```
* thread #5, stop reason = breakpoint 2.1
    frame #0: 0xfffffff007bd0168
->  0xfffffff007bd0168: mov    w23, #0x0
    0xfffffff007bd016c: ldr    x16, [x22, #0x18]
    0xfffffff007bd0170: b      -0xff59ebefc
    0xfffffff007bd0174: str    w20, [x16, #0x4]
Target 0: (No executable module.) stopped.
(lldb) x/18gx $x22
0xffffffe21af28700: 0x0000000000000000 0x0000000000000000
0xffffffe21af28710: 0xffb30ee218c55d60 0xffee59e21af28738
0xffffffe21af28720: 0x0000000000000000 0x0000000000000000
0xffffffe21af28730: 0x0000000000000000 0x0000008000000013
0xffffffe21af28740: 0xffffffe218c55d60 0x0000000000000000
0xffffffe21af28750: 0x0000003500000000 0x0000009600000014
0xffffffe21af28760: 0x0000000000000000 0x0000000000000e03
0xffffffe21af28770: 0x0000000000000001 0x0000000000000000
0xffffffe21af28780: 0x0000000000000000 0x0000000000000000
(lldb) 
```

You can see the `ikm_signature` at `0xffffffe21af28750` and `msgh_id` at `0xffffffe21af28754`. Right now `ikm_header->msgh_id` is (0x35).

Let's keep going, and break on the instruction that writes the signature at the end of `ikm_sign` (called from `ipc_kmsg_copyin_from_kernel`):

```
* thread #5, stop reason = breakpoint 3.1
    frame #0: 0xfffffff007bd07a4
->  0xfffffff007bd07a4: str    x8, [x19, #0x50]
    0xfffffff007bd07a8: ldp    x29, x30, [sp, #0x80]
    0xfffffff007bd07ac: ldp    x20, x19, [sp, #0x70]
    0xfffffff007bd07b0: ldp    x22, x21, [sp, #0x60]
Target 0: (No executable module.) stopped.
(lldb) reg read x19
     x19 = 0xffffffe21af28700
(lldb) reg read x8
      x8 = 0x0161631700000000
(lldb) nexti
Process 1 stopped
* thread #5, stop reason = instruction step over
    frame #0: 0xfffffff007bd07a8
->  0xfffffff007bd07a8: ldp    x29, x30, [sp, #0x80]
    0xfffffff007bd07ac: ldp    x20, x19, [sp, #0x70]
    0xfffffff007bd07b0: ldp    x22, x21, [sp, #0x60]
    0xfffffff007bd07b4: ldp    x24, x23, [sp, #0x50]
Target 0: (No executable module.) stopped.
(lldb) x/18gx 0xffffffe21af28700
0xffffffe21af28700: 0x0000000000000000 0x0000000000000000
0xffffffe21af28710: 0xffb30ee218c55d60 0xffee59e21af28738
0xffffffe21af28720: 0x0000000000000000 0x0000000000000000
0xffffffe21af28730: 0x0000000000000000 0x0000008000000011
0xffffffe21af28740: 0xffffffe218c55d60 0x0000000000000000
0xffffffe21af28750: 0x0161631700000000 0x0000009600000014
0xffffffe21af28760: 0x0000000000000000 0x0000000000000e03
0xffffffe21af28770: 0x0000000000000001 0x0000000000000000
0xffffffe21af28780: 0x0000000000000000 0x0000000000000000
(lldb)
```

And our POC's output:

```
iPhone:~ root# ./exploit 
surface_id == 14
call s_set_surface_notify
call s_increment_surface_use_count
call release_surface
peak:
mach_port_peek:
	seq_no == 0x0
	msg_size == 0x80
	msg_id == 0x1616317
	trailer_sz == 0x34
```

Awesome, we leaked the signature.

Of course, leaking the signature doesn't help us. It really gives us nothing. I just wanted to share this to show that if we could have a different message size, and have `ikm_header->msgh_id` alias with a pointer/some interestinf field, we could leak it (even if the signature is incorrect). Of course, we can leak only 4 bytes of it, because `msgh_id` is 32-bit value.

### Change the overlap?

Ok, so basically, we would like our overlap to avoid:

* corrupting `kmsg->ikm_header` in `ipc_kmsg_get_from_kernel`, as we saw in the first blogpost.
* modifying the signature after `ikm_sign` (meaning, not alias `ikm_signature` with things we are writing to)

It would be great to send a slightly larger message; however, we can't control the size of the notification `IOSurfaceRootUserClient::notify_surface` sends. By looking at `IOUserClient::sendAsyncResult64`, we can see that the size of the message is a function of `numArgs`, and it's fixed in `IOSurfaceRootUserClient::notify_surface`:

```assembly
FFFFFFF0088A0F10 ADD             X0, X1, #0x10 ; reference
FFFFFFF0088A0F14 ADD             X2, SP, #0x20+args ; args
FFFFFFF0088A0F18 MOV             W1, #0  ; result
FFFFFFF0088A0F1C MOV             W3, #2  ; numArgs
FFFFFFF0088A0F20 BL              IOUserClient::sendAsyncResult64(ulong long *,int,ulong long *,uint)
```

### More IOKit?

Let's look at xrefs of `IOUserClient::sendAsyncResult64` and try to find callsites which:

* are accessible from the app sandbox
* have `numArgs` larger than 2.

Besides coffee, whiskey and IOSurface, there is one other thing we can't ignore - IOGPU. Yes, GPU things tend to be pretty fun. And indeed, we have the following flow in `IOGPUDeviceUserClient::s_submit_command_buffers` (external method number 26 of `IOGPUDeviceUserClient`):

```
IOGPUDeviceUserClient::s_submit_command_buffers
	IOGPUCommandQueue::submit_command_buffers
		IOGPUCommandQueue::submit_command_buffer
			IOGPUFenceMachine::sendBlockFenceNotification
				IOUserClient::sendAsyncResult64
```

This is the relevant callsite:

```assembly
FFFFFFF00925AAD0 ADD             X2, SP, #0x80+args ; args
FFFFFFF00925AAD4 MOV             X0, X23 ; reference
FFFFFFF00925AAD8 MOV             W1, #0  ; result
FFFFFFF00925AADC MOV             W3, #7  ; numArgs
FFFFFFF00925AAE0 BL              IOUserClient::sendAsyncResult64(ulong long *,int,ulong long *,uint)
```

Interesting; and, extremely unfortunate. For those of you who already did the math in your heads - yes, it's bad. It turns out the overlap move `ikm_header` to point backward to offset `+0x10` of our kmsg. YES. We make `kmsg->ikm_header` to point to one qword before `ikm_header` itself in `ipc_kmsg`. And as we saw in previous blogposts, this panics immediately after the corrupting memcpy, on the write to `ikm_header->msgh_size `(in `ipc_kmsg_get_from_kernel`):

```assembly
FFFFFFF007BD015C                 MOV             W2, W20 ; size_t
FFFFFFF007BD0160                 MOV             X1, X21 ; void *
FFFFFFF007BD0164 ; memcpy(kmsg->ikm_header, msg, size);
FFFFFFF007BD0164                 BL              _memmove
FFFFFFF007BD0168                 MOV             W23, #0
FFFFFFF007BD016C                 LDR             X16, [X22,#0x18]
FFFFFFF007BD0170                 AUTDA           X16, X24
FFFFFFF007BD0174 ; kmsg->ikm_header->msgh_size = size;
FFFFFFF007BD0174                 STR             W20, [X16,#4]
FFFFFFF007BD0178 ; *kmsgp = kmsg;
FFFFFFF007BD0178                 STR             X22, [X19]
```

We have been here before. We know that without a PAC bypass, this is not exploitable.

Just to verify everything, let's see this in action. Of course, we need to make sure we can use this functionality and trigger it from the app sandbox. We also need to make sure this message can reach our mktimer's port. Just like we did with `notify_surface`.

However, Instead of building all that, we can check if this number of arguments will create a good message size for us. At this point, we are very familiar with the memory layout, the structures, and the offsets. And we already have a POC that triggers `IOUserClient::sendAsyncResult64` to our mktimer's port. So - why not simply patch the number of arguments right before the call to `IOUserClient::sendAsyncResult64` in `notify_surface`?

Let's see what happens if we patch it to 7. First, we get into the corrupting memcpy, with `ikm_header` just sitting there, PAC'd, and points to itself:

```
(lldb) reg read x3
      x3 = 0x0000000000000002
(lldb) reg write x3 7                                     <-- patch numArgs
(lldb) breakpoint set -a 0xFFFFFFF007BD0164
Breakpoint 2: address = 0xfffffff007bd0164
(lldb) c
Process 1 resuming
Process 1 stopped
* thread #6, stop reason = breakpoint 2.1
    frame #0: 0xfffffff007bd0164
->  0xfffffff007bd0164: bl     -0xff634e7f0               <-- call memmove
    0xfffffff007bd0168: mov    w23, #0x0
    0xfffffff007bd016c: ldr    x16, [x22, #0x18]
    0xfffffff007bd0170: b      -0xff59ed07c
Target 0: (No executable module.) stopped.
(lldb) x/14gx $x22
0xffffffe3012e7400: 0x0000000000000000 0x0000000000000000
0xffffffe3012e7410: 0xffc7dae4cb03aee0 0xfffbe2e3012e7410 <-- ikm_header, PAC'd
0xffffffe3012e7420: 0x0000000000000000 0x0000000000000000
0xffffffe3012e7430: 0x0000000000000000 0x0000000000000000
0xffffffe3012e7440: 0x0000000000000000 0x00000000000000a0
0xffffffe3012e7450: 0x0000000000000000 0x0000000000000000
0xffffffe3012e7460: 0x0000000000000000 0x0000000000000000
(lldb) breakpoint set -a 0xFFFFFFF007BD0168
Breakpoint 3: address = 0xfffffff007bd0168
(lldb) c
```

And one instruction after the corrupting `memcpy` you can see the header inside the kmsg, starting at offset `+0x10`:

```
Process 1 resuming
Process 1 stopped
* thread #6, stop reason = breakpoint 3.1
    frame #0: 0xfffffff007bd0168
->  0xfffffff007bd0168: mov    w23, #0x0
    0xfffffff007bd016c: ldr    x16, [x22, #0x18]
    0xfffffff007bd0170: b      -0xff59ed07c
    0xfffffff007bd0174: str    w20, [x16, #0x4]
Target 0: (No executable module.) stopped.
(lldb) x/14gx $x22
0xffffffe3012e7400: 0x0000000000000000 0x0000000000000000
0xffffffe3012e7410: 0x000000a800000013 0xffffffe4cb03aee0
0xffffffe3012e7420: 0x0000000000000000 0x0000003500000000
0xffffffe3012e7430: 0x000000960000003c 0x0000000000000000
0xffffffe3012e7440: 0x0000000000000000 0x0000000000000000
0xffffffe3012e7450: 0x0000000000000000 0x0000000000000000
0xffffffe3012e7460: 0x0000000000000000 0x0000000000000000
```

And the panic:

```
panic(cpu 5 caller 0xfffffff00833fec0): Kernel data abort. at pc 0xfffffff007bd0174, lr 0xfffffff007bd0168 (saved state: 0xffffffeb0e15b2d0)
          x0:  0xffffffe3012e7410 x1:  0xffffffeb0e15b758  x2:  0xfffffffffffffff8  x3:  0xffffffe3012e7478
          x4:  0x0000000000000000 x5:  0x0000000000000010  x6:  0xffffffe30110ba30  x7:  0xfffffff00828f308
          x8:  0x0000000e00000000 x9:  0xb1ab002000000000  x10: 0x0e15b850de24b304  x11: 0x0889b650ffffffeb
          x12: 0x0889b650ffffffeb x13: 0x00000001ffb619f0  x14: 0x0110ba3000000000  x15: 0x00000000ffffffe3
          x16: 0xbfffffe4cb03aee0 x17: 0x1a35ffe4cb03af58  x18: 0x0000000000000000  x19: 0xffffffeb0e15b678
          x20: 0x00000000000000a8 x21: 0xffffffeb0e15b6d0  x22: 0xffffffe3012e7400  x23: 0x0000000000000000
          x24: 0x3ca5ffe3012e7418 x25: 0xffffffe60050c02c  x26: 0xffffffe6004f2c9c  x27: 0x0000000000000000
          x28: 0x0000000000000001 fp:  0xffffffeb0e15b660  lr:  0xfffffff007bd0168  sp:  0xffffffeb0e15b620
          pc:  0xfffffff007bd0174 cpsr: 0x80601204         esr: 0x96000044          far: 0xbfffffe4cb03aee4

Debugger message: panic
Device: D17
Hardware Model: iPhone14,5
```

As you can see above (and in the first blogpost in this series), this is `FFFFFFF007BD0174`:

```assembly
FFFFFFF007BD0174                 STR             W20, [X16,#4]
```

So, no - 7 arguments does not give us a good message size.

## Sum up

This is the last blogpost in this series. As I've said before (many times), my goal here was to spread knowledge and help security researchers better understand some fundamentals of iOS/macOS internals. I hope blogposts helped in doing so.

The code is in [this](https://github.com/saaramar/ipc_kmsg_blogpost_part3) repo. It leaks `kmsg->ikm_signature` and triggers the "ikm_validate_sig: full signature mismatch" panic.



I hope you enjoyed reading this blogpost.

Thanks,

Saar Amar





