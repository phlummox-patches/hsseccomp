
// Wrappers around libseccomp macros.

#include <unistd.h>
#include <seccomp.h>

// wrap SCMP_ACT_ERRNO macro
uint32_t SCMP_ACT_ERRNO_WRP(uint16_t errno) {
  return SCMP_ACT_ERRNO(errno);
}


// wrap SCMP_ACT_TRACE macro
uint32_t SCMP_ACT_TRACE_WRP(uint16_t msg_num) {
  return SCMP_ACT_TRACE(msg_num);
}

