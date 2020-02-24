
// Wrappers around seccomp_rule_add when 0 comparators
// are supplied.

#include <unistd.h>
#include <seccomp.h>

int seccomp_rule_add0(scmp_filter_ctx ctx, uint32_t action, int syscall) {
  return seccomp_rule_add(ctx, action, syscall, 0);
}



