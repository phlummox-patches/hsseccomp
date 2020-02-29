-- vim: syntax=haskell filetype=haskell :

{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE PatternSynonyms #-}

{- |
Module      : System.Linux.Seccomp
Stability   : provisional
Portability : non-portable (requires Linux)

This module provides low-level bindings to 
<https://github.com/seccomp/libseccomp libseccomp>.

A /filter/ is represented by a 'FilterContext',
containing multiple /rules/.
The FilterContext specifies a default 'Action',
which will be taken when none of the rules in
the filter apply.

A /rule/ is added using 'seccomp_rule_add' or
'seccomp_rule_add_array'.
Each rule specifies a particular system call which can trigger it,
represented by a 'SysCall'.
To create a rule which is triggered by /all/ invocations of a
syscall, regardless of the arguments to it, use 'seccomp_rule_add';
to create finer-grained rules, which apply only when the arguments
to a syscall satisfy particular conditions, each represented by an
'ArgCmp' object, use 'seccomp_rule_add_array'.
ArgCmp objects can be used to represent conditions like (for
instance) "the 2nd argument to the syscall is greater than 4".
A rule only matches if all its ArgCmp conditions match
(i.e., they are logically AND-ed); to get the effect of
a logical OR, add multiple rules.

__TODO__: clarify that our ArgCmp is for 64-bit values.

== Typical workflow

A typical workflow to create a filter which kills threads making
syscalls other than those whitelisted by a rule: 

-   Call 'seccomp_init' to get a 'FilterContext', and specify
    that the default action, when a syscall does not matching any 
    particular filter rule, is for the thread to be killed:

    @seccomp_init SCMP_ACT_KILL@

-   Call 'seccomp_rule_add' or 'seccomp_rule_add_array' to add
    filter rules to the current seccomp filter, specifying
    'SCMP_ACT_ALLOW' as the relevant action; i.e., rather than being
    killed, the relevant syscalls will be permitted.

-   Call 'seccomp_load' to activate the current seccomp filter
    by loading it into the kernel.

-   Call 'seccomp_release' on the FilterContext to release the
    resources allocated.

As a convenience, 'withFilterContext' is also provided, which handles
calling @seccomp_init@ and @seccomp_release@.

== Example: use seccomp_rule_add to forbid syscalls other than "@open@" 

Sample code to forbid any syscall other than "@open@":

>>> import System.Posix.Process
>>> import Control.Monad
>>> :{
  pid <- forkProcess $ do
    ctx <- seccomp_init SCMP_ACT_KILL_PROCESS
    seccomp_rule_add ctx SCMP_ACT_ALLOW (Right SCopen)
    seccomp_load ctx
    seccomp_release ctx
    Control.Monad.void $ readFile "/dev/null" -- process should die,
    -- not from 'open' call, but the other syscalls after it
:}

>>> getProcessStatus True False pid
Just (Terminated 31 True)

== Example: use seccomp_rule_add_array

For finer-grained control, 'seccomp_rule_add_array' can be used,
which lets you specify not just a syscall, but a particular
set of conditions based on arguments to the syscall, which
must be satisfied for the rule to apply.


Simple example: The following kills all system calls other than opening
a file for readonly:

> ctx <- S.seccomp_init S.SCMP_ACT_KILL
> _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCopen [S.ArgCmp 1 S.MASQUED_EQ 0x3 0x1]
> _ <- S.seccomp_load ctx
> S.seccomp_release ctx

For debugging it can be useful to dump a text representation of the filter
context to stderr (file descriptor number 2):

> S.seccomp_export_pfc ctx 2


== Requirements

Requires kernel 3.13 with backported seccomp or newer.

== Unimplemented features

The following are not implemented:

-   arch support (@seccomp_arch_add()@, @seccomp_arch_remove()@,
    @seccomp_arch_native()@)
-   @seccomp_attr_set()@ and @seccomp_attr_get()@
-   @seccomp_syscall_resolve_name_rewrite()@
-   @seccomp_api_get()@ and @seccomp_api_set()@
-   the @SCMP_ACT_NOTIFY@ action and the notification
    @API@ (@seccomp_notify_alloc@, @seccomp_notify_free@,
    @seccomp_notify_receive@, @seccomp_notify_respond@,
    @seccomp_notify_id_valid@, @seccomp_notify_fd@).

== Additional documentation:

See the Linux Kernel documentation at <https://www.kernel.org/doc>:

-   <https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt SECure COMPuting with filters>
-   <https://www.kernel.org/doc/Documentation/networking/filter.txt Linux Socket Filtering aka Berkeley Packet Filter (BPF)>

The libseccomp project site, with more information and the source
code for the library, can be found at
<https://github.com/seccomp/libseccomp>.

-}
module System.Linux.Seccomp
  ( 
  -- * Initialize the API
  
  -- | The 'seccomp_init' and 'seccomp_reset' functions (re)initialize the
  -- internal seccomp filter state. See further the documentation
  -- at
  -- <http://man7.org/linux/man-pages/man3/seccomp_init.3.html seccomp_init(3)>.
    seccomp_init
  , seccomp_reset
  , FilterContext(..)
  , Action(..)
  , withFilterContext
  -- * Add a seccomp filter rule

  -- | 
  -- Filter rules can be added 
  --
  -- @seccomp_rule_add@ and
  -- @seccomp_rule_add_array@ make a "best effort" to add the rule as
  -- specified, but may alter the rule slightly due to architecture
  -- specifics, e.g. socket and ipc functions on x86.
  -- While they do not guarantee an exact filter ruleset,
  -- the functions do guarantee the
  -- same behavior regardless of the architecture.
  --
  -- The newly added filter rule does not take effect until the entire
  -- filter is loaded into the kernel using 'seccomp_load'.
  --
  -- See further the documentation at
  -- <http://man7.org/linux/man-pages/man3/seccomp_rule_add.3.html seccomp_rule_add(3)>.
  , seccomp_rule_add
  , seccomp_rule_add_array
  , SysCall(..)
  , ArgCmp(..)
  , ArgCmpOp(..)
  , seccomp_syscall_resolve_name
  , seccomp_syscall_resolve_name_arch
  -- * Load and merge filters

  -- | See further the documentation at
  -- <http://man7.org/linux/man-pages/man3/seccomp_load.3.html seccomp_load(3)>
  -- and
  -- <http://man7.org/linux/man-pages/man3/seccomp_merge.3.html seccomp_merge(3)>.
  , seccomp_load
  , seccomp_merge
  -- * Prioritize syscalls in the seccomp filter

  -- | See further the documentation at 
  -- <http://man7.org/linux/man-pages/man3/seccomp_syscall_priority.3.html seccomp_syscall_priority(3)>.
  , seccomp_syscall_priority
  -- * Release the seccomp filter state

  -- | See further the documentation at
  -- <http://man7.org/linux/man-pages/man3/seccomp_release.3.html seccomp_release(3)>.
  , seccomp_release
  -- * Export filters to a file

  -- | These functions allow filters to be exported either in human
  -- readable format (PFC), or Berkley Packet Filter format (BPF),
  -- which can be serialized to and from disk, and loaded
  -- into a running kernel.
  --
  -- See further the documentation at
  -- <http://man7.org/linux/man-pages/man3/seccomp_export_pfc.3.html seccomp_export_bpf(3)>.
  , seccomp_export_pfc
  , h_seccomp_export_pfc
  , seccomp_export_bpf
  , h_seccomp_export_bpf
  -- * Obtain libseccomp version information
  
  -- | See further 
  -- <http://man7.org/linux/man-pages/man3/seccomp_version.3.html seccomp_version(3)>
  , seccomp_version
  , Version(..)
  )
  where

import Control.Exception
import Foreign
import Foreign.C
import System.IO
import System.Posix.Types
import System.Posix.IO

import System.Linux.Seccomp.Types
import System.Linux.Seccomp.Types.Internal (Arch(..)) 

-- the unistd.h is necessary because it defines the architecture
-- specific __NR_open system call values. Without this seccomp will
-- set the wrong values.

#include <unistd.h>
#include <seccomp.h>

-- | 
-- @
-- seccomp_init action
-- @
--
-- Initialize the
-- internal seccomp filter state, prepare it for use, and set
-- a default action; this action will be taken
-- if none of the rules in a filter apply.
--
-- @seccomp_init@
-- must be called before any other libseccomp functions as the
-- rest of the library API will fail if the filter context is not
-- initialized properly.
--
-- Throws an 'IOException' on failure.
seccomp_init :: Action -> IO FilterContext
seccomp_init action =
  FilterContext <$> 
    (throwErrnoIfNull "seccomp_init failed" $ 
        c'seccomp_init $ fromAction action)

-- | @withFilterContext action f@
--
-- Convenience function wrapping 'seccomp_init' and 'seccomp_release'.
-- Get a 'FilterContext' using @seccomp_init action@,
-- perform function @f@, then release the resources
-- used by the FilterContext.
withFilterContext :: Action -> (FilterContext -> IO c) -> IO c
withFilterContext action a =
  bracket acquire release a
  where
    acquire = seccomp_init action
    release = seccomp_release

-- |
-- @seccomp_reset ctx@ releases the
-- existing filter context state before reinitializing it and can only
-- be called after a call to 'seccomp_init' has succeeded.
--
-- The filter context @ctx@ is the value returned by a call to 
-- 'seccomp_init'.
--
-- Throws an 'IOException' on failure.
seccomp_reset :: FilterContext -> Action -> IO ()
seccomp_reset (FilterContext ctx) action = 
  throwErrnoIf_ (< 0) "seccomp_reset failed" $
    c'seccomp_reset ctx (fromAction action)

-- |
-- @
-- seccomp_release ctx
-- @
-- 
-- Releases the seccomp filter in @ctx@ which was first initialized by
-- 'seccomp_init' or 'seccomp_reset' and frees any memory associated
-- with the given seccomp filter context.  Any seccomp filters loaded
-- into the kernel are not affected.
seccomp_release :: FilterContext -> IO ()
seccomp_release (FilterContext ptr) = c'seccomp_release ptr

-- |
-- @
-- seccomp_load ctx
-- @
--
-- Load the current seccomp filter into the kernel.
--
-- The filter context @ctx@ is the value returned by a call to 
-- 'seccomp_init'.
--
-- Throws an 'IOException' on failure.
seccomp_load ::  FilterContext -> IO ()
seccomp_load (FilterContext ctx) = 
  throwErrnoIf_ (< 0) "seccomp_load failed" $
    c'seccomp_load ctx

-- |
-- @
-- seccomp_merge dst src
-- @
--
-- Merges the seccomp filter in @src@ with
-- the filter in @dst@ and stores the resulting in the @dst@ filter.
-- If successful, the @src@ seccomp filter is released and all internal
-- memory associated with the filter is freed; there is no need to call
-- 'seccomp_release' on @src@ and the caller should discard any
-- references to the filter.
-- The filter context @ctx@ is the value returned by a call to 
-- 'seccomp_init'.
-- 
-- In order to merge two seccomp filters, both filters must have the
-- same attribute values and no overlapping architectures.
--
-- Throws an 'IOException' on failure.
seccomp_merge ::  FilterContext -> FilterContext -> IO ()
seccomp_merge (FilterContext dst) (FilterContext src) = 
  throwErrnoIf_ (< 0) "seccomp_merge failed" $
    c'seccomp_merge dst src

-- | @seccomp_syscall_priority@ provides a priority hint to
-- the seccomp filter generator in libseccomp such that higher priority
-- syscalls are placed earlier in the seccomp filter code so that they
-- incur less overhead at the expense of lower priority syscalls. A
-- syscall's priority can be set regardless of if any rules currently
-- exist for that syscall; the library will remember the priority and
-- it will be assigned to the syscall if and when a rule for that
-- syscall is created.
--
-- @seccomp_syscall_priority ctx syscall priority@
-- provides a priority hint for @syscall@.
-- The filter context @ctx@ is the value returned by a call to 
-- 'seccomp_init'.
-- @syscall@ represents a particular system call.
-- @priority@ is a value from 0 to 255; a higher @priority@ value
-- represents a higher priority.
--
-- Throws an 'IOException' on failure.
-- 
-- Example:
--
-- >>> ctx <- seccomp_init SCMP_ACT_KILL_PROCESS
-- >>> seccomp_syscall_priority ctx SCopen 255 
--
-- This specifies that the "@open@" syscall
-- should have the highest priority (255).
seccomp_syscall_priority :: FilterContext -> SysCall -> Word8 -> IO ()
seccomp_syscall_priority (FilterContext ctx) sysCall priority = 
  throwErrnoIf_ (< 0) "seccomp_syscall_priority failed" $
    c'seccomp_syscall_priority ctx (fromSysCall sysCall) priority

-- | Export the seccomp filter in PFC (Pseudo Filter Code)
-- format. This format is human readable and is intended primarily
-- as a debugging tool for developers.
-- 
-- @
-- seccomp_export_pfc ctx fd
-- @
--
-- Export the current filter to file descriptor @fd@.
-- The filter context @ctx@ is the value returned by a call to 
-- 'seccomp_init'.
-- Throws an 'IOException' on failure.
seccomp_export_pfc :: FilterContext -> Fd -> IO ()
seccomp_export_pfc (FilterContext ctx) fd = 
  throwErrnoIf_ (< 0) "seccomp_export_pfc failed" $
    c'seccomp_export_pfc ctx fd

-- | @h_seccomp_export_pfc ctx hdl@:
--  call 'seccomp_export_pfc' on a 'Handle', using 'handleToFd'
-- to extract the file descriptor. This
-- has the side effect of closing the 'Handle' and flushing its write buffer.
--
-- The filter context @ctx@ is the value returned by a call to 
-- 'seccomp_init'.
--
-- Throws an 'IOException' on failure.
h_seccomp_export_pfc ::
  FilterContext -> Handle -> IO ()
h_seccomp_export_pfc ctx hdl = do
  handleToFd hdl >>= seccomp_export_pfc ctx

-- | Export the seccomp filter in BPF (Berkley Packet Filter)
-- format. This format is suitable for loading into the kernel.
--
-- @
-- seccomp_export_bpf ctx fd
-- @
--
-- Export the current filter to file descriptor @fd@.
-- The filter context @ctx@ is the value returned by a call to 
-- 'seccomp_init'.
--
-- Throws an 'IOException' on failure.
seccomp_export_bpf :: FilterContext -> Fd -> IO ()
seccomp_export_bpf (FilterContext ctx) fd = 
  throwErrnoIf_ (< 0) "seccomp_export_bpf failed" $
    c'seccomp_export_bpf ctx fd

-- | @h_seccomp_export_bpf ctx hdl@:
--  call 'seccomp_export_bpf' on a 'Handle', using 'handleToFd'
-- to extract the file descriptor. This
-- has the side effect of closing the 'Handle' and flushing its write buffer.
-- The filter context @ctx@ is the value returned by a call to 
-- 'seccomp_init'.
--
-- Throws an 'IOException' on failure.
--
-- Example:
--
-- >>> ctx <- seccomp_init SCMP_ACT_KILL
-- >>> withFile "/tmp/seccomp_filter.bpf" WriteMode $ h_seccomp_export_bpf ctx
--
-- The filter could then be loaded from file and loaded
-- using the <http://man7.org/linux/man-pages/man2/prctl.2.html prctl>
-- system call - for instance, with
-- C code like the following
-- (adapted from @pchaigno@ at <https://stackoverflow.com/a/57457620>):
--
-- > #include <linux/filter.h>
-- > // ^ provides 'struct sock_fprog'
-- > #include <sys/prctl.h>
-- > // ^ provides prctl()
-- >
-- > char buf[4096];
-- >
-- > int main(int argc, char ** argv) {
-- >   int length = read(0, buf, 4096) < 0);
-- >   if (length < 0) { exit(1); }
-- >
-- >   struct sock_fprog my_filter = { .len = length, .filter = buf };
-- >   int res = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &my_filter);
-- >   if (res == -1) { exit(1); }
-- >   // ...
-- > }
h_seccomp_export_bpf ::
  FilterContext -> Handle -> IO ()
h_seccomp_export_bpf ctx hdl = do
  handleToFd hdl >>= seccomp_export_bpf ctx

-- | 
-- @
-- seccomp_rule_add ctx action sysCall
-- @
--
-- Add a new filter rule to the current seccomp filter.
-- The filter context @ctx@ is the value returned by a call to 
-- 'seccomp_init'.
-- @action@ specifies an action to be taken.
-- @sysCall@ is a system call to which the rule
-- applies.
--
-- The rule will apply to all invocations of
-- @sysCall@, regardless of the value of its arguments.
--
-- Throws an 'IOException' on failure.
--
-- For finer-grained control over system calls,
-- use 'seccomp_rule_add_array', which allows you to specify
-- not just a syscall, but conditions on arguments to
-- the syscall.
seccomp_rule_add :: FilterContext -> Action -> Either String SysCall -> IO ()
seccomp_rule_add (FilterContext ctx) action sysCall =
  throwErrnoIf_ (< 0) "seccomp_rule_add failed" $ do
    sysCall' <- case sysCall of
          Left str -> seccomp_syscall_resolve_name str
          Right r  -> return $ fromSysCall r
    c'seccomp_rule_add0 ctx (fromAction action) sysCall'


-- | 
-- @
-- seccomp_rule_add_array ctx action sysCall argCmps
-- @
--
-- Add a new filter rule to the current seccomp filter.
-- The filter context @ctx@ is the value returned by a call to 
-- 'seccomp_init'.
-- @action@ specifies an action to be taken.
-- @sysCall@ is a system call to which the rule
-- applies.
-- @argCmps@ is a list of conditions based on the
-- values of the arguments to the syscall.
--
-- Throws an 'IOException' on failure.
seccomp_rule_add_array :: 
  FilterContext -> Action -> Either String SysCall -> [ArgCmp] -> IO ()
seccomp_rule_add_array (FilterContext ctx) action sysCall argCmps =
  throwErrnoIf_ (< 0) "seccomp_rule_add_array failed" $ do
    sysCall' <- case sysCall of
          Left str -> seccomp_syscall_resolve_name str
          Right r  -> return $ fromSysCall r
    withArrayLen argCmps (add sysCall')
  where
    add sysCall' len ptr = c'seccomp_rule_add_array
                    ctx
                    (fromAction action)
                    sysCall'
                    (fromIntegral len)
                    ptr


-- | Returns version information for the currently loaded libseccomp library.
-- This function can be used by applications that need to verify
-- that they are linked to a specific libseccomp version at runtime.
seccomp_version :: IO Version
seccomp_version =
    c'seccomp_version >>= peek

-- | 
-- @
-- seccomp_syscall_resolve_name str
-- @
-- Given a string representation @str@ of a syscall
-- name, return a 'CInt' which can be passed to 
-- 'seccomp_rule_add' or 'seccomp_rule_add_array'.
--
-- Throws an 'IOException' on failure.
seccomp_syscall_resolve_name :: String -> IO CInt
seccomp_syscall_resolve_name str =
  withCString str $ \cStr ->
    throwErrnoIf (== NR_SCMP_ERROR) "seccomp_syscall_resolve_name failed" $
       c'seccomp_syscall_resolve_name cStr

-- | 
-- @
-- seccomp_syscall_resolve_name_arch str arch
-- @
-- Given a string representation of a syscall
-- name @str@, and a particular architecture @arch@,
-- return a 'CInt' which can be passed to 
-- 'seccomp_rule_add' or 'seccomp_rule_add_array'.
--
-- Throws an 'IOException' on failure.
seccomp_syscall_resolve_name_arch :: String -> Arch -> IO CInt
seccomp_syscall_resolve_name_arch str arch =
  withCString str $ \cStr ->
     throwErrnoIf (== NR_SCMP_ERROR) "seccomp_syscall_resolve_name_arch failed" $
        c'seccomp_syscall_resolve_name cStr

--  scmp_filter_ctx seccomp_init(uint32_t def_action);
foreign import ccall unsafe "seccomp_init"
    c'seccomp_init :: Word32 -> IO (Ptr FilterContext)

--  void seccomp_release(scmp_filter_ctx ctx);
foreign import ccall unsafe "seccomp_release"
    c'seccomp_release :: Ptr FilterContext -> IO ()

foreign import ccall "seccomp_reset"
    c'seccomp_reset :: Ptr FilterContext -> Word32 -> IO CInt

foreign import ccall "seccomp_merge"
    c'seccomp_merge :: Ptr FilterContext -> Ptr FilterContext -> IO CInt

-- int seccomp_syscall_priority(scmp_filter_ctx ctx,
--                              int syscall, uint8_t priority);
foreign import ccall "seccomp_syscall_priority"
    c'seccomp_syscall_priority :: Ptr FilterContext -> CInt -> Word8 -> IO CInt


-- The variadic func seccomp_rule_add() would be
-- difficult to handle, so we don't.
--    int seccomp_rule_add(uint32_t action,
--                         int syscall, unsigned int arg_cnt, ...);
--
-- Except for the 0-arg case:
foreign import ccall "seccomp_rule_add0"
    c'seccomp_rule_add0 :: Ptr FilterContext -> Word32 -> CInt -> IO CInt


-- int seccomp_rule_add_array(scmp_filter_ctx ctx,
--                            uint32_t action, int syscall,
--                            unsigned int arg_cnt,
--                            const struct scmp_arg_cmp *arg_array);
foreign import ccall "seccomp_rule_add_array"
    c'seccomp_rule_add_array :: Ptr FilterContext -> Word32 -> CInt -> CUInt -> Ptr ArgCmp -> IO CInt

foreign import ccall "seccomp_load"
    c'seccomp_load :: Ptr FilterContext -> IO CInt

foreign import ccall "seccomp_export_pfc"
    c'seccomp_export_pfc :: Ptr FilterContext -> Fd -> IO CInt

foreign import ccall "seccomp_export_bpf"
    c'seccomp_export_bpf :: Ptr FilterContext -> Fd -> IO CInt

-- const struct scmp_version *seccomp_version(void)
foreign import ccall "seccomp_version"
    c'seccomp_version :: IO (Ptr Version)

-- int seccomp_syscall_resolve_name(const char *name);
foreign import ccall "seccomp_syscall_resolve_name"
    c'seccomp_syscall_resolve_name :: CString -> IO CInt

-- int seccomp_syscall_resolve_name_arch(uint32_t arch_token,
--                                       const char *name);
foreign import ccall "seccomp_syscall_resolve_name_arch"
    c'seccomp_syscall_resolve_name_arch :: Word32 -> CString -> IO CInt

-- | returned when seccomp_syscall_resolve_name fails.
pattern NR_SCMP_ERROR :: CInt
pattern NR_SCMP_ERROR = #{const __NR_SCMP_ERROR}



