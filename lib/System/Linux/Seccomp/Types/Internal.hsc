-- vim: syntax=haskell filetype=haskell noignorecase :

-- modelled off
-- <https://raw.githubusercontent.com/seccomp/libseccomp-golang/master/seccomp_internal.go>
--

module System.Linux.Seccomp.Types.Internal
  where

import Data.Bits
import Foreign
import Foreign.C

#include <errno.h>
#include <stdlib.h>
#include <seccomp.h>



{-# ANN module "HLint: ignore Use camelCase" #-}


--arch_bad :: Word32
#define ARCH_BAD 0xffffffff
-- i.e. an unused Word32 val

#ifndef SCMP_ARCH_PPC
#define SCMP_ARCH_PPC ARCH_BAD
#endif

#ifndef SCMP_ARCH_PPC64
#define SCMP_ARCH_PPC64 ARCH_BAD
#endif

#ifndef SCMP_ARCH_PPC64LE
#define SCMP_ARCH_PPC64LE ARCH_BAD
#endif

#ifndef SCMP_ARCH_S390
#define SCMP_ARCH_S390 ARCH_BAD
#endif

#ifndef SCMP_ARCH_S390X
#define SCMP_ARCH_S390X ARCH_BAD
#endif

data Arch =
    NATIVE
  | X86
  | X86_64
  | X32
  | ARM
  | AARCH64
  | MIPS
  | MIPS64
  | MIPS64N32
  | MIPSEL
  | MIPSEL64
  | MIPSEL64N32
  | PPC
  | PPC64
  | PPC64LE
  | S390
  | S390X
  deriving (Show, Eq)

fromArch :: Arch -> Word32
fromArch arch = case arch of
  NATIVE      -> #const SCMP_ARCH_NATIVE
  X86         -> #const SCMP_ARCH_X86
  X86_64      -> #const SCMP_ARCH_X86_64
  X32         -> #const SCMP_ARCH_X32
  ARM         -> #const SCMP_ARCH_ARM
  AARCH64     -> #const SCMP_ARCH_AARCH64
  MIPS        -> #const SCMP_ARCH_MIPS
  MIPS64      -> #const SCMP_ARCH_MIPS64
  MIPS64N32   -> #const SCMP_ARCH_MIPS64N32
  MIPSEL      -> #const SCMP_ARCH_MIPSEL
  MIPSEL64    -> #const SCMP_ARCH_MIPSEL64
  MIPSEL64N32 -> #const SCMP_ARCH_MIPSEL64N32
  PPC         -> #const SCMP_ARCH_PPC
  PPC64       -> #const SCMP_ARCH_PPC64
  PPC64LE     -> #const SCMP_ARCH_PPC64LE
  S390        -> #const SCMP_ARCH_S390
  S390X       -> #const SCMP_ARCH_S390X

#ifndef SCMP_ACT_LOG
#define SCMP_ACT_LOG 0x7ffc0000U
#endif

#ifndef SCMP_ACT_KILL_PROCESS
#define SCMP_ACT_KILL_PROCESS 0x80000000U
#endif

#ifndef SCMP_ACT_KILL_THREAD
#define SCMP_ACT_KILL_THREAD 0x00000000U
#endif

data Action =
    ACT_KILL
  | ACT_KILL_PROCESS
  | ACT_KILL_THREAD
  | ACT_TRAP
  | ACT_ERRNO Word16
  | ACT_TRACE Word16
  | ACT_LOG
  | ACT_ALLOW

fromAction :: Action -> Word32
fromAction x = case x of
  ACT_KILL          -> #const SCMP_ACT_KILL
  ACT_KILL_PROCESS  -> #const SCMP_ACT_KILL_PROCESS
  ACT_KILL_THREAD   -> #const SCMP_ACT_KILL_THREAD
  ACT_TRAP          -> #const SCMP_ACT_TRAP
  (ACT_ERRNO _n)    -> undefined -- SCMP_ACT_ERRNO(0)
  (ACT_TRACE _n)    -> undefined -- SCMP_ACT_TRACE(0)
  ACT_LOG           -> #const SCMP_ACT_LOG
  ACT_ALLOW         -> #const SCMP_ACT_ALLOW

-- then the CMP_NEs, etc


-- then Version



