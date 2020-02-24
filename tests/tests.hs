module Main where

import Control.Exception    (catch, SomeException)
import Control.Monad

import Foreign.C.Error      (resetErrno, getErrno, Errno(..) )

import System.Exit          (exitFailure, exitSuccess, ExitCode(..))
import System.IO
import System.Posix.IO      ( openFd, OpenMode(..), defaultFileFlags )
import System.Posix.Process (forkProcess, getProcessStatus, ProcessStatus(..))
import System.Posix.Signals (sigSYS)

import Test.Tasty
import Test.Tasty.HUnit

import qualified System.Linux.Seccomp as S

main :: IO ()
main = defaultMain unitTests

unitTests :: TestTree
unitTests = testGroup "Unit tests"
  [ testCase "init" $ do
        ctx <- S.seccomp_init S.SCMP_ACT_KILL
        S.seccomp_reset ctx S.SCMP_ACT_ALLOW
        S.seccomp_release ctx
  , testCase "allow open"  $ assertExitSuccess allowOpen
  , testCase "allow writing to only stdout and stderr"  $ 
                assertExitSuccess allowStdOutStdErr
  , testCase "kill on open for write"  $ assertTerminated killOpenWrite
  , testCase "setting errno instead of killing"  $ assertExitSuccess actErrno
  , testCase "change priority" $ do
        ctx <- S.seccomp_init S.SCMP_ACT_KILL
        S.seccomp_syscall_priority ctx S.SCopen 8
  ]


-- test export
-- S.seccomp_export_pfc ctx 2

whitelistHaskellRuntimeCalls :: S.FilterContext -> IO ()
--TODO check return values in error monad?
whitelistHaskellRuntimeCalls ctx = do
    S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW (Right S.SCclock_gettime) []
    S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW (Right S.SCrt_sigprocmask) []
    S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW (Right S.SCrt_sigaction) []
    S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW (Right S.SCrt_sigreturn) []
    S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW (Right S.SCtimer_settime) []
    S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW (Right S.SCtimer_delete) []
    S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW (Right S.SCclock_gettime) []
    S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW (Right S.SCexit_group) []
    S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW (Right S.SCselect) []
    S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW (Right S.SCpoll) []
    S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW (Right S.SCgetrusage) []
    S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW (Right S.SCpause) []
    -- TODO no idea what haskell is doing here. I guess it tries to find out whether stdout is an attached terminal
    -- uncomment when needed
    --_ <- Seccomp.seccomp_rule_add_array ctx Seccomp.SCMP_ACT_ALLOW Seccomp.SCioctl [Seccomp.ArgCmp 0 Seccomp.EQ 1 43, Seccomp.ArgCmp 1 Seccomp.EQ 0x5401 43]
    --_ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCshmctl []
    -- only allow write for stdout (fd 1)
    S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW (Right S.SCwrite) [S.ArgCmp 0 S.EQ 1]


allowOpen :: Assertion
allowOpen = do
    S.withFilterContext S.SCMP_ACT_KILL $ \ctx -> do
      S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW (Right S.SCopen) []
      S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW (Right S.SCopenat) []

      -- TODO it's annoying that we need to white list so many syscalls
      -- for the Haskell runtime but I can't think of a better solution
      -- ATM.
      whitelistHaskellRuntimeCalls ctx
      S.seccomp_load ctx
    void $ openFd "/dev/null" ReadOnly Nothing defaultFileFlags
    putStrLn "Hello World, this should be allowed"

allowStdOutStdErr :: Assertion
allowStdOutStdErr = do
    S.withFilterContext S.SCMP_ACT_KILL $ \ctx -> do
      whitelistHaskellRuntimeCalls ctx
      -- allow write for stderr (fd 2)
      S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW (Right S.SCwrite) [S.ArgCmp 0 S.EQ 2]
      S.seccomp_load ctx
    putStrLn "Hello World, this should be allowed"
    putStrLn  "This must also work"
    hPutStrLn stderr "This must also work"

killOpenWrite :: Assertion
killOpenWrite = do
    S.withFilterContext S.SCMP_ACT_ALLOW $ \ctx -> do
      -- kill on write: test for when the 1st arg to the
      -- open syscall (viz, "flags"), when masked with O_WRONLY
      -- (namely, 0x1) equals O_WRONLY.
      S.seccomp_rule_add_array ctx S.SCMP_ACT_KILL_PROCESS (Right S.SCopen) [S.ArgCmpMaskedEq 1 0x1 0x1]
      S.seccomp_load ctx
    void $ openFd "/dev/null" WriteOnly Nothing defaultFileFlags

actErrno :: Assertion
actErrno = do
    resetErrno
    S.withFilterContext (S.SCMP_ACT_ERRNO 42) $ \ctx -> do
    -- trying to capture the syscall that should fail with an errno we can test
      whitelistHaskellRuntimeCalls ctx
      S.seccomp_load ctx

    -- triggering prohibited action
    catch 
     (void $ System.IO.openFile "/dev/null" System.IO.ReadMode) $ \e -> do
       putStrLn ("caught error: " ++ show (e :: SomeException))
       Errno errno <- getErrno
       if errno == 42
         then void exitSuccess
         else putStrLn ("unexpected errno: " ++ show errno) >>
              void exitFailure
    putStrLn "unreachable"
    void exitFailure


assertExitSuccess :: IO () -> Assertion
assertExitSuccess f = do
    pid <- forkProcess f
    result <- getProcessStatus True False pid
    assertBool ("unexpected terminate: " ++ show result)
               (result == Just (Exited ExitSuccess))


assertTerminated :: IO () -> Assertion
assertTerminated f = do
    pid <- forkProcess f
    result <- getProcessStatus True False pid
    assertBool ("didn't terminate: " ++ show result)
               (result == Just (Terminated sigSYS False)
                  || result == Just (Terminated sigSYS True))
