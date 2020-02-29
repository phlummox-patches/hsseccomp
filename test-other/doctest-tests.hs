
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}
{-# OPTIONS_GHC -fno-warn-type-defaults #-}

module Main where

import Data.Monoid
import Test.DocTest
import System.FilePath.Glob
import System.IO
import Shelly hiding (FilePath)
import qualified Shelly as Sh
import qualified Data.Text as T
import System.Environment
import System.FilePath as FP
import qualified Data.List as L

-- Requires the test-doctests flag to be enabled,
-- and the STACK_RESOLVER environment variable to
-- be defined (specifying a resolver to use, e.g.
-- "lts-14").

default (T.Text)

{-# ANN module ("HLint: ignore Eta reduce" :: String) #-}
{-# ANN module ("HLint: ignore Use camelCase" :: String) #-}

withText :: (String -> String) -> T.Text -> T.Text
withText f = T.pack . f . T.unpack

get_packages :: Sh [T.Text]
get_packages =
  T.words <$> run "ghc-pkg" ["list", "--simple-output", "--names-only"]

bad_packages :: [T.Text]
bad_packages = [
    "cryptohash"
  , "cryptohash-sha256"
  ]

-- | if they are present, try to hide packages
-- which will clash
get_package_hiding_opts :: Sh [String]
get_package_hiding_opts = do
  packages <- get_packages
  return $ concat
        [ args | pkg <- packages,
                 pkg `elem` bad_packages,
                 let args = map T.unpack ["-hide-package", pkg]]


must_have_stack_resolver :: Sh ()
must_have_stack_resolver =
  get_env "STACK_RESOLVER" >>= \case
      Nothing -> terror "STACK_RESOLVER env var not set, exiting"
      Just{}  -> return ()


-- | for each .hsc file, find the .hs file produced by hsc2hs.
processedHscFiles :: Sh [Sh.FilePath]
processedHscFiles = do
    hscFiles <- findWhen (return . hasExt "hsc") "src"
    resolver <- get_env_text "STACK_RESOLVER"
    dist_dir <- fromText . T.strip <$> run "stack" ["--resolver=" <> resolver, "path",  "--dist-dir"]
    let expectedHsFiles = 
          asStr ((-<.> ".hs") . dropDir) . toTextIgnore <$> hscFiles
    L.nub . concat <$> 
          mapM (findMatches dist_dir) expectedHsFiles
    where
      findMatches dir hs = 
        findWhen (\x -> return $ hs `isSuffixOfP` x) dir


      xs `isSuffixOfP` p = xs `T.isSuffixOf` toTextIgnore p

objFiles :: Sh [Sh.FilePath]
objFiles = do
    cFiles <- findWhen (return . hasExt "c") "cbits"
    resolver <- get_env_text "STACK_RESOLVER"
    dist_dir <- fromText . T.strip <$> run "stack" ["--resolver=" <> resolver, "path",  "--dist-dir"]
    let expectedObjFiles = asStr (-<.> ".o") . toTextIgnore <$> cFiles
    concat <$> mapM (\hs -> findWhen (\x -> return $ hs `T.isSuffixOf` toTextIgnore x) dist_dir) expectedObjFiles
     

tShow :: Show a => a -> T.Text
tShow = T.pack . show


dropDir :: FilePath -> FilePath
dropDir f = 
  case splitPath f of
    _x:xs -> joinPath xs
    _     -> error $ "can't drop dir from " ++ show f


asStr :: (String -> String) -> T.Text -> T.Text
asStr f = T.pack . f . T.unpack

main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  args <- getArgs
  putStrLn $ "\ndoctest-test. args: " ++ show args
  package_hiding_opts <- shelly $ silently $ do
    must_have_stack_resolver
    -- hide some packages which are quite likely to be installed,
    -- and which cause doctest to melt down with a
    -- "Ambiguous module name ‘XXX’..." error.
    get_package_hiding_opts
  srcFiles <- concat <$> globDir [compile "**/*.hs"] "src"
  hsFiles <- shelly $ silently $ map (T.unpack . toTextIgnore) <$> processedHscFiles
  objs <- shelly $ silently $ map (T.unpack . toTextIgnore) <$> objFiles 
  putStrLn $ ".hs source files being tested: " ++ show srcFiles
  putStrLn $ ".hs source files generated bg hsc2hs: " ++ show hsFiles
  putStrLn $ "object files: " ++ show objs
  let doctestOpts :: [String]
      doctestOpts = ["-isrc", "-lseccomp"] <> args -- <> ["--verbose"]
                     <> package_hiding_opts <> objs
  putStrLn $ "docTestOpts: " ++ show doctestOpts
  hFlush stdout
  -- actually run tests
  doctest $ doctestOpts ++ (srcFiles ++ hsFiles)

