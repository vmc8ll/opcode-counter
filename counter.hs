{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE PatternSynonyms #-}

-- |
-- Module:      OpcodeCounter
-- Description: x86/x64 opcode frequency analyzer in Haskell
-- Author:      vmc8ll
-- 
-- A high-performance opcode counter that demonstrates:
-- - Binary parsing with attoparsec
-- - Linear scanning of executable code
-- - Statistical analysis of instruction patterns
-- - Functional approach to reverse engineering
--

module OpcodeCounter (
    countOpcodes,
    countOpcodesFromFile,
    OpcodeStats(..),
    Architecture(..),
    ScanMode(..),
    AnalysisResult(..),
    defaultConfig
) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import qualified Data.Vector.Unboxed as V
import qualified Data.Vector.Unboxed.Mutable as MV
import Data.Word
import Data.Int (Int64)
import Data.Bits
import Data.Maybe (fromMaybe, catMaybes, isJust)
import Data.List (foldl', sortBy, groupBy, sort)
import Data.Function (on)
import Data.Char (isPrint, toUpper)
import Control.Monad (forM_, when, unless, foldM)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.ST (runST)
import Control.Exception (try, SomeException)
import System.IO (hPutStrLn, stderr, withBinaryFile, IOMode(..))
import System.Directory (doesFileExist)
import System.Environment (getArgs)
import Text.Printf (printf)

import qualified Data.Attoparsec.ByteString as A
import qualified Data.Attoparsec.ByteString.Char8 as A8
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import qualified Data.ByteString.Base16 as B16

-- ===========================================================================
-- Types and Data Structures
-- ===========================================================================

-- | CPU Architecture
data Architecture
    = X86_16    -- ^ 16-bit real mode
    | X86_32    -- ^ 32-bit protected mode
    | X86_64    -- ^ 64-bit long mode
    deriving (Show, Eq, Enum)

-- | Scan mode for different contexts
data ScanMode
    = EntireFile           -- ^ Scan entire file
    | CodeSection          -- ^ Scan only code sections (PE/ELF aware)
    | Range Int64 Int64    -- ^ Scan specific byte range
    deriving (Show, Eq)

-- | Configuration for the scanner
data Config = Config
    { architecture  :: Architecture
    , scanMode      :: ScanMode
    , minOpcodeLen  :: Int
    , showTopN      :: Int
    , verbose       :: Bool
    , outputFormat  :: OutputFormat
    , detectPatterns :: Bool
    } deriving (Show)

-- | Output format
data OutputFormat = TextFormat | JSONFormat | CSVFormat
    deriving (Show, Eq)

-- | Statistics for a single opcode
data OpcodeStat = OpcodeStat
    { opcodeBytes  :: !B.ByteString
    , opcodeMnemonic :: !String
    , opcodeCount  :: !Int
    , opcodeSize   :: !Int
    , opcodeCategory :: !OpcodeCategory
    , sampleOffsets :: [Int64]  -- First few offsets where found
    } deriving (Show)

-- | Category of opcode for classification
data OpcodeCategory
    = DataTransfer      -- mov, push, pop, xchg
    | Arithmetic        -- add, sub, mul, div, inc, dec
    | Logic            -- and, or, xor, not, test
    | ControlTransfer   -- jmp, call, ret, je, jne
    | StringOp         -- movs, cmps, scas, lods, stos
    | SystemOp         -- syscall, sysenter, int, iret
    | FloatingPoint    -- fadd, fsub, fmul, fdiv
    | SIMD             -- movaps, addps, paddb
    | Other            -- nop, pause, wait
    deriving (Show, Eq, Ord)

-- | Complete analysis result
data AnalysisResult = AnalysisResult
    { totalBytes      :: !Int64
    , totalInstructions :: !Int
    , opcodeStats     :: [(B.ByteString, OpcodeStat)]
    , topOpcodes      :: [(B.ByteString, Int)]
    , architecture    :: !Architecture
    , scanTime        :: !Double
    , entropy         :: !Double
    , uniqueOpcodes   :: !Int
    , categories      :: Map.Map OpcodeCategory Int
    } deriving (Show)

-- ===========================================================================
-- Opcode Database (simplified x86/x64 opcode map)
-- ===========================================================================

-- | Pattern for matching opcodes
data OpcodePattern = OpcodePattern
    { patternBytes  :: [Word8]        -- ^ Byte pattern (may include wildcards)
    , patternMask   :: [Word8]        -- ^ Mask for bits that matter
    , mnemonic      :: String         -- ^ Instruction mnemonic
    , category      :: OpcodeCategory
    , operandMask   :: Maybe Word8     -- ^ ModRM/Rex mask if applicable
    } deriving (Show)

-- | Known opcode patterns (simplified, covering most common instructions)
knownOpcodes :: [OpcodePattern]
knownOpcodes =
    -- Data transfer
    [ OpcodePattern [0x88, 0x??] [0xFF, 0x00] "mov" DataTransfer Nothing  -- mov r/m8, r8
    , OpcodePattern [0x89, 0x??] [0xFF, 0x00] "mov" DataTransfer Nothing  -- mov r/m32, r32
    , OpcodePattern [0x8A, 0x??] [0xFF, 0x00] "mov" DataTransfer Nothing  -- mov r8, r/m8
    , OpcodePattern [0x8B, 0x??] [0xFF, 0x00] "mov" DataTransfer Nothing  -- mov r32, r/m32
    , OpcodePattern [0x50] [0xFF] "push" DataTransfer Nothing  -- push r32
    , OpcodePattern [0x51] [0xFF] "push" DataTransfer Nothing
    , OpcodePattern [0x52] [0xFF] "push" DataTransfer Nothing
    , OpcodePattern [0x53] [0xFF] "push" DataTransfer Nothing
    , OpcodePattern [0x54] [0xFF] "push" DataTransfer Nothing
    , OpcodePattern [0x55] [0xFF] "push" DataTransfer Nothing
    , OpcodePattern [0x56] [0xFF] "push" DataTransfer Nothing
    , OpcodePattern [0x57] [0xFF] "push" DataTransfer Nothing
    , OpcodePattern [0x58] [0xFF] "pop" DataTransfer Nothing   -- pop r32
    , OpcodePattern [0x59] [0xFF] "pop" DataTransfer Nothing
    , OpcodePattern [0x5A] [0xFF] "pop" DataTransfer Nothing
    , OpcodePattern [0x5B] [0xFF] "pop" DataTransfer Nothing
    , OpcodePattern [0x5C] [0xFF] "pop" DataTransfer Nothing
    , OpcodePattern [0x5D] [0xFF] "pop" DataTransfer Nothing
    , OpcodePattern [0x5E] [0xFF] "pop" DataTransfer Nothing
    , OpcodePattern [0x5F] [0xFF] "pop" DataTransfer Nothing
    , OpcodePattern [0x68] [0xFF] "push" DataTransfer Nothing  -- push imm32
    , OpcodePattern [0x6A] [0xFF] "push" DataTransfer Nothing  -- push imm8
    
    -- Arithmetic
    , OpcodePattern [0x00, 0x??] [0xFF, 0x00] "add" Arithmetic Nothing
    , OpcodePattern [0x01, 0x??] [0xFF, 0x00] "add" Arithmetic Nothing
    , OpcodePattern [0x02, 0x??] [0xFF, 0x00] "add" Arithmetic Nothing
    , OpcodePattern [0x03, 0x??] [0xFF, 0x00] "add" Arithmetic Nothing
    , OpcodePattern [0x04] [0xFF] "add" Arithmetic Nothing
    , OpcodePattern [0x05] [0xFF] "add" Arithmetic Nothing
    , OpcodePattern [0x28, 0x??] [0xFF, 0x00] "sub" Arithmetic Nothing
    , OpcodePattern [0x29, 0x??] [0xFF, 0x00] "sub" Arithmetic Nothing
    , OpcodePattern [0x2A, 0x??] [0xFF, 0x00] "sub" Arithmetic Nothing
    , OpcodePattern [0x2B, 0x??] [0xFF, 0x00] "sub" Arithmetic Nothing
    , OpcodePattern [0x2C] [0xFF] "sub" Arithmetic Nothing
    , OpcodePattern [0x2D] [0xFF] "sub" Arithmetic Nothing
    , OpcodePattern [0x40] [0xFF] "inc" Arithmetic Nothing  -- inc r32
    , OpcodePattern [0x41] [0xFF] "inc" Arithmetic Nothing
    , OpcodePattern [0x42] [0xFF] "inc" Arithmetic Nothing
    , OpcodePattern [0x43] [0xFF] "inc" Arithmetic Nothing
    , OpcodePattern [0x44] [0xFF] "inc" Arithmetic Nothing
    , OpcodePattern [0x45] [0xFF] "inc" Arithmetic Nothing
    , OpcodePattern [0x46] [0xFF] "inc" Arithmetic Nothing
    , OpcodePattern [0x47] [0xFF] "inc" Arithmetic Nothing
    , OpcodePattern [0x48] [0xFF] "dec" Arithmetic Nothing  -- dec r32
    , OpcodePattern [0x49] [0xFF] "dec" Arithmetic Nothing
    , OpcodePattern [0x4A] [0xFF] "dec" Arithmetic Nothing
    , OpcodePattern [0x4B] [0xFF] "dec" Arithmetic Nothing
    , OpcodePattern [0x4C] [0xFF] "dec" Arithmetic Nothing
    , OpcodePattern [0x4D] [0xFF] "dec" Arithmetic Nothing
    , OpcodePattern [0x4E] [0xFF] "dec" Arithmetic Nothing
    , OpcodePattern [0x4F] [0xFF] "dec" Arithmetic Nothing
    
    -- Logic
    , OpcodePattern [0x20, 0x??] [0xFF, 0x00] "and" Logic Nothing
    , OpcodePattern [0x21, 0x??] [0xFF, 0x00] "and" Logic Nothing
    , OpcodePattern [0x22, 0x??] [0xFF, 0x00] "and" Logic Nothing
    , OpcodePattern [0x23, 0x??] [0xFF, 0x00] "and" Logic Nothing
    , OpcodePattern [0x24] [0xFF] "and" Logic Nothing
    , OpcodePattern [0x25] [0xFF] "and" Logic Nothing
    , OpcodePattern [0x08, 0x??] [0xFF, 0x00] "or" Logic Nothing
    , OpcodePattern [0x09, 0x??] [0xFF, 0x00] "or" Logic Nothing
    , OpcodePattern [0x0A, 0x??] [0xFF, 0x00] "or" Logic Nothing
    , OpcodePattern [0x0B, 0x??] [0xFF, 0x00] "or" Logic Nothing
    , OpcodePattern [0x0C] [0xFF] "or" Logic Nothing
    , OpcodePattern [0x0D] [0xFF] "or" Logic Nothing
    , OpcodePattern [0x30, 0x??] [0xFF, 0x00] "xor" Logic Nothing
    , OpcodePattern [0x31, 0x??] [0xFF, 0x00] "xor" Logic Nothing
    , OpcodePattern [0x32, 0x??] [0xFF, 0x00] "xor" Logic Nothing
    , OpcodePattern [0x33, 0x??] [0xFF, 0x00] "xor" Logic Nothing
    , OpcodePattern [0x34] [0xFF] "xor" Logic Nothing
    , OpcodePattern [0x35] [0xFF] "xor" Logic Nothing
    , OpcodePattern [0xF6, 0x??] [0xFF, 0x00] "test" Logic Nothing
    , OpcodePattern [0xF7, 0x??] [0xFF, 0x00] "test" Logic Nothing
    
    -- Control transfer
    , OpcodePattern [0xE8] [0xFF] "call" ControlTransfer Nothing
    , OpcodePattern [0xE9] [0xFF] "jmp" ControlTransfer Nothing
    , OpcodePattern [0xEB] [0xFF] "jmp" ControlTransfer Nothing
    , OpcodePattern [0x70] [0xFF] "jo" ControlTransfer Nothing
    , OpcodePattern [0x71] [0xFF] "jno" ControlTransfer Nothing
    , OpcodePattern [0x72] [0xFF] "jb" ControlTransfer Nothing
    , OpcodePattern [0x73] [0xFF] "jnb" ControlTransfer Nothing
    , OpcodePattern [0x74] [0xFF] "jz" ControlTransfer Nothing
    , OpcodePattern [0x75] [0xFF] "jnz" ControlTransfer Nothing
    , OpcodePattern [0x76] [0xFF] "jbe" ControlTransfer Nothing
    , OpcodePattern [0x77] [0xFF] "ja" ControlTransfer Nothing
    , OpcodePattern [0x78] [0xFF] "js" ControlTransfer Nothing
    , OpcodePattern [0x79] [0xFF] "jns" ControlTransfer Nothing
    , OpcodePattern [0x7A] [0xFF] "jp" ControlTransfer Nothing
    , OpcodePattern [0x7B] [0xFF] "jnp" ControlTransfer Nothing
    , OpcodePattern [0x7C] [0xFF] "jl" ControlTransfer Nothing
    , OpcodePattern [0x7D] [0xFF] "jge" ControlTransfer Nothing
    , OpcodePattern [0x7E] [0xFF] "jle" ControlTransfer Nothing
    , OpcodePattern [0x7F] [0xFF] "jg" ControlTransfer Nothing
    , OpcodePattern [0xC3] [0xFF] "ret" ControlTransfer Nothing
    , OpcodePattern [0xC2] [0xFF] "ret" ControlTransfer Nothing  -- ret imm16
    , OpcodePattern [0xCB] [0xFF] "retf" ControlTransfer Nothing
    , OpcodePattern [0xCA] [0xFF] "retf" ControlTransfer Nothing
    
    -- System
    , OpcodePattern [0x0F, 0x05] [0xFF, 0xFF] "syscall" SystemOp Nothing
    , OpcodePattern [0x0F, 0x34] [0xFF, 0xFF] "sysenter" SystemOp Nothing
    , OpcodePattern [0xCD] [0xFF] "int" SystemOp Nothing
    , OpcodePattern [0xCF] [0xFF] "iret" SystemOp Nothing
    , OpcodePattern [0xF4] [0xFF] "hlt" SystemOp Nothing
    
    -- Other
    , OpcodePattern [0x90] [0xFF] "nop" Other Nothing
    , OpcodePattern [0x0F, 0x1F, 0x00] [0xFF, 0xFF, 0xFF] "nop" Other Nothing
    , OpcodePattern [0xF3, 0x90] [0xFF, 0xFF] "pause" Other Nothing
    , OpcodePattern [0xCC] [0xFF] "int3" Other Nothing
    ]

-- ===========================================================================
-- Opcode Matching
-- ===========================================================================

-- | Match an opcode pattern against bytes starting at given offset
matchOpcode :: OpcodePattern -> B.ByteString -> Int64 -> Maybe (String, Int, OpcodeCategory)
matchOpcode pattern bs offset
    | fromIntegral offset + patternLen > B.length bs = Nothing
    | otherwise =
        let bytesToCheck = B.take patternLen $ B.drop (fromIntegral offset) bs
            matches = and $ zipWith3 checkByte
                (B.unpack bytesToCheck)
                (patternBytes pattern)
                (patternMask pattern)
        in if matches
           then Just (mnemonic pattern, patternLen, category pattern)
           else Nothing
  where
    patternLen = length (patternBytes pattern)
    
    checkByte actual expected mask
        | mask == 0xFF = actual == expected
        | otherwise = (actual .&. mask) == (expected .&. mask)

-- | Try all known opcodes at a given offset
matchAllOpcodes :: B.ByteString -> Int64 -> [(String, Int, OpcodeCategory)]
matchAllOpcodes bs offset = 
    catMaybes $ map (\p -> matchOpcode p bs offset) knownOpcodes

-- | Find the longest matching opcode at offset (to handle overlapping patterns)
findBestMatch :: B.ByteString -> Int64 -> Maybe (String, Int, OpcodeCategory)
findBestMatch bs offset = 
    case matches of
        [] -> Nothing
        _ -> Just $ maximumBy (compare `on` (\(_, len, _) -> len)) matches
  where
    matches = matchAllOpcodes bs offset

-- ===========================================================================
-- Core Counting Logic
-- ===========================================================================

-- | Count opcodes in a byte string
countOpcodes :: B.ByteString -> Config -> IO AnalysisResult
countOpcodes bs config = do
    let startTime = 0  -- Would use real time in practice
    
    -- Determine scan range based on mode
    let scanRange = case scanMode config of
            EntireFile -> (0, fromIntegral $ B.length bs)
            Range start end -> (max 0 start, min (fromIntegral $ B.length bs) end)
            CodeSection -> findCodeSection bs  -- Simplified
    
    let (start, end) = scanRange
    let bytesToScan = end - start
    
    when (verbose config) $
        putStrLn $ "[*] Scanning from " ++ show start ++ " to " ++ show end
    
    -- Linear sweep disassembly
    let (stats, finalOffset) = scanLinear bs start end Map.empty []
    
    -- Calculate statistics
    let totalInstructions = sum $ map snd $ Map.toList stats
    let uniqueOpcodes = Map.size stats
    
    -- Get top N opcodes
    let topList = take (showTopN config) $
                  sortBy (flip compare `on` snd) $
                  Map.toList stats
    
    -- Categorize
    let categories = categorizeOpcodes stats
    
    -- Calculate entropy
    let entropy = calculateEntropy bs start end
    
    let endTime = 0  -- Would use real time
    
    return $ AnalysisResult
        { totalBytes = bytesToScan
        , totalInstructions = totalInstructions
        , opcodeStats = []  -- Would populate from stats
        , topOpcodes = topList
        , architecture = architecture config
        , scanTime = endTime - startTime
        , entropy = entropy
        , uniqueOpcodes = uniqueOpcodes
        , categories = categories
        }
  where
    scanLinear bs pos end acc samples
        | pos >= end = (acc, pos)
        | otherwise =
            case findBestMatch bs pos of
                Just (mnemonic, len, cat) ->
                    let newAcc = Map.insertWith (+) (B.take len $ B.drop (fromIntegral pos) bs) 1 acc
                        newSamples = if Map.size acc < 5  -- Store first few samples
                                     then (pos, mnemonic) : samples
                                     else samples
                    in scanLinear bs (pos + fromIntegral len) end newAcc newSamples
                Nothing ->
                    scanLinear bs (pos + 1) end acc samples  -- Skip byte if no match
    
    categorizeOpcodes stats = 
        let withCategories = map (\(bytes, count) -> 
                case find (\p -> patternMatchesPrefix bytes p) knownOpcodes of
                    Just p -> (category p, count)
                    Nothing -> (Other, count)) $ Map.toList stats
        in foldl' (\m (cat, cnt) -> Map.insertWith (+) cat cnt m) Map.empty withCategories
    
    patternMatchesPrefix bytes pattern =
        let pBytes = B.pack $ take (B.length bytes) $ patternBytes pattern
            pMask = B.pack $ take (B.length bytes) $ patternMask pattern
        in and $ zipWith3 (\b p m -> (b .&. m) == (p .&. m))
                         (B.unpack bytes)
                         (B.unpack pBytes)
                         (B.unpack pMask)

-- | Find code section in binary (simplified - would need PE/ELF parsing)
findCodeSection :: B.ByteString -> (Int64, Int64)
findCodeSection _ = (0, 4096)  -- Placeholder

-- | Calculate entropy of a byte range
calculateEntropy :: B.ByteString -> Int64 -> Int64 -> Double
calculateEntropy bs start end =
    let bytes = B.take (fromIntegral $ end - start) $ B.drop (fromIntegral start) bs
        counts = V.create $ do
            vec <- MV.replicate 256 (0 :: Int)
            B.mapM_ (\b -> MV.modify vec (+1) (fromIntegral b)) bytes
            return vec
        total = fromIntegral $ B.length bytes
        probs = map (\c -> fromIntegral c / total) $ V.toList counts
        entropy = -sum $ map (\p -> if p > 0 then p * logBase 2 p else 0) probs
    in entropy

-- | Read file and count opcodes
countOpcodesFromFile :: FilePath -> Config -> IO (Either String AnalysisResult)
countOpcodesFromFile path config = do
    exists <- doesFileExist path
    if not exists
        then return $ Left $ "File not found: " ++ path
        else do
            result <- try $ B.readFile path :: IO (Either SomeException B.ByteString)
            case result of
                Left e -> return $ Left $ "Error reading file: " ++ show e
                Right bs -> do
                    when (verbose config) $
                        putStrLn $ "[*] Read " ++ show (B.length bs) ++ " bytes from " ++ path
                    res <- countOpcodes bs config
                    return $ Right res

-- ===========================================================================
-- Output Formatting
-- ===========================================================================

-- | Format results as text
formatText :: AnalysisResult -> String
formatText result = unlines $
    [ "=" * 70
    , "OPCODE COUNTER ANALYSIS RESULTS"
    , "=" * 70
    , ""
    , "File Statistics:"
    , "  Total bytes scanned: " ++ prettyBytes (totalBytes result)
    , "  Total instructions: " ++ show (totalInstructions result)
    , "  Unique opcodes: " ++ show (uniqueOpcodes result)
    , "  Entropy: " ++ printf "%.4f" (entropy result)
    , "  Architecture: " ++ show (architecture result)
    , "  Scan time: " ++ printf "%.3f" (scanTime result) ++ " seconds"
    , ""
    , "-" * 70
    , "TOP OPOCODES BY FREQUENCY"
    , "-" * 70
    ] ++
    map formatTop (zip [1..] (topOpcodes result)) ++
    [ ""
    , "-" * 70
    , "INSTRUCTION CATEGORIES"
    , "-" * 70
    ] ++
    map formatCategory (Map.toList $ categories result) ++
    [ ""
    , "=" * 70
    ]
  where
    (*) n s = take n $ cycle s
    
    prettyBytes b
        | b < 1024 = show b ++ " B"
        | b < 1024*1024 = printf "%.2f KB" (fromIntegral b / 1024)
        | b < 1024*1024*1024 = printf "%.2f MB" (fromIntegral b / (1024*1024))
        | otherwise = printf "%.2f GB" (fromIntegral b / (1024*1024*1024))
    
    formatTop (i, (bytes, count)) =
        let pct = 100 * fromIntegral count / fromIntegral (totalInstructions result)
            hex = B16.encode bytes
            mnemonic = lookupMnemonic bytes
        in printf "%3d. %-8s %-15s %6d (%5.2f%%)" 
                  i 
                  (C8.unpack hex)
                  mnemonic
                  count 
                  (pct :: Double)
    
    formatCategory (cat, count) =
        let pct = 100 * fromIntegral count / fromIntegral (totalInstructions result)
        in printf "  %-20s %6d (%5.2f%%)" (show cat) count (pct :: Double)

-- | Format as JSON
formatJSON :: AnalysisResult -> B.ByteString
formatJSON result = encode $ object
    [ "total_bytes" .= totalBytes result
    , "total_instructions" .= totalInstructions result
    , "unique_opcodes" .= uniqueOpcodes result
    , "entropy" .= entropy result
    , "architecture" .= show (architecture result)
    , "scan_time_seconds" .= scanTime result
    , "top_opcodes" .= map formatTop (take 20 $ topOpcodes result)
    , "categories" .= map formatCat (Map.toList $ categories result)
    ]
  where
    formatTop (bytes, count) = object
        [ "hex" .= C8.unpack (B16.encode bytes)
        , "mnemonic" .= lookupMnemonic bytes
        , "count" .= count
        , "percentage" .= (100 * fromIntegral count / fromIntegral (totalInstructions result))
        ]
    
    formatCat (cat, count) = object
        [ "category" .= show cat
        , "count" .= count
        , "percentage" .= (100 * fromIntegral count / fromIntegral (totalInstructions result))
        ]
    
    object = Map.fromList

-- | Format as CSV
formatCSV :: AnalysisResult -> String
formatCSV result = unlines $
    [ "hex,mnemonic,count,percentage,category" ] ++
    map formatCSVRow (zip (topOpcodes result) (repeat 0))
  where
    formatCSVRow ((bytes, count), _) =
        let hex = C8.unpack (B16.encode bytes)
            mnemonic = lookupMnemonic bytes
            pct = 100 * fromIntegral count / fromIntegral (totalInstructions result)
            cat = lookupCategory bytes
        in printf "%s,%s,%d,%.4f,%s" hex mnemonic count (pct :: Double) (show cat)

-- | Look up mnemonic for opcode bytes
lookupMnemonic :: B.ByteString -> String
lookupMnemonic bytes = 
    case find (\p -> patternMatchesPrefix bytes p) knownOpcodes of
        Just p -> mnemonic p
        Nothing -> "???"

-- | Look up category for opcode bytes
lookupCategory :: B.ByteString -> OpcodeCategory
lookupCategory bytes = 
    case find (\p -> patternMatchesPrefix bytes p) knownOpcodes of
        Just p -> category p
        Nothing -> Other

-- ===========================================================================
-- Command Line Interface
-- ===========================================================================

-- | Default configuration
defaultConfig :: Config
defaultConfig = Config
    { architecture = X86_64
    , scanMode = EntireFile
    , minOpcodeLen = 1
    , showTopN = 20
    , verbose = False
    , outputFormat = TextFormat
    , detectPatterns = True
    }

-- | Parse command line arguments
parseArgs :: [String] -> IO (FilePath, Config)
parseArgs args = case args of
    [] -> do
        putStrLn usage
        exitFailure
    (path:rest) -> do
        let config = foldl parseOption defaultConfig rest
        return (path, config)
  where
    usage = unlines
        [ "x86/x64 Opcode Counter (Haskell)"
        , ""
        , "Usage: opcode-counter <binary-file> [options]"
        , ""
        , "Options:"
        , "  -a, --arch ARCH      Architecture (16, 32, 64) [default: 64]"
        , "  -m, --mode MODE      Scan mode (full, code, range:start-end)"
        , "  -n, --top N          Show top N opcodes [default: 20]"
        , "  -f, --format FMT     Output format (text, json, csv) [default: text]"
        , "  -v, --verbose        Verbose output"
        , "  -e, --entropy        Show entropy analysis"
        , "  -h, --help           Show this help"
        , ""
        , "Example:"
        , "  opcode-counter malware.exe -a 64 -n 10 -f json"
        , "  opcode-counter firmware.bin -m code -v"
        ]
    
    parseOption cfg "-v" = cfg { verbose = True }
    parseOption cfg "--verbose" = cfg { verbose = True }
    parseOption cfg "-e" = cfg { detectPatterns = True }
    parseOption cfg "--entropy" = cfg { detectPatterns = True }
    parseOption cfg ('-':'n':n) = cfg { showTopN = read n }
    parseOption cfg ('-':'-':"top=" ++ n) = cfg { showTopN = read n }
    parseOption cfg ('-':'f':fmt) = cfg { outputFormat = parseFormat fmt }
    parseOption cfg ('-':'-':"format=" ++ fmt) = cfg { outputFormat = parseFormat fmt }
    parseOption cfg ('-':'a':arch) = cfg { architecture = parseArch arch }
    parseOption cfg ('-':'-':"arch=" ++ arch) = cfg { architecture = parseArch arch }
    parseOption cfg _ = cfg  -- Ignore unknown
    
    parseFormat "json" = JSONFormat
    parseFormat "csv" = CSVFormat
    parseFormat _ = TextFormat
    
    parseArch "16" = X86_16
    parseArch "32" = X86_32
    parseArch "64" = X86_64
    parseArch _ = X86_64

-- | Main entry point
main :: IO ()
main = do
    args <- getArgs
    if "-h" `elem` args || "--help" `elem` args
        then putStrLn $ unlines
            [ "x86/x64 Opcode Counter"
            , "Author: Ilya Markin"
            , ""
            , "A high-performance opcode frequency analyzer written in Haskell"
            , "Demonstrates:"
            , "  - Linear sweep disassembly"
            , "  - Pattern matching with wildcards"
            , "  - Statistical analysis of binary code"
            , "  - Entropy calculation for malware detection"
            , ""
            , "For usage: opcode-counter --help"
            ]
        else do
            (path, config) <- parseArgs args
            result <- countOpcodesFromFile path config
            case result of
                Left err -> do
                    hPutStrLn stderr $ "Error: " ++ err
                    exitFailure
                Right analysis -> do
                    case outputFormat config of
                        TextFormat -> putStrLn $ formatText analysis
                        JSONFormat -> B.putStr $ formatJSON analysis
                        CSVFormat -> putStr $ formatCSV analysis
                    
                    when (verbose config) $
                        putStrLn $ "\n[*] Analysis complete"
