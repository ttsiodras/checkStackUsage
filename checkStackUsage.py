#!/usr/bin/env python3
"""
Utility to detect recursive calls and calculate total stack usage per function
(via following the call graph).

Published under the GPL, (C) 2011 Thanassis Tsiodras
Suggestions/comments: ttsiodras@gmail.com

Updated to use GCC-based .su files (-fstack-usage) in 2021.
"""

import os
import re
import sys
import operator

from typing import Dict, Set, Optional, List, Tuple

FunctionName = str
FunctionNameToInt = Dict[FunctionName, int]

# For each function, what is the set of functions it calls?
CallGraph = Dict[FunctionName, Optional[Set[FunctionName]]]

# .su files data
Filename = str
SuData = Dict[FunctionName, List[Tuple[Filename, int]]]


# findStackUsage will return a tuple:
# - The total stack size used
# - A list of pairs, of the functions/stacksizes, adding up to the final use.
UsageResult = Tuple[int, List[Tuple[FunctionName, int]]]


class Matcher:
    """regexp helper"""
    def __init__(self, pattern, flags=0):
        self._pattern = re.compile(pattern, flags)
        self._hit = None

    def match(self, line):
        self._hit = re.match(self._pattern, line)
        return self._hit

    def search(self, line):
        self._hit = re.search(self._pattern, line)
        return self._hit

    def group(self, idx):
        return self._hit.group(idx)


def lookupStackSizeOfFunction(
        fn: FunctionName,
        fns: List[Tuple[FunctionName, int]],
        suData: SuData,
        stackUsagePerFunction: FunctionNameToInt) -> int:
    """
    What do you do when you have moronic C code like this?

    ===
    a.c
    ===
    static int func() { ...}
    void foo() { func(); }

    ===
    b.c
    ===
    static int func() { ...}
    void bar() { func(); }

    You have a problem. There is only one entry in stackUsagePerFunction,
    since we assign as we scan the su files - but you basically want to
    use the right value, based on filescope (due to the static).
    In effect, the .su files need to be read *prioritizing local calls*
    when computing stack usage.

    So what we do is this: we have suData - a dictionary that stores
    per each function name, WHERE we found it (at which .su filename)
    and what size it had there. We scan that from the beginning of our fns
    list all the way to the end - storing the *last active suFilename*.

    And we then look up the stack use of our function prioritizing that
    suFilename.
    """
    if not fns or fn not in suData:
        return stackUsagePerFunction[fn]

    suFilename = None
    for elem in fns:
        functionName = elem[0]
        if functionName not in suData:
            continue
        suList = suData[functionName]
        if len(suList) != 1:
            continue
        suFilename = suList[0][0]

    if not suFilename:
        return stackUsagePerFunction[fn]

    # SuData = Dict[FunctionName, List[Tuple[Filename, int]]]
    for elem in suData[fn]:
        if elem[0] != suFilename:
            continue
        return elem[1]

    return stackUsagePerFunction[fn]


def findStackUsage(
        fn: FunctionName,
        fns: List[Tuple[FunctionName, int]],
        suData: SuData,
        stackUsagePerFunction: FunctionNameToInt,
        callGraph: CallGraph) -> UsageResult:
    """
    Calculate the total stack usage of the input function,
    taking into account who it calls.
    """
    # Sadly, we can't apply memoization anymore. A function
    # can appear in two .su files - we'd store and reuse
    # the same value for both places (which is wrong).
    #
    # #  pylint: disable=W0102
    # if fn in cache:  # memoization
    #     return cache[fn]

    if fn in [x[0] for x in fns]:
        # So, what to do with recursive functions?
        # We just reached this point with fns looking like this:
        #   [a, b, c, d, a]
        # A "baseline" answer is better than no answer;
        # so we let the parent series of calls accumulate to
        #    as + bs + cs + ds
        # ...ie. the stack sizes of all others.
        # We therefore return 0 for this "last step"
        # and stop the recursion here.
        totalStackUsage = sum(x[1] for x in fns)
        return (totalStackUsage, fns[:])

    if fn not in stackUsagePerFunction:
        totalStackUsage = sum(x[1] for x in fns)
        return (totalStackUsage, fns[:])  # Unknown function, what else to do?

    thisFunctionStackSize = lookupStackSizeOfFunction(
        fn, fns, suData, stackUsagePerFunction)
    calledFunctions = callGraph.get(fn, set())

    # If we call noone else, stack usage is just our own stack usage
    if fn not in callGraph or not calledFunctions:
        totalStackUsage = sum(x[1] for x in fns) + thisFunctionStackSize
        res = (totalStackUsage, fns + [(fn, thisFunctionStackSize)])
        return res

    # Otherwise, we check the stack usage for each function we call
    totalStackUsage = 0
    maxStackPath = []
    for x in calledFunctions:
        total, path = findStackUsage(
            x,
            fns + [(fn, thisFunctionStackSize)],
            suData,
            stackUsagePerFunction,
            callGraph)
        if total > totalStackUsage:
            totalStackUsage = total
            maxStackPath = path

    # ...and add the maximum in the list to our own stack usage:
    res = (totalStackUsage, maxStackPath[:])
    return res


def ParseCmdLineArgs() -> Tuple[str, str, Matcher, Matcher, Matcher]:
    try:
        idx = sys.argv.index("-cross")
    except ValueError:
        idx = -1
    if idx != -1:
        cross_prefix = sys.argv[idx + 1]
        objdump = cross_prefix + 'objdump'
        nm = cross_prefix + 'nm'
        functionNamePattern = Matcher(r'^(\S+) <([a-zA-Z0-9\._]+?)>:')
        callPattern = Matcher(r'^.*call\s+\S+\s+<([a-zA-Z0-9\._]+)>')
        stackUsagePattern = Matcher(
            r'^.*save.*%sp, (-[0-9]{1,}), %sp')
    else:
        binarySignature = os.popen(f"file \"{sys.argv[-2]}\"").readlines()[0]

        x86 = Matcher(r'ELF 32-bit LSB.*80.86')
        x64 = Matcher(r'ELF 64-bit LSB.*x86-64')
        leon = Matcher(r'ELF 32-bit MSB.*SPARC')
        arm = Matcher(r'ELF 32-bit LSB.*ARM')

        if x86.search(binarySignature):
            objdump = 'objdump'
            nm = 'nm'
            functionNamePattern = Matcher(r'^(\S+) <([a-zA-Z0-9_]+?)>:')
            callPattern = Matcher(r'^.*call\s+\S+\s+<([a-zA-Z0-9_]+)>')
            stackUsagePattern = Matcher(r'^.*[add|sub]\s+\$(0x\S+),%esp')
        elif x64.search(binarySignature):
            objdump = 'objdump'
            nm = 'nm'
            functionNamePattern = Matcher(r'^(\S+) <([a-zA-Z0-9_]+?)>:')
            callPattern = Matcher(r'^.*callq?\s+\S+\s+<([a-zA-Z0-9_]+)>')
            stackUsagePattern = Matcher(r'^.*[add|sub]\s+\$(0x\S+),%rsp')
        elif leon.search(binarySignature):
            objdump = 'sparc-rtems5-objdump'
            nm = 'sparc-rtems5-nm'
            functionNamePattern = Matcher(r'^(\S+) <([a-zA-Z0-9_]+?)>:')
            callPattern = Matcher(r'^.*call\s+\S+\s+<([a-zA-Z0-9_]+)>')
            stackUsagePattern = Matcher(
                r'^.*save.*%sp, (-([0-9]{2}|[3-9])[0-9]{2}), %sp')
        elif arm.search(binarySignature):
            objdump = 'arm-eabi-objdump'
            nm = 'arm-eabi-nm'
            functionNamePattern = Matcher(r'^(\S+) <([a-zA-Z0-9_]+?)>:')
            callPattern = Matcher(r'^.*bl\s+\S+\s+<([a-zA-Z0-9_]+)>')
            stackUsagePattern = Matcher(
                r'^.*sub.*sp, (#[0-9][0-9]*)')
        else:
            print("Unknown signature:", binarySignature, "please use -cross")
            sys.exit(1)
    return objdump, nm, functionNamePattern, callPattern, stackUsagePattern


def GetSizeOfSymbols(nm: str, elf_binary: str) -> Tuple[
        FunctionNameToInt, FunctionNameToInt]:
    # Store .text symbol offsets and sizes (use nm)
    offsetOfSymbol = {}  # type: FunctionNameToInt
    for line in os.popen(
            nm + " \"" + elf_binary + "\" | grep ' [Tt] '").readlines():
        offsetData, unused, symbolData = line.split()
        offsetOfSymbol[symbolData] = int(offsetData, 16)
    sizeOfSymbol = {}
    lastOffset = 0
    lastSymbol = ""
    sortedSymbols = sorted(
        offsetOfSymbol.items(), key=operator.itemgetter(1))
    for symbolStr, offsetInt in sortedSymbols:
        if lastSymbol != "":
            sizeOfSymbol[lastSymbol] = offsetInt - lastOffset
        lastSymbol = symbolStr
        lastOffset = offsetInt
    sizeOfSymbol[lastSymbol] = 2**31  # allow last .text symbol to roam free
    return sizeOfSymbol, offsetOfSymbol


def GetCallGraph(
        objdump: str,
        offsetOfSymbol: FunctionNameToInt, sizeOfSymbol: FunctionNameToInt,
        functionNamePattern: Matcher, stackUsagePattern: Matcher,
        callPattern: Matcher) -> Tuple[CallGraph, FunctionNameToInt]:

    # Parse disassembly to create callgraph (use objdump -d)
    functionName = ""
    stackUsagePerFunction = {}  # type: FunctionNameToInt
    callGraph = {}              # type: CallGraph
    insideFunctionBody = False

    offsetPattern = Matcher(r'^([0-9A-Za-z]+):')
    for line in os.popen(objdump + " -d \"" + sys.argv[-2] + "\"").readlines():
        # Have we matched a function name yet?
        if functionName != "":
            # Yes, update "insideFunctionBody" boolean by checking
            # the current offset against the length of this symbol,
            # stored in sizeOfSymbol[functionName]
            offset = offsetPattern.match(line)
            if offset:
                offset = int(offset.group(1), 16)
                if functionName in offsetOfSymbol:
                    startOffset = offsetOfSymbol[functionName]
                    insideFunctionBody = \
                        insideFunctionBody and \
                        (offset - startOffset) < sizeOfSymbol[functionName]

        # Check to see if we see a new function:
        # 08048be8 <_functionName>:
        fn = functionNamePattern.match(line)
        if fn:
            offset = int(fn.group(1), 16)
            functionName = fn.group(2)
            callGraph.setdefault(functionName, set())
            # make sure this is the function we found with nm
            # UPDATE: no, can't do - if a symbol is of local file scope
            # (i.e. if it was declared with 'static')
            # then it may appear in multiple offsets!...
            #
            # if functionName in offsetOfSymbol:
            #     if offsetOfSymbol[functionName] != offset:
            #         print "Weird,", functionName, \
            #             "is not at offset reported by", nm
            #         print hex(offsetOfSymbol[functionName]), hex(offset)
            insideFunctionBody = True
            foundFirstCall = False
            stackUsagePerFunction[functionName] = 0

        # If we're inside a function body
        # (i.e. offset is not out of symbol size range)
        if insideFunctionBody:
            # Check to see if we have a call
            #  8048c0a:       e8 a1 03 00 00       call   8048fb0 <frame_dummy>
            call = callPattern.match(line)
            if functionName != "" and call:
                foundFirstCall = True
                calledFunction = call.group(1)
                calledFunctions = callGraph[functionName]
                if calledFunctions is not None:
                    calledFunctions.add(calledFunction)

            # Check to see if we have a stack reduction opcode
            #  8048bec:       83 ec 04                sub    $0x46,%esp
            if functionName != "" and not foundFirstCall:
                stackMatch = stackUsagePattern.match(line)
                if stackMatch:
                    value = stackMatch.group(1)
                    if value.startswith("0x"):
                        # sub    $0x46,%esp
                        value = int(stackMatch.group(1), 16)
                        if value > 2147483647:
                            # unfortunately, GCC may also write:
                            # add    $0xFFFFFF86,%esp
                            value = 4294967296 - value
                    elif value.startswith("#"):
                        # sub sp, sp, #1024
                        value = int(value[1:])
                    else:
                        # save  %sp, -104, %sp
                        value = -int(value)
                    assert(
                        stackUsagePerFunction[functionName] is not None)
                    stackUsagePerFunction[functionName] += value

    # for fn,v in stackUsagePerFunction.items():
    #    print fn,v
    #    print "CALLS:", callGraph[fn]
    return callGraph, stackUsagePerFunction


def ReadSU(fullPathToSuFile: str) -> Tuple[FunctionNameToInt, SuData]:
    stackUsagePerFunction = {}  # type: FunctionNameToInt
    suData = {}                 # type: SuData
    # pylint: disable=R1732
    for line in open(fullPathToSuFile, encoding='utf-8'):
        data = line.strip().split()
        if len(data) == 3 and data[2] == 'static':
            try:
                functionName = data[0].split(':')[-1]
                functionStackUsage = int(data[1])
            except:
                continue
            stackUsagePerFunction[functionName] = functionStackUsage
            suData.setdefault(functionName, []).append(
                (fullPathToSuFile, functionStackUsage))
    return stackUsagePerFunction, suData


def GetSizesFromSUfiles(root_path) -> Tuple[FunctionNameToInt, SuData]:
    stackUsagePerFunction = {}  # type: FunctionNameToInt
    suData = {}                 # type: SuData
    for root, unused_dirs, files in os.walk(root_path):
        for f in files:
            if f.endswith('.su'):
                supf, sud = ReadSU(root + os.sep + f)
                for k, v in supf.items():
                    stackUsagePerFunction[k] = max(
                        v, stackUsagePerFunction.get(k, 0))

                # We need to augment the list of .su if there's
                # a symbol that appears in two or more .su files.
                for functionName, v in sud.items():
                    suData.setdefault(functionName, []).extend(v)
    return stackUsagePerFunction, suData


def main() -> None:
    if len(sys.argv) < 3 or not os.path.exists(sys.argv[-2]) \
            or not os.path.isdir(sys.argv[-1]):
        print(f"Usage: {sys.argv[0]} [-cross PREFIX]"
              " ELFbinary root_path_for_su_files")
        print("\nwhere the default prefix is:\n")
        print("\tarm-eabi-      for ARM binaries")
        print("\tsparc-rtems5-  for SPARC binaries")
        print("\t(no prefix)    for x86/amd64 binaries")
        print("\nNote that if you use '-cross', SPARC opcodes are assumed.\n")
        sys.exit(1)

    objdump, nm, functionNamePattern, callPattern, stackUsagePattern = \
        ParseCmdLineArgs()
    sizeOfSymbol, offsetOfSymbol = GetSizeOfSymbols(nm, sys.argv[-2])
    callGraph, stackUsagePerFunction = GetCallGraph(
        objdump,
        offsetOfSymbol, sizeOfSymbol,
        functionNamePattern, stackUsagePattern, callPattern)

    supf, suData = GetSizesFromSUfiles(sys.argv[-1])
    for k, v in supf.items():
        stackUsagePerFunction[k] = max(
            v, stackUsagePerFunction.get(k, 0))

    print("Cumulative stack usage per function:")
    # Then, navigate the graph to calculate stack needs per function
    results = []
    for fn, value in stackUsagePerFunction.items():
        if value is not None:
            results.append(
                (fn,
                 findStackUsage(
                     fn, [], suData, stackUsagePerFunction, callGraph)))
    for fn, data in sorted(results, key=lambda x: x[1][0]):
        # pylint: disable=C0209
        print(
            "%10s: %s (%s)" % (
                data[0], fn, ",".join(
                    x[0] + "(" + str(x[1]) + ")"
                    for x in data[1])))


if __name__ == "__main__":
    main()
