import subprocess
from pwn import *
from pwnlib import *


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
         
  