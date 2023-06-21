import subprocess
from pwn import *
from pwnlib import *


#Check for format string
def check_for_format_string(fuzzed_program,format_parameter,fuzz_file,input_from_file,detailed_log):
    inp=""+format_parameter
    if input_from_file:
        file = open(fuzz_file, 'wb')
        attack_string=inp.encode('ascii')
        file.write(attack_string)
        file.close()
    try:
        if input_from_file:
            output = subprocess.run([fuzzed_program, fuzz_file], capture_output=True, text=True, shell=False, check=True, errors='ignore')
        else:
            output = subprocess.run([fuzzed_program, inp], capture_output=True, text=True, shell=False, errors='ignore')
        if detailed_log:
            print(f"The output for checking if there is a format string using {format_parameter}")
            print(output.stdout)
        if format_parameter in output.stdout:
            print("The program has no format string")
            return False
    except subprocess.CalledProcessError:
        return True
    return True


#How many characters could the input buffer take
def max_length_of_the_format_string(fuzzed_program,fuzz_file,input_from_file,detailed_log):
    inp="A"
    i=1
    gb=10_000_000_000
        
    while i<gb:
        inp='A'*i
        if input_from_file:
            file = open(fuzz_file, 'wb')
            attack_string=inp.encode('ascii')
            file.write(attack_string)
            file.close()
        try:
            if input_from_file:
                subprocess.run([fuzzed_program, fuzz_file], capture_output=True, text=True, shell=False, check=True, errors='ignore')
            else:
                subprocess.run([fuzzed_program, inp], capture_output=True, text=True, shell=False, errors='ignore')
        except subprocess.CalledProcessError:
            break
        except OSError:
                break
        i=i*10
    if detailed_log:
        print(f"The attack string size can be at least {int(i/10)} characters in size")
    return i


#How long can the input be only unsing format string parameters
def how_many_format_parameters(fuzzed_program,format_parameter,mutations,max_len,fuzz_file ,input_from_file, detailed_log):
    inp=format_parameter
    for i in range (1,mutations):
        if input_from_file:
            file = open(fuzz_file, 'wb')
            attack_string=inp.encode('ascii')
            file.write(attack_string)
            file.close()
            output = subprocess.run([fuzzed_program, fuzz_file], capture_output=True, text=True, shell=False, errors='ignore')
        else:
            output = subprocess.run([fuzzed_program, inp], capture_output=True, text=True, shell=False, errors='ignore')
            
        if output.returncode==-11:
            # it must be i/len(formatParameter) since "%" and "s" whould count as two different characters
            if int(i/len(format_parameter))< max_len:
                if detailed_log:
                    print("The program contains the format string vulnerabilty")
                    print(f"The program crashes with a string containing {i} \"{format_parameter}\"")
                return i
            else:
                if detailed_log:
                    print("The program crashed from diffrent reasons other than format string")
                return 0  
        inp=inp+format_parameter
    #count how many times did the '#' character appear in stdout to check if all of the format parameters were consumed by the program
    count=0
    for i in output.stdout:
        if i=='#':
            count=count+1
    if count<mutations:
        if detailed_log:
            print(f"The program crashes with a string containing {count} \"{format_parameter}\"")
        return count
    
    if detailed_log:     
        print(f"The program can support at least {mutations} characters of the type \"{format_parameter}\"")
    return mutations


#Try to map the memory using %s at different possitions on the stack for memory leaking purposes
def map_memory(fuzzed_program,format_parameter,mutations,fuzz_file,input_from_file,detailed_log,show_fails):
    inp=""
    possitions_of_valid_addresses=[]
    string_value_of_valid_address=[]
    byte_value_of_valid_address=[]
    for i in range(0,mutations):
        inp=i*format_parameter+"%s#"
        if input_from_file:
            file = open(fuzz_file, 'wb')
            attack_string=inp.encode('ascii')
            file.write(attack_string)
            file.close()
            output = subprocess.run([fuzzed_program, fuzz_file], capture_output=True, text=True, shell=False, errors='ignore')
        else:
            output = subprocess.run([fuzzed_program, inp], capture_output=True, text=True, shell=False, errors='ignore')
        if output.returncode!=-11:
            #the program did not end in a segmentation fault
            if detailed_log:
                print(f"\n**************{i}**************\n")
                print(f"The input string is: {inp}")
                print("Output using \"%s\":")
                print(output.stdout)
            possitions_of_valid_addresses.append(i)
            inp=(i+1)*format_parameter
            if input_from_file:
                file = open(fuzz_file, 'wb')
                attack_string=inp.encode('ascii')
                file.write(attack_string)
                file.close()
                outputx = subprocess.run([fuzzed_program, fuzz_file], capture_output=True, text=True, shell=False, check=True, errors='ignore')
            else:
                outputx = subprocess.run([fuzzed_program, inp], capture_output=True, text=True, shell=False, errors='ignore')
            
            if detailed_log:
                print(f"The input string is: {inp}")
                print(f"Output using only \"{format_parameter}\":")
                print(outputx.stdout)
            #extract the last byte and its value from the output
            stringV=output.stdout[(i+1)*9:]
            byteV=outputx.stdout[(i)*9:]
            string_value_of_valid_address.append(stringV)
            byte_value_of_valid_address.append(byteV)
            if detailed_log:
                print(f"string value of the last format parameter: {string_value_of_valid_address[-1]}")
                print(f"byte value of the last format parameter: {byte_value_of_valid_address[-1]}")
                print(f"\n**************{i}**************\n")
        else:
            if show_fails and detailed_log:
                print(f"\n**************{i}**************\n")
                print(f"The input string is: {inp}")
                print("Program ended with a segmentation fault")
                print(f"\n**************{i}**************\n")
    return possitions_of_valid_addresses,string_value_of_valid_address
         
  