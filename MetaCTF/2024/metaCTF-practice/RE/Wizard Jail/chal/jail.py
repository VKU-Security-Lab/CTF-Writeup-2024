from types import CodeType

def magic_wand(spell):
    spell = "~" + spell[::-1]
    spell = spell[5:10:] + "~" + spell[:5:]
    spell += "~"
    return eval(spell + "]")

def mend(magic_wand, location, charm):
    co = magic_wand.__code__
    magic_wand.__code__ = CodeType(co.co_argcount, co.co_posonlyargcount, co.co_kwonlyargcount, co.co_nlocals, co.co_stacksize, co.co_flags, co.co_code[:location] + charm + co.co_code[location+1:], co.co_consts, co.co_names, co.co_varnames, co.co_filename, co.co_name, co.co_qualname, co.co_firstlineno, co.co_linetable, co.co_exceptiontable, co.co_freevars, co.co_cellvars)
    return magic_wand

print("Break out of the jail!")

mends_left = 5

while True:
    print("\nChoose an option:")
    print("  1) Use magic wand")
    print("  2) Mend magic wand")

    while True:
        option = input("\nEnter 1 or 2: ")
        if option in ["1", "2"]: break
        print("\nInvalid input. Try again.")

    if option == "1":
        spell = input("\nEnter your spell: ")
        try:
            result = magic_wand(spell)
            print("\nSpell worked! The ancient voices whisper back: '" + str(result) + "'")
        except Exception as e:
            print("\nOh no! The spell failed.")

    elif option == "2":
        if mends_left <= 0:
            print("\n. Unfortunately the wand can no longer be mended.")
        else:
            location = input("\nEnter the location on the wand that you'd like to mend (an integer): ")
            enchatment = input("\nEnter the enchantment that you'd like to use (an integer): ")
            try:
                magic_wand = mend(magic_wand, int(location), int(enchatment).to_bytes())
                mends_left -= 1
                print("\nThe wand has been mended!")
            except Exception as e:
                print("\nMending failed.", e)