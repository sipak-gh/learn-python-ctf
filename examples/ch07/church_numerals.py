#!/usr/bin/env python3
"""Lambda calculus in Python: Church numerals and booleans.

Some reversing challenges (``goated``) encode their whole check as nested
``lambda``s -- *lambda calculus*. Numbers are Church numerals: ``n`` is a
function that applies ``f`` to ``x`` exactly ``n`` times. Booleans pick one of
two arguments. Once you recognise the shapes you can decode the constants back
to integers instead of executing the obfuscation.
"""
# Church numerals: n(f)(x) = f applied n times to x.
ZERO = lambda f: lambda x: x
SUCC = lambda n: lambda f: lambda x: f(n(f)(x))


def church_to_int(n):
    return n(lambda k: k + 1)(0)


one = SUCC(ZERO)
two = SUCC(one)
three = SUCC(two)
print("church numerals:", [church_to_int(n) for n in (ZERO, one, two, three)])

# Church booleans: TRUE picks the first arg, FALSE the second.
TRUE = lambda a: lambda b: a
FALSE = lambda a: lambda b: b
print("TRUE  picks:", TRUE("yes")("no"))
print("FALSE picks:", FALSE("yes")("no"))

# Arithmetic as composition: ADD(m)(n) = m applied on top of n.
ADD = lambda m: lambda n: lambda f: lambda x: m(f)(n(f)(x))
print("1 + 2 =", church_to_int(ADD(one)(two)))
