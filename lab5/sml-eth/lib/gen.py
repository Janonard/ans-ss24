"""
 Copyright 2024 Computer Networks Group @ UPB

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 """

"""
    Utilities to generate input data
"""

import random

MAX_INT_VAL = 0xffff
MAX_FLOAT_VAL = 1

def GenMultipleOfInRange(lo=2, hi=2048, multiple=1, seed=42):
    """
    Generate a random integer in range [lo, hi] that is a multiple of 'multiple'
    If the range is not correct, it will be 'fixed' to make sure that:
        multiple <= lo <= hi
    By default the function passes `seed` to the RNG and then resets it. Which is useful
    for generating the same random number across workers etc.
    """
    if lo < multiple:
        lo = multiple
    if hi <= lo:
        hi = lo
    random.seed(seed)
    n = random.randint(lo, hi)
    random.seed(None)
    res = multiple * round(n / multiple)
    return res + multiple if res < lo or res > hi else res

def GenInts(n=1, unique=None):
    """
    Generate n random integers in range [0, MAX_INT_VAL]
    if unique is not None, all elements have the value unique
    """
    return [unique] * n if unique is not None else random.sample(range(0, MAX_INT_VAL), n)

def GenFloats(n=1, unique=None):
    """
    Generate n random floats in range [0, MAX_FLOAT_VAL]
    if unique is not None, all elements have the value unique
    """
    return [float(unique)] * n if unique is not None else [random.uniform(0, MAX_FLOAT_VAL) for i in range(n)]