"""Manually reviewed, hash-bound facts for the original MC-808 x64 image.

Table lengths follow each switch's unsigned range check; compact tables derive
their target count from the maximum byte selector. Validated by control_flow.py.
"""
SHA256 = '984f00a9ffe11380e63392e7d7f6e3e5f70aa178a9764d47fc790a2170aaf084'
SWITCHES = [
    dict(jump=0x0ff3, table=0x11cc, selector=0x11ec, count=0x78),
    dict(jump=0x13be, table=0x14a8, selector=None, count=8),
    dict(jump=0x155c, table=0x18a8, selector=0x18c0, count=0xf4),
    dict(jump=0x2893, table=0x312c, selector=None, count=16),
    dict(jump=0x6ad5, table=0x6bc0, selector=None, count=21),
    dict(jump=0x6c95, table=0x6d84, selector=None, count=21),
    dict(jump=0x79c3, table=0x7bc8, selector=0x7bdc, count=0xfd),
    dict(jump=0x7a27, table=0x7cdc, selector=0x7cf4, count=0xfd),
]
# Data/padding within executable sections. Do not seed this material as code.
DATA_RANGES = [
    dict(begin=0xfe10,end=0xff80,kind='embedded_constants_and_strings'),
    dict(begin=0x13080,end=0x13088,kind='zero_prefix'),
    dict(begin=0x13102,end=0x13104,kind='int3_padding'),
    dict(begin=0x13104,end=0x137e2,kind='import_metadata'),
]
