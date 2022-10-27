import json
import os
from .mib import on_mib
from .tc import MIB_TEXTUAL_CONVENTIONS

MIB_INDEX = {}
MIB_JSON_FOLDER = 'mibs/parsed/'


def read_mib(mibname):
    with open(os.path.join(MIB_JSON_FOLDER, mibname + '.json')) as f:
        mib = json.load(f)

    for imibname, _ in mib['IMPORTS']:
        if imibname not in MIB_INDEX:
            read_mib(imibname)

    # custom TEXTUAL CONVENTIONS
    lk_definitions = MIB_TEXTUAL_CONVENTIONS.get(mibname, {})
    # print(mibname, lk_definitions)
    on_mib(MIB_INDEX, mibname, mib, lk_definitions)


# RFC1213-MIB is obsoleted by SNMPv2-SMI
# loaded definitions are updated by on_mib, therefore it is important
# to first load old MIBS
read_mib('RFC1213-MIB')

for fn in os.listdir(MIB_JSON_FOLDER):
    if fn[:-5] not in MIB_INDEX:
        read_mib(fn[:-5])
