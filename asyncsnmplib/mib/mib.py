class NoMibError(Exception):
    pass


class NoNameError(Exception):
    pass


def on_mib(mi, mibname, mib, lk_definitions):
    lk = {
        0: (0, ),
        1: (1, ),
        2: (2, ),
        'ccitt': (0,),
        'iso': (1,),
        'iso-ccitt': (2,),
    }

    smi_objs = {
        'TRAP-TYPE',
        'MODULE-IDENTITY',
        'OBJECT-IDENTITY',
        'OBJECT-TYPE',
        'NOTIFICATION-TYPE',
        'OBJECT-GROUP',
        'NOTIFICATION-GROUP',
        'MODULE-COMPLIANCE',
        'AGENT-CAPABILITIES',
        'TEXTUAL-CONVENTION',
        'ObjectName',
        'ObjectSyntax',
    }

    names = {}

    mib_imports = mib.pop('IMPORTS')
    for imibname, iobjs in mib_imports:
        if imibname not in mi:
            raise NoMibError('! mib not found {}'.format(imibname))

        m_lk = mi[imibname]
        for iobj in iobjs:
            if iobj in smi_objs:
                pass
            elif iobj in lk:
                pass
            elif iobj in lk_definitions:
                pass
            elif iobj in m_lk:
                lk[iobj] = m_lk[iobj]
            elif iobj in m_lk[None]:
                lk_definitions[iobj] = m_lk[None][iobj]
            else:
                raise NoNameError('! obj not imported {} {}'.format(
                    imibname, iobj))

    for name, obj in mib.items():
        if name not in lk_definitions and 'value' not in obj:
            if obj['tp'] == 'TEXTUAL-CONVENTION':
                if obj['syntax']['tp'] in mib:
                    obj['syntax'] = mib[obj['syntax']['tp']]
                if obj['syntax']['tp'] in lk_definitions:
                    obj['syntax'] = lk_definitions[obj['syntax']['tp']]

                if obj['syntax']['tp'] == 'TEXTUAL-CONVENTION':
                    obj['syntax'] = obj['syntax']['syntax']

            lk_definitions[name] = obj

    for name, obj in mib.items():
        if 'value' in obj:
            if obj['tp'] == 'OBJECT-TYPE':
                if obj['syntax']['tp'] in mib:
                    obj['syntax'] = mib[obj['syntax']['tp']]
                if obj['syntax']['tp'] in lk_definitions:
                    obj['syntax'] = lk_definitions[obj['syntax']['tp']]

                if obj['syntax']['tp'] == 'TEXTUAL-CONVENTION':
                    obj['syntax'] = obj['syntax']['syntax']
                if 'values' in obj['syntax']:
                    obj['syntax']['values'] = {
                        int(k): v for k, v in obj['syntax']['values'].items()}

                names[name] = obj
            elif obj['tp'] == 'OBJECT-IDENTITY':
                names[name] = obj
            elif obj['tp'] == 'OBJECT IDENTIFIER':
                names[name] = obj
            elif obj['tp'] == 'MODULE-IDENTITY':
                names[name] = obj
            elif obj['tp'] == 'OBJECT-GROUP':
                names[name] = obj

    for name, obj in names.items():
        other_name = name
        oid = []
        while other_name in names:
            path = names[other_name]['value']
            oid = path[1:] + oid
            other_name = path[0]

        if other_name not in lk:
            raise NoNameError('! name {} {}'.format(name, other_name))

        oid = lk[other_name] + tuple(oid)
        lk[name] = oid

        obj['mib_name'] = mibname
        obj['name'] = name
        obj['oid'] = oid
        mi[oid] = obj

    mi[mibname] = {**lk, None: lk_definitions}
