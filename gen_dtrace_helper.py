#!/usr/bin/env python3

from typing import Optional, Dict, Set

import elftools.elf.elffile
from elftools.dwarf.die import DIE

ENCODING = 'utf-8'

class TypeDG:
    TAGS_for_types = (
        "DW_TAG_array_type",
        "DW_TAG_enumeration_type",
        "DW_TAG_structure_type",
        "DW_TAG_typedef",
        "DW_TAG_union_type",
        "DW_TAG_subprogram",
    )
    TAGS_for_qualifiers = (
        "DW_TAG_const_type",
        "DW_TAG_volatile_type",
        "DW_TAG_restrict_type",
    )

    def __init__(self,
                 CU: elftools.dwarf.compileunit.CompileUnit,
                 line_program: elftools.dwarf.lineprogram.LineProgram):

        # attr['DW_AT_decl_file'] -> name
        self.filedesc = dict( (le.dir_index, le.name.decode(ENCODING))
                              for le in line_program['file_entry'])
        top = CU.get_top_DIE()

        self.cu_offset = CU.cu_offset
        self.fullpath = top.get_full_path()

        named_types = {}
        def walk(die, names, depth: int = 0):
            name = self._get_attr__name(die)
            # print(depth, die.tag, name)
            if (die.tag in self.TAGS_for_types) and name:
                names.setdefault(name, set()).add(die)
            # offset -> die
            yield ((die.offset - self.cu_offset), die)
            for child in die.iter_children():
                yield from walk(child, names, depth+1)

        self.offset_to_die = dict(walk(top, named_types))
        self.named_types = named_types

        
    def _get_attr__type_die(self, die :DIE) -> Optional[DIE]:
        if 'DW_AT_type' in die.attributes:
            value = die.attributes["DW_AT_type"].value
            return self.offset_to_die.get(value, None)
        else:
            return None

    def _get_attr__srcloc(self, die :DIE) -> Optional[str]:
        loc_file = die.attributes.get('DW_AT_decl_file', None)
        loc_line = die.attributes.get('DW_AT_decl_line', None)
        return ( (self.filedesc.get((loc_file.value-1) if loc_file else None, "_nowhere_"))
                 + (":{}".format(loc_line.value if loc_line else -1)) )


    def _get_attr__name(self, die :DIE, gensym: bool = False) -> Optional[str]:
        if 'DW_AT_name' in die.attributes:
            return die.attributes["DW_AT_name"].value.decode(ENCODING)
        if gensym:
            stem = die.tag.split("_")[2]
            return ("anon_" + stem
                    + "_{:x}_{:x}".format(self.cu_offset, die.offset))
        return None


    def explain(self, filter = None):
        shown = {}
        for name, dies in self.named_types.items():
            if filter:
                dies = filter(name, dies, shown)
            for die in dies:
                self.track(die, shown, 0)

    def gen_decl(self, die: Optional[DIE], shown, name: str = None):
        if die is None:
            if name is None:
                return "void"
            return "void " + name
        
        elif die.tag == "DW_TAG_base_type":
            if name:
                return (self._get_attr__name(die) + " " + name)
            return (self._get_attr__name(die))

        elif die.tag == "DW_TAG_const_type":
            return ("const "
                    + self.gen_decl(self._get_attr__type_die(die), shown, name))

        elif die.tag == "DW_TAG_volatile_type":
            return ("volatile "
                    + self.gen_decl(self._get_attr__type_die(die), shown, name))

        elif die.tag == "DW_TAG_pointer_type":
            return (self.gen_decl(self._get_attr__type_die(die), shown,
                                  "*" + (name if name else "")))
        
        elif die.tag == "DW_TAG_typedef":
            dep = self._get_attr__type_die(die)
            if shown.get(dep, None) != "defined":
                self.track(dep, shown)
            return (self._get_attr__name(die)
                    + " " + (name if name else ""))

        elif die.tag == "DW_TAG_subroutine_type":
            rettype = self._get_attr__type_die(die)
            args = []
            for child in die.iter_children():
                if child.tag != "DW_TAG_formal_parameter":
                    continue
                args.append(self.gen_decl(self._get_attr__type_die(child), shown, None))
            if not args:
                args = [self.gen_decl(None, shown, None)]
            return (self.gen_decl(rettype, shown, None)
                    + " (" + name + ")(" + (", ".join(args)) + ")")

        elif die.tag == "DW_TAG_structure_type":
            return ("struct "
                    + self._get_attr__name(die)
                    + " " + (name if name else ""))

        elif die.tag == "DW_TAG_union_type":
            return ("union "
                    + self._get_attr__name(die, True)
                    + " " + (name if name else ""))

        elif die.tag == "DW_TAG_array_type":
            elemtype = self._get_attr__type_die(die)
            count = "[]"
            for child in die.iter_children():
                if child.tag == "DW_TAG_subrange_type":
                    if not "DW_AT_count" in child.attributes:
                        continue
                    count = "[{}]".format(child.attributes["DW_AT_count"].value)
            return (self.gen_decl(elemtype, shown, None) + " " + name + count)

        elif die.tag == "DW_TAG_enumeration_type":
            return ("enum "
                    + self._get_attr__name(die)
                    + ((" " + name) if name else ""))

        raise Exception("cannot generate decl. for ", die)
        return die.tag

    def track(self, die: Optional[DIE], shown, depth: int,
              maybe_incomplete: bool = False):
        depth = depth + 1
        if die is None:
            return

        cur = shown.get(die, None)
        if cur == "defined":
            return
        if cur == "decl_only" and maybe_incomplete:
            return
            
        decl_only = False
        if die.tag == "DW_TAG_base_type":
            pass

        elif die.tag == "DW_TAG_subroutine_type":
            self.track(self._get_attr__type_die(die), shown, depth)
            for child in die.iter_children():
                if child.tag != "DW_TAG_formal_parameter":
                    continue
                self.track(self._get_attr__type_die(child), shown, depth)
            
        elif die.tag == "DW_TAG_pointer_type":
            self.track(self._get_attr__type_die(die), shown, depth, True)

        elif die.tag in self.TAGS_for_qualifiers:
            self.track(self._get_attr__type_die(die), shown, depth)

        elif die.tag == "DW_TAG_typedef":
            dep = self._get_attr__type_die(die)
            self.track(dep, shown, depth)
            print("\n/* @", self._get_attr__srcloc(die), "*/")
            print("typedef " + self.gen_decl(dep, shown, self._get_attr__name(die)) + ";")
            
        elif die.tag == "DW_TAG_structure_type":
            name = self._get_attr__name(die);
            if maybe_incomplete:
                print("struct " + name + ";")
                decl_only = True
            else:
                members = []
                for child in die.iter_children():
                    if child.tag != "DW_TAG_member":
                        continue
                    mname = self._get_attr__name(child);
                    mtype = self._get_attr__type_die(child)
                    moff = child.attributes['DW_AT_data_member_location'].value
                    self.track(mtype, shown, depth)
                    members.append("\t" + self.gen_decl(mtype, shown, mname)
                                   + ";\t/* +0x{:x} */".format(moff));
                if members:
                    print("\n/* @", self._get_attr__srcloc(die), "*/")
                    print("struct " + name + " {")
                    for line in members:
                        print(line)
                    print("};")
                else:
                    return # empty struct?

        elif die.tag == "DW_TAG_union_type":
            name = self._get_attr__name(die, True);
            if maybe_incomplete:
                print("union " + name + ";")
                decl_only = True
            else:
                members = []
                for child in die.iter_children():
                    if child.tag != "DW_TAG_member":
                        continue
                    mname = self._get_attr__name(child);
                    mtype = self._get_attr__type_die(child)
                    moff = child.attributes['DW_AT_data_member_location'].value
                    #print(name, "has member:", child, "\n\t-> mtype:", mtype)
                    self.track(mtype, shown, depth)
                    members.append("\t" + self.gen_decl(mtype, shown, mname)
                                   + "; /* +0x{:x} */".format(moff));
                if members:
                    print("\n/* @", self._get_attr__srcloc(die), "*/")
                    print("union " + name + " {")
                    for line in members:
                        print(line)
                    print("};")
                else:
                    return # empty union?
                
        elif die.tag == "DW_TAG_array_type":
            elemtype = self._get_attr__type_die(die)
            self.track(elemtype, shown, depth)

        elif die.tag == "DW_TAG_enumeration_type":
            members = []
            for child in die.iter_children():
                if child.tag != "DW_TAG_enumerator":
                    continue
                ctval = child.attributes["DW_AT_const_value"]
                members.append( (",\t" if members else "\t")
                                + self._get_attr__name(child)
                                + (" = {}".format(ctval.value) if ctval else ""))
            print(self.gen_decl(die, shown, None) + " {")
            for line in members:
                print(line)
            print("};")

        elif die.tag == "DW_TAG_subprogram":
            pass

        else:
            raise Exception("unhandled DIE", die)
        if decl_only:
            if shown.get(die, None) != "defined":
                shown[die] = "declared"
        else:
            shown[die] = "defined"


if __name__ == '__main__':
    import sys
    sys.setrecursionlimit(100)
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        path = "./a.out"

    with open(path, 'rb') as f:
        elf = elftools.elf.elffile.ELFFile(f)
        dwarf = elf.get_dwarf_info(relocate_dwarf_sections=False)
        for CU in dwarf.iter_CUs():
            line_program = dwarf.line_program_for_CU(CU)
            dg = TypeDG(CU, line_program)
            def any(name: str, dies: Set[DIE], shown: dict):
                for die in dies:
                    yield die
            dg.explain(any)