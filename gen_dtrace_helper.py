#!/usr/bin/env python3

from typing import Optional, Dict, Set

import elftools.elf.elffile
from elftools.dwarf.die import DIE

ENCODING = 'utf-8'

class TypeDG:
    TAGS_for_types = {
        "DW_TAG_array_type": None,
        "DW_TAG_enumeration_type": "enum",
        "DW_TAG_structure_type": "struct",
        "DW_TAG_typedef": "typedef",
        "DW_TAG_union_type": "union",
        "DW_TAG_subprogram": None,
    }
    TAGS_for_qualifiers = {
        "DW_TAG_const_type": "const",
        "DW_TAG_volatile_type": "volatile",
        "DW_TAG_restrict_type": "restrict",
    }

    def __init__(self,
                 CU: elftools.dwarf.compileunit.CompileUnit,
                 line_program: elftools.dwarf.lineprogram.LineProgram):
        top = CU.get_top_DIE()

        self.cu_offset = CU.cu_offset
        self.fullpath = top.get_full_path()

        # attr['DW_AT_decl_file'] -> name
        self.filedesc = dict( (le.dir_index, le.name.decode(ENCODING))
                              for le in line_program['file_entry'])

        named_types = {}
        def walk(die, names, depth: int = 0):
            name = self._get_die_name(die)
            if (die.tag in self.TAGS_for_types) and name:
                names.setdefault(name, set()).add(die)
            yield ((die.offset - self.cu_offset), die)
            for child in die.iter_children():
                yield from walk(child, names, depth+1)

        self.offset_to_die = dict(walk(top, named_types))
        self.named_types = named_types
        
    def _get_type_die(self, die :DIE) -> Optional[DIE]:
        if 'DW_AT_type' in die.attributes:
            value = die.attributes["DW_AT_type"].value
            return self.offset_to_die.get(value, None)
        else:
            return None

    def _get_attr__srcloc(self, die :DIE) -> Optional[str]:
        loc_file = die.attributes.get('DW_AT_decl_file', None)
        if loc_file:
            dir_index = loc_file.value
            if 0 in self.filedesc:
                dir_index -= 1
            srcfile = self.filedesc.get(dir_index,
                                        "_nowhere{}_".format(dir_index))
        else:
            srcfile = "_nowhere_"
        loc_line = die.attributes.get('DW_AT_decl_line', None)
        if loc_line:
            srcline = ":{}".format(loc_line.value)
        else:
            srcline = ""
        return (srcfile + srcline)

    def _get_stem(self, die):
        stem = self.TAGS_for_types.get(die.tag, None)
        if stem is None:
            raise Exception("no stem is known for", die)
        return stem

    def _get_die_name(self, die :DIE, gensym: bool = False) -> Optional[str]:
        if 'DW_AT_name' in die.attributes:
            return die.attributes["DW_AT_name"].value.decode(ENCODING)
        if gensym:
            stem = self._get_stem(die)
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
                return (self._get_die_name(die) + " " + name)
            return (self._get_die_name(die))

        elif die.tag == "DW_TAG_pointer_type":
            return (self.gen_decl(self._get_type_die(die), shown,
                                  "*" + (name if name else "")))
        
        elif die.tag == "DW_TAG_subroutine_type":
            rettype = self._get_type_die(die)
            args = []
            for child in die.iter_children():
                if child.tag != "DW_TAG_formal_parameter":
                    continue
                args.append(self.gen_decl(self._get_type_die(child), shown, None))
            if not args:
                args = [self.gen_decl(None, shown, None)]
            return (self.gen_decl(rettype, shown, None)
                    + " (" + name + ")(" + (", ".join(args)) + ")")

        elif self.TAGS_for_qualifiers.get(die.tag, None):
            if die.tag == "DW_TAG_restrict_type":
                return (self.gen_decl(self._get_type_die(die), shown, name))
            else:
                stem = self.TAGS_for_qualifiers[die.tag]
                return (stem + " "
                        + self.gen_decl(self._get_type_die(die), shown, name))

        elif die.tag == "DW_TAG_array_type":
            elemtype = self._get_type_die(die)
            count = "[]"
            for child in die.iter_children():
                if child.tag != "DW_TAG_subrange_type":
                    continue
                if not "DW_AT_count" in child.attributes:
                    continue
                count = "[{}]".format(child.attributes["DW_AT_count"].value)
            return (self.gen_decl(elemtype, shown, None) + " " + name + count)

        elif die.tag == "DW_TAG_typedef":
            return (self._get_die_name(die)
                    + " " + (name if name else ""))

        elif self.TAGS_for_types.get(die.tag, None):
            return (self._get_stem(die) + " "
                    + self._get_die_name(die, True)
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

        elif die.tag in ("DW_TAG_subprogram",
                         "DW_TAG_subroutine_type"):
            self.track(self._get_type_die(die), shown, depth)
            for child in die.iter_children():
                if child.tag != "DW_TAG_formal_parameter":
                    continue
                self.track(self._get_type_die(child), shown, depth)
            
        elif die.tag == "DW_TAG_pointer_type":
            self.track(self._get_type_die(die), shown, depth, True)

        elif die.tag in self.TAGS_for_qualifiers:
            self.track(self._get_type_die(die), shown, depth)

        elif die.tag == "DW_TAG_typedef":
            dep = self._get_type_die(die)
            self.track(dep, shown, depth)
            print("\n/* @", self._get_attr__srcloc(die), "*/")
            print("typedef " + self.gen_decl(dep, shown, self._get_die_name(die)) + ";")
            
        elif die.tag in ("DW_TAG_structure_type",
                         "DW_TAG_union_type"):
            if maybe_incomplete:
                print(self.gen_decl(die, shown, None) + ";")
                decl_only = True
            elif "DW_AT_declaration" in die.attributes:
                return
            else:
                members = []
                for child in die.iter_children():
                    if child.tag != "DW_TAG_member":
                        continue
                    mname = self._get_die_name(child);
                    mtype = self._get_type_die(child)
                    moff = child.attributes['DW_AT_data_member_location'].value
                    self.track(mtype, shown, depth)
                    members.append("\t" + self.gen_decl(mtype, shown, mname)
                                   + ";\t/* +0x{:x} */".format(moff));
                print("\n/* @", self._get_attr__srcloc(die), "*/")
                print(self.gen_decl(die, shown, None)
                      + " {"
                      + "\t/* size=0x{:x} */".format(die.attributes["DW_AT_byte_size"].value))
                if members:
                    for line in members:
                        print(line)
                print("};")

        elif die.tag == "DW_TAG_array_type":
            elemtype = self._get_type_die(die)
            self.track(elemtype, shown, depth)

        elif die.tag == "DW_TAG_enumeration_type":
            members = []
            for child in die.iter_children():
                if child.tag != "DW_TAG_enumerator":
                    continue
                ctval = child.attributes["DW_AT_const_value"]
                members.append( (",\t" if members else "\t")
                                + self._get_die_name(child)
                                + (" = {}".format(ctval.value) if ctval else ""))
            print(self.gen_decl(die, shown, None) + " {")
            for line in members:
                print(line)
            print("};")

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
