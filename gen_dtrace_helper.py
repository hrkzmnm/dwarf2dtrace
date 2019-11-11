#!/usr/bin/env python3

from typing import Optional, Dict, Set, Callable, Iterable
import re

import elftools.elf.elffile
from elftools.dwarf.die import DIE

ENCODING = 'utf-8'
class ParseError(Exception):
    pass

class TypeDG:
    TAGS_for_types = {
        "DW_TAG_array_type": None,
        "DW_TAG_enumeration_type": "enum",
        "DW_TAG_structure_type": "struct",
        "DW_TAG_class_type": "/*class*/struct", # interpret as a struct
        "DW_TAG_typedef": "typedef",
        "DW_TAG_union_type": "union",
        "DW_TAG_subprogram": None,
    }
    TAGS_for_qualifiers = {
        "DW_TAG_const_type": "const",
        "DW_TAG_volatile_type": "volatile",
        "DW_TAG_restrict_type": "restrict",
    }
    badchars = re.compile(".*[<> ,;:]")
    def is_valid_name(self, name):
        if self.badchars.match(name):
            return False
        return True

    def __init__(self,
                 CU: elftools.dwarf.compileunit.CompileUnit,
                 line_program: elftools.dwarf.lineprogram.LineProgram):
        top = CU.get_top_DIE()

        self.cu_offset = CU.cu_offset
        self.fullpath = top.get_full_path()

        # attr['DW_AT_decl_file'] -> name
        self.filedesc = dict( (li, le.name.decode(ENCODING))
                              for (li, le) in enumerate(line_program['file_entry']))
        named_types = {}
        def walk(die, names, depth: int = 0):
            if die.tag in self.TAGS_for_types:
                try:
                    given_name = self._get_die_name(die)
                except ParseError as e:
                    return
                if given_name:
                    names.setdefault(given_name, set()).add(die)
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

    def _get_attr__srcloc(self, die :DIE) -> str:
        loc_file = die.attributes.get('DW_AT_decl_file', None)
        if loc_file:
            fileno = loc_file.value - 1
            srcfile = self.filedesc.get(fileno, f"_nowhere{fileno}_")
        else:
            srcfile = "_nowhere_"
        loc_line = die.attributes.get('DW_AT_decl_line', None)
        if loc_line:
            srcline = f":{loc_line.value}"
        else:
            srcline = ""
        return (srcfile + srcline)

    def _get_stem(self, die):
        stem = self.TAGS_for_types.get(die.tag, None)
        if stem is None:
            raise ParseError("no stem is known for " + die.tag)
        return stem

    def _get_die_name(self, die :DIE, gensym: bool = False) -> Optional[str]:
        if 'DW_AT_name' in die.attributes:
            name = die.attributes["DW_AT_name"].value.decode(ENCODING)
            if self.is_valid_name(name):
                return name
            raise ParseError("non C name '{name}'")
        if gensym:
            stem = self._get_stem(die)
            return f"anon_{stem}_{self.cu_offset:x}_{die.offset:x}"
        return None


    def explain(self,
                filter: Callable[[str, Iterable[DIE], Dict[DIE, str]],
                                 Iterable[DIE]] = None,
                shown: Dict[DIE, str] = None):
        if shown is None:
            shown = {} # dedup locally
        for name, dies in self.named_types.items():
            if filter:
                dies = filter(name, dies, shown)
            for die in dies:
                try:
                    self.track(die, shown, 0)
                except ParseError as e:
                    print(f"// skipped {self.fullpath} '{name}':",
                          die.tag , str(e))

    def gen_decl(self, die: Optional[DIE], shown: Dict[DIE, str],
                 name: str = None):
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

        elif die.tag == "DW_TAG_reference_type":
            return (self.gen_decl(self._get_type_die(die), shown,
                                  "/*&*/" +(name if name else "")))

        elif die.tag == "DW_TAG_rvalue_reference_type":
            return (self.gen_decl(self._get_type_die(die), shown,
                                  "/*&&*/" +(name if name else "")))

        elif die.tag == "DW_TAG_subroutine_type":
            fparams = []
            for child in die.iter_children():
                if child.tag != "DW_TAG_formal_parameter":
                    continue
                fparams.append(self.gen_decl(self._get_type_die(child), shown))
            if not fparams:
                fparams = [self.gen_decl(None, shown)] # (void)
            return (self.gen_decl(self._get_type_die(die), shown)
                    + " (" + name + ")(" + (", ".join(fparams)) + ")")

        elif die.tag == "DW_TAG_array_type":
            count = "[]"
            for child in die.iter_children():
                if child.tag != "DW_TAG_subrange_type":
                    continue
                if not "DW_AT_count" in child.attributes:
                    continue
                count = f"[{child.attributes['DW_AT_count'].value}]"
            return (self.gen_decl(self._get_type_die(die), shown)
                    + " " + name + count)

        elif self.TAGS_for_qualifiers.get(die.tag, None):
            if die.tag == "DW_TAG_restrict_type":
                prefix = ""
            else:
                prefix = self.TAGS_for_qualifiers[die.tag] + " "
            return (prefix
                    + self.gen_decl(self._get_type_die(die), shown, name))

        elif self.TAGS_for_types.get(die.tag, None):
            if die.tag == "DW_TAG_typedef":
                prefix = ""
            else:
                prefix = self._get_stem(die) + " "
            return (prefix
                    + self._get_die_name(die, True)
                    + ((" " + name) if name else ""))

        raise ParseError("cannot generate decl. for " + die.tag)

    def track(self, die: Optional[DIE], shown, depth: int,
              maybe_incomplete: bool = False):
        depth = depth + 1
        if die is None:
            return

        is_known = shown.get(die, None)
        if is_known == "defined":
            return
        if is_known == "declared" and maybe_incomplete:
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
                try:
                    self.track(self._get_type_die(child), shown, depth)
                except ParseError as e:
                    raise ParseError("formal-parameter -> " + str(e)) from e

        elif die.tag == "DW_TAG_pointer_type":
            try:
                self.track(self._get_type_die(die), shown, depth, True)
            except ParseError as e:
                raise ParseError("pointer -> " + str(e)) from e

        elif die.tag in self.TAGS_for_qualifiers:
            self.track(self._get_type_die(die), shown, depth)

        elif die.tag == "DW_TAG_typedef":
            dep = self._get_type_die(die)
            try:
                self.track(dep, shown, depth)
            except ParseError as e:
                raise ParseError("typedef -> " + str(e)) from e
            print("\n/* @", self._get_attr__srcloc(die), "*/")
            print("typedef " + self.gen_decl(dep, shown, self._get_die_name(die)) + ";")
            
        elif die.tag in ("DW_TAG_structure_type",
                         "DW_TAG_class_type",
                         "DW_TAG_union_type"):
            if maybe_incomplete:
                print(self.gen_decl(die, shown, None) + ";")
                decl_only = True
            elif "DW_AT_declaration" in die.attributes:
                return
            else:
                shown[die] = "defined"
                members = []
                for child in die.iter_children():
                    if child.tag != "DW_TAG_member":
                        continue
                    mtype = self._get_type_die(child)
                    if not 'DW_AT_data_member_location' in child.attributes:
                        continue
                    moff = child.attributes['DW_AT_data_member_location'].value
                    try:
                        mname = self._get_die_name(child)
                        self.track(mtype, shown, depth)
                    except ParseError as e:
                        raise ParseError(f"failed to track a member {mtype.tag} {mname} " + str(e))
                    members.append(f"\t{self.gen_decl(mtype, shown, mname)};"
                                   + f"\t/* +0x{moff:x} */");
                print("\n/* @", self._get_attr__srcloc(die), "*/")
                print(self.gen_decl(die, shown) + " {\t/* "
                      + f"size=0x{die.attributes['DW_AT_byte_size'].value:x}"
                      + " */")
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
                members.append( "\t"
                                + self._get_die_name(child)
                                + (f" = {ctval.value}" if ctval else ""))
            print(self.gen_decl(die, shown, None) + " {")
            print(",\n".join(members))
            print("};")


        elif die.tag == "DW_TAG_reference_type":
            dep = self._get_type_die(die)
            try:
                self.track(dep, shown, depth)
            except:
                raise ParseError("reference -> " + str(e)) from e

        elif die.tag == "DW_TAG_rvalue_reference_type":
            dep = self._get_type_die(die)
            try:
                self.track(dep, shown, depth)
            except:
                raise ParseError("rvalue -> " + str(e)) from e

        else:
            raise ParseError("incmpatible DIE: " + die.tag)

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
        shown = {}
        for CU in dwarf.iter_CUs():
            line_program = dwarf.line_program_for_CU(CU)
            dg = TypeDG(CU, line_program)
            def any(name: str, dies: Set[DIE], shown: dict):
                for die in dies:
                    yield die
            dg.explain(any, shown)
