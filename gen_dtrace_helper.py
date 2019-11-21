#!/usr/bin/env python3

from typing import Optional, Dict, Set, Callable, Iterable
import re

import elftools.elf.elffile
from elftools.dwarf.die import DIE
from elftools.dwarf import constants

ENCODING = 'utf-8'
class ParseError(Exception):
    pass

class TypeDG:
    LANGUAGES = {
        constants.DW_LANG_C,
        constants.DW_LANG_C89,
        constants.DW_LANG_C99,
        constants.DW_LANG_C11 if 'DW_LANG_C11' in dir(constants) else 0x1d,
        # constants.DW_LANG_C_plus_plus,
        # constants.DW_LANG_C_plus_plus_03,
        # constants.DW_LANG_C_plus_plus_11,
        # constants.DW_LANG_C_plus_plus_14,
    }
    TAGS_for_types = {
        "DW_TAG_array_type": None,
        "DW_TAG_enumeration_type": "enum",
        "DW_TAG_structure_type": "struct",
        "DW_TAG_class_type": "/*<class>*/struct", # interpret as a struct
        "DW_TAG_typedef": "typedef",
        "DW_TAG_union_type": "union",
        "DW_TAG_subprogram": None,
    }
    TAGS_for_qualifiers = {
        "DW_TAG_const_type": "const",
        "DW_TAG_volatile_type": "volatile",
        "DW_TAG_restrict_type": "restrict",
        "DW_TAG_atomic_type": "_Atomic", # C11
    }
    badchars = re.compile(".*[^A-Za-z0-9_ ]")
    VERBOSE = 1
    def is_valid_name(self, name: str):
        if self.badchars.match(name):
            return False
        return True

    def __init__(self):
        self.symbols = {}
        self.offset_to_die = {}

    def parse_cu(self, CU: elftools.dwarf.compileunit.CompileUnit):
        top = CU.get_top_DIE()
        if not top.attributes['DW_AT_language'].value in self.LANGUAGES:
            return
        print(f"\n/** CU 0x{CU.cu_offset:x} '{top.get_full_path()}' **/")
        def register_die(die: DIE):
            self.offset_to_die[die.offset] = die
            symolname = None
            if not (die.tag in self.TAGS_for_types):
                return
            if "DW_AT_declaration" in die.attributes:
                return
            try:
                symolname = self._get_die_name(die)
            except ParseError as e:
                print(f"/* ignored {die.tag} at {self.src_location(die)}: {str(e)} */")
            if symolname is None:
                return
            try:
                known = self.symbols[symolname]
            except KeyError as e: 
                self.symbols[symolname] = die
                if self.VERBOSE > 0:
                    print(f"/* got {symolname}"
                          f" GOFF=0x{die.offset:x}"
                          f" at {self.src_location(die)} */")
            else:
                if self.VERBOSE > 0:
                    print(f"/* duplicated {symolname}"
                          f" GOFF=0x{die.offset:x} at {self.src_location(die)},"
                          f" which is known as"
                          f" GOFF=0x{known.offset:x} at {self.src_location(known)} */")
            
        def walk(die, depth: int = 0):
            register_die(die)
            for child in die.iter_children():
                walk(child, depth+1)
        walk(top)

    def _get_type_die(self, die :DIE) -> Optional[DIE]:
        at_type = die.attributes.get('DW_AT_type', None)
        if at_type is None:
            return None
        if at_type.form == "DW_FORM_ref_addr":
            # global offset (needs relocation?)
            value = die.attributes["DW_AT_type"].value 
        elif at_type.form == "DW_FORM_ref_sig8":
            # 8-byte type signature
            raise ParseError("cannot handle {at_type.form} yet") 
        elif at_type.form in {"DW_FORM_ref_sup4", "DW_FORM_ref_sup8"}:
            # supplementary obj file
            raise ParseError("cannot handle {at_type.form} yet")
        else:
            # for _ref[1248] or _ref_udata, CU-local offset
            value = die.attributes["DW_AT_type"].value + die.cu.cu_offset
        try:
            return self.offset_to_die[value]
        except KeyError as e:
            raise ParseError(f"no DIE at offset=0x{value:x}") from e

    def src_location(self, die :DIE) -> str:
        loc_file = die.attributes.get('DW_AT_decl_file', None)
        if loc_file:
            fileno = loc_file.value - 1 # DwarfV4
            line_program = die.cu.dwarfinfo.line_program_for_CU(die.cu)
            srcfile = line_program['file_entry'][fileno].name.decode(ENCODING)
        else:
            srcfile = "_nowhere_"
        loc_line = die.attributes.get('DW_AT_decl_line', None)
        if loc_line:
            return f"{srcfile}:{loc_line.value}"
        return srcfile

    def get_keyword(self, die: DIE) -> str:
        keyword = self.TAGS_for_types.get(die.tag, None)
        if keyword is None:
            raise ParseError("no keyword is known for " + die.tag)
        return keyword

    def _get_die_name(self, die :DIE, gensym: bool = False) -> Optional[str]:
        if 'DW_AT_name' in die.attributes:
            name = die.attributes["DW_AT_name"].value.decode(ENCODING)
            if self.is_valid_name(name):
                return name
            raise ParseError(f"'{name}' may not be a valid identifier")
        if gensym:
            keyword = self.get_keyword(die)
            return f"anon_{keyword}_CU0x{die.cu.cu_offset:x}_GOFF0x{die.offset:x}"
        return None


    def explain(self,
                checker: Callable[[DIE], bool] = None):
        shown = {}
        for name, die in self.symbols.items():
            if not checker(die):
                continue
            try:
                self.track(die, shown, 0)
            except ParseError as e:
                print(f"/* skipped {die.tag} '{name}'"
                      f" at {self.src_location(die)}: {str(e)} */")

    def gen_decl(self, die: Optional[DIE], name: str = None) -> str:
        if die is None:
            if name is None:
                return "void"
            return "void " + name
        
        elif die.tag == "DW_TAG_base_type":
            if name:
                return (self._get_die_name(die) + " " + name)
            return (self._get_die_name(die))

        elif die.tag == "DW_TAG_pointer_type":
            return (self.gen_decl(self._get_type_die(die),
                                  "*" + (name if name else "")))

        elif die.tag == "DW_TAG_reference_type":
            return (self.gen_decl(self._get_type_die(die),
                                  "/*<&>*/" +(name if name else "")))

        elif die.tag == "DW_TAG_rvalue_reference_type":
            return (self.gen_decl(self._get_type_die(die),
                                  "/*<&&>*/" +(name if name else "")))

        elif die.tag == "DW_TAG_subroutine_type":
            fparams = []
            for child in die.iter_children():
                if child.tag != "DW_TAG_formal_parameter":
                    continue
                fparams.append(self.gen_decl(self._get_type_die(child)))
            if not fparams:
                fparams = [self.gen_decl(None)] # (void)
            return (self.gen_decl(self._get_type_die(die))
                    + " (" + name + ")(" + (", ".join(fparams)) + ")")

        elif die.tag == "DW_TAG_array_type":
            count = "[]"
            for child in die.iter_children():
                if child.tag != "DW_TAG_subrange_type":
                    continue
                if not "DW_AT_count" in child.attributes:
                    continue
                count = f"[{child.attributes['DW_AT_count'].value}]"
            return (self.gen_decl(self._get_type_die(die))
                    + " " + name + count)

        elif self.TAGS_for_qualifiers.get(die.tag, None):
            if die.tag == "DW_TAG_restrict_type":
                prefix = ""
            else:
                prefix = self.TAGS_for_qualifiers[die.tag] + " "
            return (prefix
                    + self.gen_decl(self._get_type_die(die), name))

        elif self.TAGS_for_types.get(die.tag, None):
            if die.tag == "DW_TAG_typedef":
                prefix = ""
            else:
                prefix = self.get_keyword(die) + " "
            return (prefix
                    + self._get_die_name(die, True)
                    + ((" " + name) if name else ""))

        raise ParseError("cannot generate decl. for " + die.tag)

    def track(self, die: Optional[DIE],
              shown: Dict[DIE, str],
              depth: int,
              maybe_incomplete: bool = False):
        if die is None:
            return
        depth = depth + 1
        is_known = shown.get(die, None)
        if is_known == "defined":
            return
        if is_known == "declared" and maybe_incomplete:
            return
            
        decl_only = False
        if die.tag == "DW_TAG_base_type":
            return

        if die.tag in ("DW_TAG_subprogram",
                         "DW_TAG_subroutine_type"):
            self.track(self._get_type_die(die), shown, depth)
            for child in die.iter_children():
                if child.tag != "DW_TAG_formal_parameter":
                    continue
                try:
                    self.track(self._get_type_die(child), shown, depth)
                except ParseError as e:
                    raise ParseError("formal-parameter -> " + str(e)) from e
            return

        if die.tag == "DW_TAG_pointer_type":
            try:
                self.track(self._get_type_die(die), shown, depth, True)
            except ParseError as e:
                raise ParseError("pointer -> " + str(e)) from e
            return

        if die.tag in self.TAGS_for_qualifiers:
            try:
                self.track(self._get_type_die(die), shown, depth)
            except ParseError as e:
                raise ParseError("qual -> " + str(e)) from e
            return

        if die.tag == "DW_TAG_typedef":
            dep = self._get_type_die(die)
            try:
                self.track(dep, shown, depth)
            except ParseError as e:
                raise ParseError("typedef -> " + str(e)) from e
            defined_name = self._get_die_name(die)
            
            print(f"\n/* @ {self.src_location(die)}, define '{defined_name}' */")
            print(f"typedef {self.gen_decl(dep, defined_name)};")
            return

        if die.tag in ("DW_TAG_structure_type",
                         "DW_TAG_class_type",
                         "DW_TAG_union_type"):
            if maybe_incomplete:
                print(self.gen_decl(die) + ";")
                decl_only = True
            elif "DW_AT_declaration" in die.attributes:
                return
            else:
                tag = self._get_die_name(die, True)
                if tag in shown:
                    return
                shown[tag] = die
                shown[die] = "defined" # pretend to know itself
                size = die.attributes['DW_AT_byte_size'].value
                members = []
                for child in die.iter_children():
                    if child.tag != "DW_TAG_member":
                        continue
                    mtype = self._get_type_die(child)
                    if mtype is None:
                        raise ParseError(f"failed to get {mname}'s type")

                    mloc = child.attributes.get('DW_AT_data_member_location', None)
                    if mloc is None:
                        continue

                    try:
                        mname = self._get_die_name(child)
                    except ParseError as e:
                        raise ParseError(f"failed to get name of a member"
                                         f" {mtype.tag} " + str(e))
                    if mname is None:
                        mname = f"unnamed{len(members)}__goff_0x{mloc.value:x}"

                    try:
                        self.track(mtype, shown, depth)
                    except ParseError as e:
                        raise ParseError(f"failed to track a member"
                                         f" {mtype.tag} '{mname}' " + str(e))
                    members.append(f"\t{self.gen_decl(mtype, mname)};"
                                   + f"\t/* +0x{mloc.value:x} */");
                print("\n/* @", self.src_location(die), "*/")
                print(self.gen_decl(die)
                      + "\t{" + f"/* size=0x{size:x} */")
                if members:
                    for line in members:
                        print(line)
                elif size > 0:
                    print(f"\tchar dummy[0x{size:x}];")
                print("};")

        elif die.tag == "DW_TAG_array_type":
            elemtype = self._get_type_die(die)
            self.track(elemtype, shown, depth)

        elif die.tag == "DW_TAG_enumeration_type":
            tag = self._get_die_name(die, True)
            if tag in shown:
                return
            shown[tag] = die
            members = []
            for child in die.iter_children():
                if child.tag != "DW_TAG_enumerator":
                    continue
                ctval = child.attributes["DW_AT_const_value"]
                if ctval:
                    members.append(f"\t{self._get_die_name(child)} = {ctval.value}")
                else:
                    members.append(f"\t{self._get_die_name(child)}")
            print(self.gen_decl(die) + " {")
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
    # sys.setrecursionlimit(100)
    path = sys.argv[1]
    with open(path, 'rb') as f:
        efile = elftools.elf.elffile.ELFFile(f)
        dwinfo = efile.get_dwarf_info(relocate_dwarf_sections=False)
        dg = TypeDG()
        for CU in dwinfo.iter_CUs():
            dg.parse_cu(CU)
        def everything(die: DIE):
            return True
        dg.explain(everything)
