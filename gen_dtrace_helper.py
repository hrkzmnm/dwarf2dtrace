#!/usr/bin/env python3

from typing import Optional, Dict, Set, Callable, Iterable
import re
import sys
import dataclasses

import elftools.elf.elffile
from elftools.dwarf.die import DIE

ENCODING = 'utf-8'
class ParseError(Exception):
    pass

@dataclasses.dataclass
class Node:
    tag: str
    offset: int
    name: str
    nickname: str
    type_goff: int
    is_decl: bool
    decl_file: str
    decl_line: int
    byte_size: int
    bit_size: int # bitfields
    deps: Iterable[int] # for composite types
    quantity: int # for arrays
    data_member_location: int # for members
    def src_location(self) -> str:
        return f"{self.decl_file}:{self.decl_line}"

class TypeDG:
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
        self.offset_to_node = {}

    def summarize(self, die: DIE):
        name = None
        if 'DW_AT_name' in die.attributes:
            name = die.attributes["DW_AT_name"].value.decode(ENCODING)
            if not self.is_valid_name(name):
                name = None
        nickname = name
        if nickname is None:
            keyword = self.TAGS_for_types.get(die.tag, None)
            if keyword:
                nickname = f"anon_{keyword}__GOFF0x{die.offset:x}"
        def get_type_goff(die):
            at_type = die.attributes.get('DW_AT_type', None)
            if not at_type:
                return -1
            if at_type.form == "DW_FORM_ref_addr":
                # global offset (needs relocation?)
                return at_type.value
            if at_type.form == "DW_FORM_ref_sig8":
                # 8-byte type signature
                raise ParseError("cannot handle {at_type.form} yet")
            if at_type.form in {"DW_FORM_ref_sup4", "DW_FORM_ref_sup8"}:
                # supplementary obj file?
                raise ParseError("cannot handle {at_type.form} yet")
            # for _ref[1248] or _ref_udata, CU-local offset
            return at_type.value + die.cu.cu_offset
        def get_decl_file(die):
            if not die.tag in self.TAGS_for_types:
                return "_omitted_"
            decl_file = die.attributes.get('DW_AT_decl_file', None)
            if decl_file:
                # note: no need to -1 for DWARFv5?
                fileno = decl_file.value - 1
                line_program = die.cu.dwarfinfo.line_program_for_CU(die.cu)
                return line_program['file_entry'][fileno].name.decode(ENCODING)
            else:
                return "_nowhere_"
        def get_decl_line(die):
            decl_line = die.attributes.get('DW_AT_decl_line', None)
            return decl_line.value if decl_line else -1
        def get_byte_size(die):
            byte_size = die.attributes.get('DW_AT_byte_size')
            return byte_size.value if byte_size else -1
        def get_bit_size(die):
            bit_size = die.attributes.get('DW_AT_bit_size')
            return bit_size.value if bit_size else None
        deps = None
        if die.tag in ("DW_TAG_structure_type",
                       "DW_TAG_class_type",
                       "DW_TAG_union_type"):
            deps = [child.offset for child in die.iter_children()
                    if child.tag == "DW_TAG_member"]
        elif die.tag in ("DW_TAG_subprogram",
                         "DW_TAG_subroutine_type"):
            deps = [child.offset for child in die.iter_children()
                    if child.tag == "DW_TAG_formal_parameter"]
        elif die.tag == "DW_TAG_enumeration_type":
            deps = [child.offset for child in die.iter_children()
                    if child.tag == "DW_TAG_enumerator"]
        def get_quantity(die):
            if die.tag == "DW_TAG_array_type":
                for child in die.iter_children():
                    if child.tag != "DW_TAG_subrange_type":
                        continue
                    if not "DW_AT_count" in child.attributes:
                        continue
                    return child.attributes['DW_AT_count'].value
            if die.tag == "DW_TAG_enumerator":
                ctval = die.attributes["DW_AT_const_value"]
                if ctval:
                    return ctval.value
            return None
        data_member_location = None
        if die.tag == "DW_TAG_member":
            if "DW_AT_data_member_location" in die.attributes:
                data_member_location = die.attributes["DW_AT_data_member_location"].value
            elif  "DW_AT_bit_offset" in die.attributes:
                data_member_location = die.attributes["DW_AT_bit_offset"].value
        return Node(
            tag = sys.intern(die.tag),
            offset = die.offset,
            name = name,
            nickname = nickname,
            type_goff = get_type_goff(die),
            is_decl = ("DW_AT_declaration" in die.attributes),
            decl_file = sys.intern(get_decl_file(die)),
            decl_line = get_decl_line(die),
            byte_size = get_byte_size(die),
            bit_size = get_bit_size(die),
            deps = deps,
            quantity = get_quantity(die),
            data_member_location = data_member_location,
        )
    def parse_cu(self, CU: elftools.dwarf.compileunit.CompileUnit):
        from elftools.dwarf import constants
        top = CU.get_top_DIE()
        if not top.attributes['DW_AT_language'].value in {
                constants.DW_LANG_C,
                constants.DW_LANG_C89,
                constants.DW_LANG_C99,
                constants.DW_LANG_C11 if 'DW_LANG_C11' in dir(constants) else 0x1d,
                # constants.DW_LANG_C_plus_plus,
                # constants.DW_LANG_C_plus_plus_03,
                # constants.DW_LANG_C_plus_plus_11,
                # constants.DW_LANG_C_plus_plus_14,
        }:
            return
        if self.VERBOSE > 0:
            print(f"\n/** CU 0x{CU.cu_offset:x} '{top.get_full_path()}' **/")
        def register_die(die: DIE):
            try:
                node = self.summarize(die)
            except ParseError as e:
                print(f"/* ignored {die.tag} at {die.offset}: {str(e)} */")
                return
            self.offset_to_node[die.offset] = node
            symolname = None
            if not (die.tag in self.TAGS_for_types):
                return
            if "DW_AT_declaration" in die.attributes:
                return
            symolname = node.name
            if symolname is None:
                return
            try:
                known = self.symbols[symolname]
            except KeyError as e: 
                self.symbols[symolname] = node
                if self.VERBOSE > 0:
                    print(f"/* got {symolname}"
                          f" GOFF=0x{die.offset:x}"
                          f" at {node.src_location()} */")
            else:
                if self.VERBOSE > 0:
                    print(f"/* duplicated {symolname}"
                          f" GOFF=0x{die.offset:x} at {node.src_location()},"
                          f" which is known as"
                          f" GOFF=0x{known.offset:x} at {known.src_location()} */")

        def walk(die, depth: int = 0):
            register_die(die)
            for child in die.iter_children():
                walk(child, depth+1)
        walk(top)

    def type_of(self, node :Node) -> Optional[Node]:
        value = node.type_goff
        if value == -1:
            return None
        try:
            return self.offset_to_node[value]
        except KeyError as e:
            raise ParseError(f"no DIE at offset=0x{value:x}") from e

    def explain(self,
                checker: Callable[[Node], bool] = None):
        shown = {}
        for name, node in self.symbols.items():
            if not checker(node):
                continue
            try:
                self.track(node, shown, 0)
            except ParseError as e:
                print(f"/* skipped {node.tag} '{name}'"
                      f" at {node.src_location()}: {str(e)} */")

    def gen_decl(self, node: Optional[Node], name: str = None) -> str:
        if node is None:
            if name is None:
                return "void"
            return "void " + name
        
        if node.tag == "DW_TAG_base_type":
            if name:
                return (node.name + " " + name)
            return (node.name)

        if node.tag == "DW_TAG_pointer_type":
            return (self.gen_decl(self.type_of(node),
                                  "*" + (name if name else "")))

        if node.tag == "DW_TAG_reference_type":
            return (self.gen_decl(self.type_of(node),
                                  "/*<&>*/" +(name if name else "")))

        if node.tag == "DW_TAG_rvalue_reference_type":
            return (self.gen_decl(self.type_of(node),
                                  "/*<&&>*/" +(name if name else "")))

        if node.tag == "DW_TAG_subroutine_type":
            fparams = []
            for child_goff in node.deps:
                child = self.offset_to_node[child_goff]
                fparams.append(self.gen_decl(self.type_of(child)))
            if not fparams:
                fparams = [self.gen_decl(None)] # (void)
            return (self.gen_decl(self.type_of(node))
                    + " (" + name + ")(" + (", ".join(fparams)) + ")")

        if node.tag == "DW_TAG_array_type":
            count = "[]"
            if not node.quantity is None:
                count = f"[{node.quantity}]"
            return (self.gen_decl(self.type_of(node))
                    + " " + name + count)

        if self.TAGS_for_qualifiers.get(node.tag, None):
            if node.tag == "DW_TAG_restrict_type":
                prefix = ""
            else:
                prefix = self.TAGS_for_qualifiers[node.tag] + " "
            return (prefix
                    + self.gen_decl(self.type_of(node), name))

        if self.TAGS_for_types.get(node.tag, None):
            keyword = self.TAGS_for_types.get(node.tag, None)
            if keyword is None:
                raise ParseError("no keyword is known for " + node.tag)
            if keyword == "typedef":
                prefix = ""
            else:
                prefix = keyword + " "
            if name:
                postfix = " " + name
            else:
                postfix = ""
            return (prefix + node.nickname + postfix)

        raise ParseError("cannot generate decl. for " + node.tag)

    def track(self, node: Optional[Node],
              shown: Dict[str, str],
              depth: int,
              maybe_incomplete: bool = False):
        if node is None:
            return
        depth = depth + 1

        if node.tag == "DW_TAG_base_type":
            return

        if node.tag == "DW_TAG_pointer_type":
            try:
                self.track(self.type_of(node), shown, depth, True)
            except ParseError as e:
                raise ParseError("pointer -> " + str(e)) from e
            return

        if node.tag in ("DW_TAG_subprogram",
                        "DW_TAG_subroutine_type"):
            self.track(self.type_of(node), shown, depth)
            for child_goff in node.deps:
                child = self.offset_to_node[child_goff]
                if child.tag != "DW_TAG_formal_parameter":
                    continue
                try:
                    self.track(self.type_of(child), shown, depth)
                except ParseError as e:
                    raise ParseError("formal-parameter -> " + str(e)) from e
            return

        if node.tag == "DW_TAG_array_type":
            elemtype = self.type_of(node)
            self.track(elemtype, shown, depth)
            return

        if node.tag == "DW_TAG_reference_type":
            dep = self.type_of(node)
            try:
                self.track(dep, shown, depth)
            except:
                raise ParseError("reference -> " + str(e)) from e
            return

        if node.tag == "DW_TAG_rvalue_reference_type":
            dep = self.type_of(node)
            try:
                self.track(dep, shown, depth)
            except:
                raise ParseError("rvalue -> " + str(e)) from e
            return

        if node.tag in self.TAGS_for_qualifiers:
            try:
                self.track(self.type_of(node), shown, depth)
            except ParseError as e:
                raise ParseError("qual -> " + str(e)) from e
            return

        # tags below may trigger 'redefinition'
        if node.nickname in shown:
            is_known = shown[node.nickname]
            if is_known == "defined":
                return
            if is_known == "declared" and maybe_incomplete:
                return

        if node.tag == "DW_TAG_typedef":
            dep = self.type_of(node)
            try:
                self.track(dep, shown, depth)
            except ParseError as e:
                raise ParseError("typedef -> " + str(e)) from e
            print(f"\n/* @ {node.src_location()}, define '{node.nickname}' */")
            print(f"typedef {self.gen_decl(dep, node.nickname)};")
            shown[node.nickname] = "defined"
            return

        if node.tag in ("DW_TAG_structure_type",
                        "DW_TAG_class_type",
                        "DW_TAG_union_type"):
            if maybe_incomplete or node.is_decl:
                cur = shown.get(node.nickname, None)
                if cur is None:
                    print(self.gen_decl(node) + ";")
                    shown[node.nickname] = "declared"
                return
            shown[node.nickname] = "defined" # pretend to know itself
            members = []
            for child_goff in node.deps:
                child = self.offset_to_node[child_goff]
                mtype = self.type_of(child)
                if mtype is None:
                    raise ParseError(f"failed to get {mname}'s type")
                mloc = child.data_member_location
                if mloc is None:
                    raise ParseError(f"failed to get {mname}'s doff")                    
                mname = child.name
                if not mname:
                    mname = f"unnamed{len(members)}__goff_0x{mloc:x}"
                try:
                    self.track(mtype, shown, depth)
                except ParseError as e:
                    raise ParseError(f"failed to track a member"
                                     f" {mtype.tag} '{mname}' " + str(e))
                if not child.bit_size is None:
                    mname += f":{child.bit_size}"
                members.append(f"\t{self.gen_decl(mtype, mname)};"
                               f"\t/* +0x{mloc:x} */");
            print(f"\n/* @ {node.src_location()} */")
            print(self.gen_decl(node)+ " {"
                  f"/* size=0x{node.byte_size:x} */")
            if members:
                for line in members:
                    print(line)
            elif node.byte_size > 0:
                print(f"\tchar dummy[0x{node.byte_size:x}];")
            print("};")
            return

        if node.tag == "DW_TAG_enumeration_type":
            if node.nickname in shown:
                return
            shown[node.nickname] = "defined"
            members = []
            for child_goff in node.deps:
                child = self.offset_to_node[child_goff]
                cname = child.name
                if cname in shown:
                    cname = f"{cname}__GOFF0x{node.offset:x}"
                shown[cname] = "defined"
                members.append(f"\t{cname} = {child.quantity}")
            print(self.gen_decl(node) + " {")
            print(",\n".join(members))
            print("};")
            return

        else:
            raise ParseError("incompatible tag: " + node.tag)


if __name__ == '__main__':
    # sys.setrecursionlimit(100)
    path = sys.argv[1]
    with open(path, 'rb') as f:
        efile = elftools.elf.elffile.ELFFile(f)
        dwinfo = efile.get_dwarf_info(relocate_dwarf_sections=False)
        dg = TypeDG()
        for CU in dwinfo.iter_CUs():
            dg.parse_cu(CU)
        def everything(node: Node):
            return True
        dg.explain(everything)
