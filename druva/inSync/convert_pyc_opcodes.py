import marshal
from types import CodeType
from StringIO import StringIO
import sys
import dis
import re
import os
import shutil

# Author: Chris Lyne (@lynerc)
# This script will convert Python opcodes from one mapping to another
# Tested on 2.7

def read_file(filename):
	f = open(filename, "rb")
	
	bytes = ''
	while True:
		chunk = ''
		chunk = f.read()
		if chunk == '':
			break
		else:
			bytes += chunk
	
	f.close()
	return bytes

# strips off the 8 byte pyc header
# and pulls out the code object(s)
def unmarshal_pyc_code(filename):
    bytes = read_file(filename)
    obj = marshal.loads(bytes[8:])
    return obj

# flip a dictionary so the keys become values. vice versa
def flip_dict(the_dict):
    new_dict = dict()
    for k,v in the_dict.items():
        new_dict[v] = k
    return new_dict
    
# dis.dis() prints straight to stdout
# so we have to redirect stdout to capture the output
def capture_disassembly(code_obj):
    output = ''
    new_stdout = StringIO()
    orig_stdout = sys.stdout
    sys.stdout = new_stdout
    # disassemble
    dis.dis(code_obj)
    # restore stdout 
    sys.stdout = orig_stdout
    output = new_stdout.getvalue()
    new_stdout.close()
    return output
    
def recurse_convert_code_objects(code_obj_in, to_opcodes):
    new_co_code = convert_opcodes(code_obj_in, to_opcodes)
    # there are possibly nested code objected
    # let's recurse in
    new_co_consts = []
    for const in code_obj_in.co_consts:
        if type(const) == CodeType:
            new_const = recurse_convert_code_objects(const, to_opcodes)
            new_co_consts.append(new_const) # append converted
        else:
            new_co_consts.append(const) # append as-is
    
    # create a new code object
    # everything remains the same except the opcodes
    new_code_obj_out = CodeType(
        code_obj_in.co_argcount,
        code_obj_in.co_nlocals,
        code_obj_in.co_stacksize,
        code_obj_in.co_flags,
        new_co_code,   # <-- new op codes
        tuple(new_co_consts),
        code_obj_in.co_names,
        code_obj_in.co_varnames,
        code_obj_in.co_filename,
        code_obj_in.co_name,
        code_obj_in.co_firstlineno,
        code_obj_in.co_lnotab,
        code_obj_in.co_freevars,
        code_obj_in.co_cellvars
    )
    
    return new_code_obj_out
    

# return a list of instructions
# instructions are in a dictionary: key=offset, value=opname
def parse_disassembly(dis_output):
    # e.g. [(0, 'LOAD_CONST'), (3, 'PRINT_ITEM'), (4, 'PRINT_NEWLINE'), (5, 'LOAD_CONST'), (8, 'RETURN_VALUE')]
    instructions = dict()
    lines = dis_output.split('\n')
    regex = "^.*[ \t]+([0-9]+) ([A-Z][A-Z_\+0-9]+)(?:[ \t]+[0-9]+|[ ]*$)"
    for instr in lines:
        match = re.match(regex, instr)
        if match is not None:
            offset = int(match.group(1))
            opname = match.group(2)
            instructions[offset] = opname
    return instructions
    
# convert opcodes
def convert_opcodes(code_obj_in, to_opcodes):
    # disassemble
    dis_output = capture_disassembly(code_obj_in)
    
    # parse out the instruction offsets and operation names
    instructions = parse_disassembly(dis_output)
    
    code_out = ''
    # we need to build a new byte string of opcodes 
    # so 
    # loop instructions to modify
    offset = 0
    while offset < len(code_obj_in.co_code):
        # instruction e.g.: {offset, op_name}
        if offset in instructions:
            op_name = instructions[offset]      # get opname from dictionary
            new_opcode = to_opcodes[op_name]    # grab opcode using op name
            code_out += chr(new_opcode)         # convert from int to byte
        else:
            code_out += code_obj_in.co_code[offset] # otherwise, just add the byte as-is. These are likely operands
        offset += 1

    return code_out
    
def convert_pyc_file(to_opcodes, pyc_file):
    pyc_code_obj_in = unmarshal_pyc_code(pyc_file)
    
    # recursively look for code objects
    # should also rebuild code object
    code_object_out = recurse_convert_code_objects(pyc_code_obj_in, to_opcodes)

    magic = '\x03\xf3\x0d\x0a'  # 62211 version
    time = '\x00'*4
    new_pyc_out = magic + time + marshal.dumps(code_object_out)
    
    filename = os.path.basename(pyc_code_obj_in.co_filename)
    filename = filename.replace(".pyc", "_converted.pyc")

    output_filename = os.path.dirname(pyc_file) + "\\" + filename

    with open(output_filename, 'wb') as f:
        f.write(new_pyc_out)
    
    return output_filename

if __name__ == '__main__':

    # note that the Python shared library (e.g. Python27.dll) must be loaded in order to disassemble the "from" opcodes 
    # we can use these maps to convert opcodes
    # druva opcodes not used. here for reference
    druva_opcodes = {'CALL_FUNCTION': 111, 'DUP_TOP': 64, 'INPLACE_FLOOR_DIVIDE': 71, 'MAP_ADD': 161, 'BINARY_XOR': 55, 'END_FINALLY': 18, 'RETURN_VALUE': 13, 'POP_BLOCK': 17, 'SETUP_LOOP': 140, 'BUILD_SET': 94, 'POP_TOP': 61, 'EXTENDED_ARG': 159, 'SETUP_FINALLY': 142, 'INPLACE_TRUE_DIVIDE': 70, 'CALL_FUNCTION_KW': 121, 'INPLACE_AND': 2, 'SETUP_EXCEPT': 141, 'STORE_NAME': 100, 'IMPORT_NAME': 98, 'LOAD_GLOBAL': 136, 'LOAD_NAME': 91, 'FOR_ITER': 103, 'EXEC_STMT': 15, 'DELETE_NAME': 101, 'BUILD_LIST': 93, 'COMPARE_OP': 97, 'BINARY_OR': 56, 'INPLACE_MULTIPLY': 47, 'STORE_FAST': 145, 'CALL_FUNCTION_VAR': 120, 'SET_ADD': 160, 'LOAD_LOCALS': 12, 'CONTINUE_LOOP': 139, 'PRINT_EXPR': 9, 'DELETE_GLOBAL': 108, 'GET_ITER': 58, 'STOP_CODE': 60, 'UNARY_NOT': 82, 'BINARY_LSHIFT': 52, 'LOAD_CLOSURE': 115, 'IMPORT_STAR': 14, 'INPLACE_OR': 0, 'BINARY_SUBTRACT': 75, 'STORE_MAP': 44, 'INPLACE_ADD': 45, 'INPLACE_LSHIFT': 4, 'INPLACE_MODULO': 49, 'STORE_ATTR': 105, 'BUILD_MAP': 95, 'SETUP_WITH': 123, 'BINARY_DIVIDE': 78, 'INPLACE_RSHIFT': 3, 'PRINT_ITEM_TO': 6, 'UNPACK_SEQUENCE': 102, 'BINARY_MULTIPLY': 79, 'PRINT_NEWLINE_TO': 5, 'NOP': 69, 'LIST_APPEND': 104, 'INPLACE_XOR': 1, 'STORE_GLOBAL': 107, 'INPLACE_SUBTRACT': 46, 'INPLACE_POWER': 57, 'ROT_FOUR': 65, 'DELETE_SUBSCR': 51, 'BINARY_AND': 54, 'BREAK_LOOP': 10, 'MAKE_FUNCTION': 112, 'DELETE_SLICE+1': 41, 'DELETE_SLICE+0': 40, 'DUP_TOPX': 109, 'CALL_FUNCTION_VAR_KW': 122, 'LOAD_ATTR': 96, 'BINARY_TRUE_DIVIDE': 72, 'ROT_TWO': 62, 'IMPORT_FROM': 99, 'DELETE_FAST': 146, 'BINARY_ADD': 76, 'LOAD_CONST': 90, 'STORE_DEREF': 117, 'UNARY_NEGATIVE': 81, 'UNARY_POSITIVE': 80, 'STORE_SUBSCR': 50, 'BUILD_TUPLE': 92, 'BINARY_POWER': 89, 'BUILD_CLASS': 19, 'UNARY_CONVERT': 83, 'BINARY_MODULO': 77, 'DELETE_SLICE+3': 43, 'DELETE_SLICE+2': 42, 'WITH_CLEANUP': 11, 'DELETE_ATTR': 106, 'POP_JUMP_IF_TRUE': 135, 'JUMP_IF_FALSE_OR_POP': 131, 'PRINT_ITEM': 8, 'RAISE_VARARGS': 110, 'SLICE+0': 20, 'SLICE+1': 21, 'SLICE+2': 22, 'SLICE+3': 23, 'POP_JUMP_IF_FALSE': 134, 'LOAD_DEREF': 116, 'LOAD_FAST': 144, 'JUMP_IF_TRUE_OR_POP': 132, 'BINARY_FLOOR_DIVIDE': 73, 'BINARY_RSHIFT': 53, 'BINARY_SUBSCR': 74, 'YIELD_VALUE': 16, 'ROT_THREE': 63, 'STORE_SLICE+0': 30, 'STORE_SLICE+1': 31, 'STORE_SLICE+2': 32, 'STORE_SLICE+3': 33, 'UNARY_INVERT': 85, 'PRINT_NEWLINE': 7, 'INPLACE_DIVIDE': 48, 'BUILD_SLICE': 113, 'JUMP_ABSOLUTE': 133, 'MAKE_CLOSURE': 114, 'JUMP_FORWARD': 130}
    normal_opcodes = {'CALL_FUNCTION': 131, 'DUP_TOP': 4, 'INPLACE_FLOOR_DIVIDE': 28, 'MAP_ADD': 147, 'BINARY_XOR': 65, 'END_FINALLY': 88, 'RETURN_VALUE': 83, 'POP_BLOCK': 87, 'SETUP_LOOP': 120, 'BUILD_SET': 104, 'POP_TOP': 1, 'EXTENDED_ARG': 145, 'SETUP_FINALLY': 122, 'INPLACE_TRUE_DIVIDE': 29, 'CALL_FUNCTION_KW': 141, 'INPLACE_AND': 77, 'SETUP_EXCEPT': 121, 'STORE_NAME': 90, 'IMPORT_NAME': 108, 'LOAD_GLOBAL': 116, 'LOAD_NAME': 101, 'FOR_ITER': 93, 'EXEC_STMT': 85, 'DELETE_NAME': 91, 'BUILD_LIST': 103, 'COMPARE_OP': 107, 'BINARY_OR': 66, 'INPLACE_MULTIPLY': 57, 'STORE_FAST': 125, 'CALL_FUNCTION_VAR': 140, 'SET_ADD': 146, 'LOAD_LOCALS': 82, 'CONTINUE_LOOP': 119, 'PRINT_EXPR': 70, 'DELETE_GLOBAL': 98, 'GET_ITER': 68, 'STOP_CODE': 0, 'UNARY_NOT': 12, 'BINARY_LSHIFT': 62, 'LOAD_CLOSURE': 135, 'IMPORT_STAR': 84, 'INPLACE_OR': 79, 'BINARY_SUBTRACT': 24, 'STORE_MAP': 54, 'INPLACE_ADD': 55, 'INPLACE_LSHIFT': 75, 'INPLACE_MODULO': 59, 'STORE_ATTR': 95, 'BUILD_MAP': 105, 'SETUP_WITH': 143, 'BINARY_DIVIDE': 21, 'INPLACE_RSHIFT': 76, 'PRINT_ITEM_TO': 73, 'UNPACK_SEQUENCE': 92, 'BINARY_MULTIPLY': 20, 'PRINT_NEWLINE_TO': 74, 'NOP': 9, 'LIST_APPEND': 94, 'INPLACE_XOR': 78, 'STORE_GLOBAL': 97, 'INPLACE_SUBTRACT': 56, 'INPLACE_POWER': 67, 'ROT_FOUR': 5, 'DELETE_SUBSCR': 61, 'BINARY_AND': 64, 'BREAK_LOOP': 80, 'MAKE_FUNCTION': 132, 'DELETE_SLICE+1': 51, 'DELETE_SLICE+0': 50, 'DUP_TOPX': 99, 'CALL_FUNCTION_VAR_KW': 142, 'LOAD_ATTR': 106, 'BINARY_TRUE_DIVIDE': 27, 'ROT_TWO': 2, 'IMPORT_FROM': 109, 'DELETE_FAST': 126, 'BINARY_ADD': 23, 'LOAD_CONST': 100, 'STORE_DEREF': 137, 'UNARY_NEGATIVE': 11, 'UNARY_POSITIVE': 10, 'STORE_SUBSCR': 60, 'BUILD_TUPLE': 102, 'BINARY_POWER': 19, 'BUILD_CLASS': 89, 'UNARY_CONVERT': 13, 'BINARY_MODULO': 22, 'DELETE_SLICE+3': 53, 'DELETE_SLICE+2': 52, 'WITH_CLEANUP': 81, 'DELETE_ATTR': 96, 'POP_JUMP_IF_TRUE': 115, 'JUMP_IF_FALSE_OR_POP': 111, 'PRINT_ITEM': 71, 'RAISE_VARARGS': 130, 'SLICE+0': 30, 'SLICE+1': 31, 'SLICE+2': 32, 'SLICE+3': 33, 'POP_JUMP_IF_FALSE': 114, 'LOAD_DEREF': 136, 'LOAD_FAST': 124, 'JUMP_IF_TRUE_OR_POP': 112, 'BINARY_FLOOR_DIVIDE': 26, 'BINARY_RSHIFT': 63, 'BINARY_SUBSCR': 25, 'YIELD_VALUE': 86, 'ROT_THREE': 3, 'STORE_SLICE+0': 40, 'STORE_SLICE+1': 41, 'STORE_SLICE+2': 42, 'STORE_SLICE+3': 43, 'UNARY_INVERT': 15, 'PRINT_NEWLINE': 72, 'INPLACE_DIVIDE': 58, 'BUILD_SLICE': 133, 'JUMP_ABSOLUTE': 113, 'MAKE_CLOSURE': 134, 'JUMP_FORWARD': 110}
    
    # extract code object from this pyc
    if len(sys.argv) < 2:
        print "Need to specify a pyc file or dir"
        print "e.g. python convert_pyc_opcodes.py pyc_dir"
        sys.exit(0)
        
    path = sys.argv[1]
    output_path = ''
    num_converted = 0
    if os.path.isdir(path):
        output_path = "converted\\" + os.path.basename(path)
        print "Copying directory tree to " + output_path
        shutil.copytree(path, "converted\\" + os.path.basename(path))
        print "Converting pyc in dir"
        
        for root,d_names,f_names in os.walk(output_path):
            #print root, d_names, f_names
            for file in f_names:
                if "_converted.pyc" in file or ".pyc" not in file:
                    continue
                file_path = os.path.join(root, file)
                output_filename = convert_pyc_file(normal_opcodes, file_path)
                num_converted += 1
                os.remove(file_path)
                os.rename(output_filename, output_filename.replace("_converted", ""))

    elif os.path.isfile(path):
        output_path = path
        print "Is a file"
        # convert (to, file.pyc)
        output_filename = convert_pyc_file(normal_opcodes, output_path)
        print 'Wrote to ' + output_filename
        print 'Done!'
        
    print "Converted " + str(num_converted) + " files"
