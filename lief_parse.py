import os
import hashlib
import lief
import pandas as pd
from sklearn.preprocessing import OneHotEncoder, StandardScaler, MinMaxScaler, OrdinalEncoder
from sklearn.feature_extraction.text import CountVectorizer

import json

def save_dict_to_json(data, filename, indent=3):
  """
  Saves a Python dictionary to a JSON file with indentation.

  Args:
    data: The Python dictionary to be saved.
    filename: The name of the JSON file to be created.
    indent: The number of spaces to use for indentation (default: 4).
  """
  with open(filename, 'w') as f:
    json.dump(data, f, indent=indent)

def parse_elf(file_path, json_file):
    try:
        binary = lief.parse(file_path)
    except lief.bad_file:
        print(f"Error parsing file: {file_path}")
    
    features = {
        'header': {},
        'imports': {},
        'exports': {},
    }

    try:
        features['header']['file_type'] = binary.header.file_type.name
        features['header']['machine_type'] = binary.header.machine_type.name
        features['header']['object_file_version'] = binary.header.object_file_version.value
        features['header']['processor_flag'] = binary.header.processor_flag

        features['header']['entrypoint'] = binary.entrypoint
        features['header']['header_size'] = binary.header.header_size
        features['header']['numberof_sections'] = binary.header.numberof_sections
        features['header']['numberof_segments'] = binary.header.numberof_segments

        features['header']['program_header_offset'] = binary.header.program_header_offset
        features['header']['program_header_size'] = binary.header.program_header_size
        features['header']['section_header_offset'] = binary.header.section_header_offset
        features['header']['section_header_size'] = binary.header.section_header_size
        features['header']['section_name_table_idx'] = binary.header.section_name_table_idx

        features['header']['imagebase'] = binary.imagebase
        features['header']['eof_offset'] = binary.eof_offset
        features['overlay'] = len(binary.overlay)

        # Architecture-specific flags (example: ARM)
        if hasattr(binary.header, 'arm_flags'):
            features['header']['arm_flags_list'] = binary.header.arm_flags

        # Add similar checks for other architectures (e.g., Hexagon, MIPS, PPC64)
        if hasattr(binary.header, 'hexagon_flags'):
            features['header']['hexagon_flags_list'] = binary.header.hexagon_flags
        if hasattr(binary.header, 'mips_flags'):
            features['header']['mips_flags_list'] = binary.header.mips_flags
        if hasattr(binary.header, 'ppc64_flags'):
            features['header']['ppc64_flags_list'] = binary.header.ppc64_flags


        features['imports']['imported_functions'] = [function.name for function in binary.imported_functions]
        features['imports']['libraries'] = [library for library in binary.libraries]
        features['exports']['exported_functions'] = [function.name for function in binary.exported_functions]

        features['strings'] = binary.strings        

        # Identity fields
        features['identity'] = binary.header.identity
        features['identity_abi_version'] = binary.header.identity_abi_version
        features['identity_class'] = binary.header.identity_class.name
        features['identity_os_abi'] = binary.header.identity_os_abi.name
        features['identity_version'] = binary.header.identity_version.value
    
    except Exception as e:
        print(f"Error parsing file: {file_path} ", e)

    save_dict_to_json(features, json_file)

file_path = 'C:\Lab\ELF\wildfire-test-elf-file'
json_file = 'C:\Lab\ELF\wildfire-test-elf-file.json'
parse_elf(file_path, json_file)


from capstone import *

def disassemble_elf(file_path):
    """
    Disassembles an ELF file using Capstone and extracts features.

    Args:
        file_path (str): Path to the ELF file.

    Returns:
        list: A list of dictionaries, where each dictionary represents a disassembled instruction 
              and its features.
    """

    try:
        binary = lief.parse(file_path)
    except lief.bad_file as e:
        print(f"Error parsing ELF file: {e}")
        return []

    # Get the code section
    code_section = binary.get_section(".text")
    if code_section is None:
        print("Error: Could not find code section.")
        return []

    # Initialize Capstone disassembler WITH DETAIL ENABLED
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True  # Enable detail mode

    instructions = []
    for i in md.disasm(bytes(code_section.content), code_section.virtual_address):
        instruction = {
            'address': i.address,
            'mnemonic': i.mnemonic,
            'op_str': i.op_str,
            # Add more features here as needed
            'size': i.size,
            'bytes': i.bytes,
            # Example: Extract register operands
            'operands': [operand.type for operand in i.operands]
        }
        instructions.append(instruction)

    return instructions


disasm = disassemble_elf(file_path)
disasm
