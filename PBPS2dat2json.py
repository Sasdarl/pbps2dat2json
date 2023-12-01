import os
import sys
import struct
import argparse
import subprocess
import json
import shutil

from pathlib import Path

def ru08(buf, offset):
    return struct.unpack("<B", buf[offset:offset+1])[0]

def ru16(buf, offset):
    return struct.unpack("<H", buf[offset:offset+2])[0]

def ru32(buf, offset):
    return struct.unpack("<I", buf[offset:offset+4])[0]
    
def ruFloat(buf, offset):
    return struct.unpack("<f", buf[offset:offset+4])[0]

def wu08(value):
    return struct.pack("<B", value)
    
def wu16(value):
    return struct.pack("<H", value)

def wu32(value):
    return struct.pack("<I", value)

def wuFloat(value):
    return struct.pack("<f", value)

def xorString(str, key):
    strbytes = struct.pack("<31s",str) # The array is a string
    return bytes(a ^ key for a in strbytes) # Array of integers

def decodeRender(value): # Used for render flags
    result = []
    result.append((value & 0x02)>>1) # These are all the ones I know are used
    result.append((value & 0x04)>>2)
    result.append((value & 0x20)>>5)
    result.append((value & 0x200)>>9)
    return result # Ten-bit integer

def encodeRender(array): # Used for render flags
    result = array[0]<<1
    result += array[1]<<2
    result += array[2]<<5
    result += array[3]<<9
    return result # Array of integers, either 0 or 1

def find_DAT(buf): # Used for BTR files. It's used on regular DAT files too but immediately finds its target
    MAGIC = bytearray((int(0x21), int(0x01), int(0xF0), int(0xFF))) # We're just searching for this
    offsets = []
    
    off_start = 0x0
    off_end = len(buf)
    exit = False
    
    while off_start < off_end and exit == False:
        offset = buf.find(MAGIC, off_start, off_end)
        
        if offset == -1:
            exit = True
        else:
            return offset # Integer
    
    return -1

def DATtoJSON(buf):
    offset = 0x0C
    emptydict = {}
    dict = {}
    dict["textures"] = [] # Python's JSON module is a godsend
    dict["groups"] = []
    for i in range(ru32(buf,0x04)): # Textures
        texdict = {}
        texdict["width"] = ruFloat(buf,offset)
        texdict["height"] = ruFloat(buf,offset+4)
        dict["textures"].append(texdict)
        offset += 8
    for i in range(ru32(buf,0x08)):
        group = {}
        group["length"] = ruFloat(buf,offset)
        group["metadata"] = [0, 0, 0]
        for j in range(3):
            group["metadata"][j] = ruFloat(buf,offset+4+j*4) # I don't know what these do but there they are
        offset += 0x10
        if ru32(buf,offset) >= 1:
            offset += 0x08
            group["voiceLines"] = []
            for j in range(ru32(buf,offset-4)):
                voiceLine = {} # Legitimately no idea why these had to be XOR-encrypted
                voiceLine["voiceLength"] = ruFloat(buf,offset)
                offset += 0x04
                key = buf[offset] # The first character is the key
                voicename = xorString(buf[offset+1:offset+32],key).rstrip('\x00'.encode()) # Trim the null bytes
                voiceLine["filename"] = chr(key) + voicename.decode()
                offset += 0x20
                group["voiceLines"].append(voiceLine)
        else:
            offset += 0x04
        group["overlays"] = []
        offset += 0x04
        for j in range(ru32(buf,offset-4)):
            overlay = {}
            overlay["renderFlags"] = decodeRender(ru32(buf,offset)) # Special protocol
            overlay["textureNumber"] = ru32(buf,offset+4)
            overlay["xNumerator"] = ruFloat(buf,offset+8)
            overlay["yNumerator"] = ruFloat(buf,offset+12)
            overlay["xDenominator"] = ruFloat(buf,offset+16)
            overlay["yDenominator"] = ruFloat(buf,offset+20)
            overlay["width"] = ruFloat(buf,offset+24)
            overlay["height"] = ruFloat(buf,offset+28)
            overlay["angle"] = ruFloat(buf,offset+32)
            offset += 40

            overlay["vertexColor"] = [[],[],[],[]] # Double array, why not
            for k in range(4):
                overlay["vertexColor"][k] = [0, 0, 0, 0]
                for l in range(4):
                    overlay["vertexColor"][k][l] = ruFloat(buf,offset+l*4)
                offset += 16
            overlay["visibleTime"] = [0, 0]
            for k in range(2):
                overlay["visibleTime"][k] = ruFloat(buf,offset+k*4)
            offset += 8
            overlay["uv"] = [[],[]]
            for k in range(2):
                overlay["uv"][k] = [0, 0]
                for l in range(2):
                    overlay["uv"][k][l] = ruFloat(buf,offset+l*4)
                offset += 8
            overlay["brightnessMask"] = ru32(buf,offset)
            overlay["antiAliasing"] = ru32(buf,offset+4)
            offset += 8

            if ru32(buf,offset) >= 1: # Effects
                overlay["effects"] = []
                offset += 4
                for k in range(ru32(buf,offset-4)):
                    effect = {}
                    effect["effectType"] = ru32(buf,offset) # Mess around and learn what for
                    if ru32(buf,offset+4) >= 1:
                        effect["effectKeyframes"] = []
                        offset += 12
                        for l in range(ru32(buf,offset-4)):
                            keyframe = []
                            keyValueCount = ru32(buf,offset+4) # This is set by keyframe in the file itself (why?)
                            keyframe.append(ruFloat(buf,offset))
                            for m in range(keyValueCount):
                                keyframe.append(ruFloat(buf,offset+8+m*4))
                            offset += 8+keyValueCount*4
                            effect["effectKeyframes"].append(keyframe)
                    else:
                        offset += 8
                    overlay["effects"].append(effect) # Chain everything together
            else:
                offset += 4

            group["overlays"].append(overlay)
        dict["groups"].append(group)

    return json.dumps(dict, indent=userIndent) # And in one stroke, we have a formatted string

def JSONtoDAT(buf):
    data = json.loads(buf) # Load the dictionary
    NewDAT = []
    if "headerMagic" not in data or data["headerMagic"] != 0: # Compatibility with prerelease versions.
        NewDAT.append(wu32(0xFFF00121)) # I don't recall if any examples of magic-less DAT files actually exist
    NewDAT.append(wu32(len(data["textures"])))
    NewDAT.append(wu32(len(data["groups"])))

    for texture in data["textures"]: # Textures
        NewDAT.append(wuFloat(texture["width"]))
        NewDAT.append(wuFloat(texture["height"]))
    
    for group in data["groups"]:
        NewDAT.append(wuFloat(group["length"]))
        for m in group["metadata"]:
            NewDAT.append(wuFloat(m))

        if "voiceLines" in group:
            NewDAT.append(wu32(1))
            NewDAT.append(wu32(len(group["voiceLines"]))) # Voice lines
            for line in group["voiceLines"]:
                NewDAT.append(wuFloat(line["voiceLength"]))
                voiceline = line["filename"][1::].encode() # Make this a string so we can reuse the function
                key = ord(line["filename"][0])
                NewDAT.append(wu08(key))
                NewDAT.append(xorString(voiceline,key))
        else:
            NewDAT.append(wu32(0))

        NewDAT.append(wu32(len(group["overlays"])))
        for overlay in group["overlays"]:
            NewDAT.append(wu32(encodeRender(overlay["renderFlags"]))) # Render flags again
            NewDAT.append(wu32(overlay["textureNumber"]))
            NewDAT.append(wuFloat(overlay["xNumerator"]))
            NewDAT.append(wuFloat(overlay["yNumerator"]))
            NewDAT.append(wuFloat(overlay["xDenominator"]))
            NewDAT.append(wuFloat(overlay["yDenominator"]))
            NewDAT.append(wuFloat(overlay["width"]))
            NewDAT.append(wuFloat(overlay["height"]))
            NewDAT.append(wuFloat(overlay["angle"]))
            NewDAT.append(wu32(group["overlays"].index(overlay)+1))

            for vc in overlay["vertexColor"]:
                NewDAT.append(wuFloat(vc[0])) # This probably barely edges out a for loop
                NewDAT.append(wuFloat(vc[1]))
                NewDAT.append(wuFloat(vc[2]))
                NewDAT.append(wuFloat(vc[3]))
            for vt in overlay["visibleTime"]:
                NewDAT.append(wuFloat(vt))
            for uv in overlay["uv"]:
                NewDAT.append(wuFloat(uv[0]))
                NewDAT.append(wuFloat(uv[1]))
            NewDAT.append(wu32(overlay["brightnessMask"]))
            NewDAT.append(wu32(overlay["antiAliasing"]))

            if "effects" in overlay: # If there aren't effects, there are not effects
                NewDAT.append(wu32(len(overlay["effects"])))
                for effect in overlay["effects"]:
                    NewDAT.append(wu32(effect["effectType"]))
                    if "effectKeyframes" in effect: # If there aren't keyframes, lockpicks won't work
                        NewDAT.append(wu32(1))
                        NewDAT.append(wu32(len(effect["effectKeyframes"])))
                        for keyframe in effect["effectKeyframes"]:
                            NewDAT.append(wuFloat(keyframe[0]))
                            NewDAT.append(wu32(len(keyframe)-1))
                            for kv in keyframe[1::]:
                                NewDAT.append(wuFloat(kv))
                    else:
                        NewDAT.append(wu32(0))
            else:
                NewDAT.append(wu32(0))
    return NewDAT # This is an array of 0-256 integers
    

parser = argparse.ArgumentParser(description='Phantom Blood PS2 DAT-JSON Converter\nProgram by Hudgyn Sasdarl') # Technically they're LXE files
parser.add_argument("inpath", help="File Input (DAT/JSON)") # but QuickBMS's assumed name for them stuck
parser.add_argument("-o", "--outpath", help="Optional. The filename used for the output JSON/DAT file.")
parser.add_argument("-sf", "--sourcefile", help="Optional. The file the resulting DAT should be written into when converting JSON. No effect without the source offset.")
parser.add_argument("-so", "--sourceoffset", help="The offset in the source file the DAT should be written into when converting JSON. No effect without the source file.")
parser.add_argument("-in", "--indent", type=int, help="Determines the indentation level used for the resulting JSON file. No effect when creating DAT.")
args = parser.parse_args()

userIndent = 4
if args.indent:
    userIndent = args.indent
if not args.inpath.endswith(".json"): # DAT input is assumed
    def save_json(input_file_buffer, output_json, outpath):
        with open(outpath, "wb") as outfile:
            outfile.write(output_json)
            print(f"Saved JSON to {outpath}")
    
    with open(args.inpath, "rb") as input_file:
        input_file_buffer = bytearray( input_file.read() )
        dat_offset = find_DAT(input_file_buffer) # Let's just handle both regular DAT and BTR in one swoop
            
        dat = input_file_buffer[dat_offset:]
        output_json = DATtoJSON(dat)
        if args.outpath:
            if dat_offset == 0: # Add hexadecimal offset to aid rebuilding BTRs
                outpath = (f"{Path(args.outpath).stem}{Path(args.outpath).suffix}")
            else:
                outpath = (f"{Path(args.outpath).stem}_{hex(dat_offset)}{Path(args.outpath).suffix}")
        else:
            if dat_offset == 0: # Adding the "_output" part should keep the original file safe
                outpath = (f"{Path(args.inpath).stem}_output.json")
            else:
                outpath = (f"{Path(args.inpath).stem}_{hex(dat_offset)}_output.json")
        save_json(input_file_buffer, bytearray(output_json,"UTF-8"), outpath)


elif args.inpath.endswith(".json"): # DAT output is assumed
    with open(args.inpath, "rb") as input_file:
        input_file_buffer = bytearray( input_file.read() )
        output_dat = JSONtoDAT(input_file_buffer)
        outpath = (f"{Path(args.inpath).stem}_output.dat")
        if args.sourcefile and args.sourceoffset: # Reinsertion, particularly into BTR
            outpath = (f"{Path(args.sourcefile).stem}_output{Path(args.sourcefile).suffix}")
            if args.outpath:
                outpath = (f"{Path(args.outpath)}") # User output choice takes priority
            sourceOffset = int(args.sourceoffset,16) # But not in decimal
            shutil.copy(args.sourcefile,outpath) # This is probably faster
            with open(outpath, "r+b") as outfile:
                outfile.seek(sourceOffset)
                for byte in output_dat:
                    outfile.write(byte)
        else:
            if args.outpath:
                outpath = (f"{Path(args.outpath)}")
            with open(outpath, "wb") as outfile:
                for byte in output_dat:
                    outfile.write(byte)
        outfile.close()
        input_file.close()
        print(f"Saved DAT to {outpath}")