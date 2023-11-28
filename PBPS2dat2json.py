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

def xorString(array, key):
    str = struct.pack("<31s",array)
    return bytes(a ^ key for a in str)

def decodeRender(value):
    result = []
    result.append((value & 0x02)>>1)
    result.append((value & 0x04)>>2)
    result.append((value & 0x20)>>5)
    result.append((value & 0x200)>>9)
    return result

def encodeRender(array):
    result = array[0]<<1
    result += array[1]<<2
    result += array[2]<<5
    result += array[3]<<9
    return result

def find_DAT(buf):
    MAGIC = bytearray((int(0x21), int(0x01), int(0xF0), int(0xFF)))
    offsets = []
    
    off_start = 0x0
    off_end = len(buf)
    exit = False
    
    while off_start < off_end and exit == False:
        offset = buf.find(MAGIC, off_start, off_end)
        
        if offset == -1:
            exit = True
        else:
            return offset
    
    return -1

def DATtoJSON(buf):
    offset = 0x0C
    emptydict = {}
    dict = {}
    dict["textures"] = []
    dict["groups"] = []
    for i in range(ru32(buf,0x04)):
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
            group["metadata"][j] = ruFloat(buf,offset+4+j*4)
        offset += 0x10
        if ru32(buf,offset) >= 1:
            offset += 0x08
            group["voiceLines"] = []
            for j in range(ru32(buf,offset-4)):
                voiceLine = {}
                voiceLine["voiceLength"] = ruFloat(buf,offset)
                offset += 0x04
                key = buf[offset]
                voicename = xorString(buf[offset+1:offset+32],key).rstrip('\x00'.encode())
                voiceLine["filename"] = chr(key) + voicename.decode()
                offset += 0x20
                group["voiceLines"].append(voiceLine)
        else:
            offset += 0x04
        group["overlays"] = []
        offset += 0x04
        for j in range(ru32(buf,offset-4)):
            overlay = {}
            overlay["renderFlags"] = decodeRender(ru32(buf,offset))
            overlay["textureNumber"] = ru32(buf,offset+4)
            overlay["xNumerator"] = ruFloat(buf,offset+8)
            overlay["yNumerator"] = ruFloat(buf,offset+12)
            overlay["xDenominator"] = ruFloat(buf,offset+16)
            overlay["yDenominator"] = ruFloat(buf,offset+20)
            overlay["width"] = ruFloat(buf,offset+24)
            overlay["height"] = ruFloat(buf,offset+28)
            overlay["angle"] = ruFloat(buf,offset+32)
            offset += 40

            overlay["vertexColor"] = [[],[],[],[]]
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

            if ru32(buf,offset) >= 1:
                overlay["effects"] = []
                offset += 4
                for k in range(ru32(buf,offset-4)):
                    effect = {}
                    effect["effectType"] = ru32(buf,offset)
                    if ru32(buf,offset+4) >= 1:
                        effect["effectKeyframes"] = []
                        offset += 12
                        for l in range(ru32(buf,offset-4)):
                            keyframe = []
                            keyValueCount = ru32(buf,offset+4)
                            keyframe.append(ruFloat(buf,offset))
                            for m in range(keyValueCount):
                                keyframe.append(ruFloat(buf,offset+8+m*4))
                            offset += 8+keyValueCount*4
                            effect["effectKeyframes"].append(keyframe)
                    else:
                        offset += 8
                    overlay["effects"].append(effect)
            else:
                offset += 4

            group["overlays"].append(overlay)
        dict["groups"].append(group)

    return json.dumps(dict, indent=userIndent)

def JSONtoDAT(buf):
    data = json.loads(buf)
    NewDAT = []
    if "headerMagic" not in data or data["headerMagic"] != 0:
        NewDAT.append(wu32(0xFFF00121))
    NewDAT.append(wu32(len(data["textures"])))
    NewDAT.append(wu32(len(data["groups"])))

    for texture in data["textures"]:
        NewDAT.append(wuFloat(texture["width"]))
        NewDAT.append(wuFloat(texture["height"]))
    
    for group in data["groups"]:
        NewDAT.append(wuFloat(group["length"]))
        for m in group["metadata"]:
            NewDAT.append(wuFloat(m))

        if "voiceLines" in group:
            NewDAT.append(wu32(1))
            NewDAT.append(wu32(len(group["voiceLines"])))
            for line in group["voiceLines"]:
                NewDAT.append(wuFloat(line["voiceLength"]))
                voiceline = line["filename"][1::].encode()
                key = ord(line["filename"][0])
                NewDAT.append(wu08(key))
                NewDAT.append(xorString(voiceline,key))
        else:
            NewDAT.append(wu32(0))

        NewDAT.append(wu32(len(group["overlays"])))
        for overlay in group["overlays"]:
            NewDAT.append(wu32(encodeRender(overlay["renderFlags"])))
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
                NewDAT.append(wuFloat(vc[0]))
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

            if "effects" in overlay:
                NewDAT.append(wu32(len(overlay["effects"])))
                for effect in overlay["effects"]:
                    NewDAT.append(wu32(effect["effectType"]))
                    if "effectKeyframes" in effect:
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
    return NewDAT
    

parser = argparse.ArgumentParser(description='Phantom Blood PS2 DAT-JSON Converter')
parser.add_argument("inpath", help="File Input (DAT/JSON)")
parser.add_argument("-o", "--outpath", help="Optional. The filename used for the output JSON/DAT file.")
parser.add_argument("-sf", "--sourcefile", help="Optional. The file the resulting DAT should be written into when converting JSON. No effect without the source offset.")
parser.add_argument("-so", "--sourceoffset", help="The offset in the source file the DAT should be written into when converting JSON. No effect without the source file.")
parser.add_argument("-in", "--indent", type=int, help="Determines the indentation level used for the resulting JSON file. No effect when creating DAT.")
args = parser.parse_args()

userIndent = 4
if args.indent:
    userIndent = args.indent
if not args.inpath.endswith(".json"): #DAT input is assumed
    def save_json(input_file_buffer, output_json, outpath):
        with open(outpath, "wb") as outfile:
            outfile.write(output_json)
            print(f"Saved JSON to {outpath}")
    
    with open(args.inpath, "rb") as input_file:
        input_file_buffer = bytearray( input_file.read() )
        dat_offset = find_DAT(input_file_buffer)
            
        dat = input_file_buffer[dat_offset:]
        output_json = DATtoJSON(dat)
        if args.outpath:
            if dat_offset == 0:
                outpath = (f"{Path(args.outpath).stem}{Path(args.outpath).suffix}")
            else:
                outpath = (f"{Path(args.outpath).stem}_{hex(dat_offset)}{Path(args.outpath).suffix}")
        else:
            if dat_offset == 0:
                outpath = (f"{Path(args.inpath).stem}_output.json")
            else:
                outpath = (f"{Path(args.inpath).stem}_{hex(dat_offset)}_output.json")
        save_json(input_file_buffer, bytearray(output_json,"UTF-8"), outpath)


elif args.inpath.endswith(".json"): #DAT output is assumed
    with open(args.inpath, "rb") as input_file:
        input_file_buffer = bytearray( input_file.read() )
        output_dat = JSONtoDAT(input_file_buffer)
        outpath = (f"{Path(args.inpath).stem}_output.dat")
        if args.outpath:
            outpath = (f"{Path(args.outpath)}")
            with open(outpath, "wb") as outfile:
                for byte in output_dat:
                    outfile.write(byte)
        elif args.sourcefile and args.sourceoffset:
            outpath = (f"{Path(args.sourcefile).stem}_output{Path(args.sourcefile).suffix}")
            if args.sourceoffset[1] == "x":
                sourceOffset = int(args.sourceoffset,16)
            else:
                sourceOffset = int(args.sourceoffset,10)
            shutil.copy(args.sourcefile,outpath)
            with open(outpath, "r+b") as outfile:
                outfile.seek(sourceOffset)
                for byte in output_dat:
                    outfile.write(byte)
        else:
            with open(outpath, "wb") as outfile:
                for byte in output_dat:
                    outfile.write(byte)
        outfile.close()
        input_file.close()
        print(f"Saved DAT to {outpath}")