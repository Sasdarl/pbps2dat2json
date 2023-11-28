# pbps2dat2json
A Python 3.4 script capable of converting DAT (overlay data) files in JoJo's Bizarre Adventure: Phantom Blood (PS2) into JSON and back.

Optional parameters:

**-o (--outfile):** Set a filename for the output file.

**-sf (--sourcefile):** Select a file to import converted DAT data into a copy of. The original file will not be overwritten. No effect without the sourceoffset parameter.

**-so (--sourceoffset):** Select a position within the source file to import converted DAT data into. No effect without the sourcefile parameter.

**-in (--indent):** Set the level of whitespace indentation when exporting JSON.
