# extract.py — robust hex / base64 / xor pipeline
import re
import base64
import sys
import os

# --- Config (change filenames if needed) ---
HEX_INPUT_FILE   = 'extracted_payload1.txt'
BIN_OUTPUT_FILE  = 'output_dump1.bin'
B64_OUTPUT_FILE  = 'decoded_dump1.bin'
FINAL_OUTPUT_FILE= 'reconstructed_dump1.bin'
XOR_KEY          = 0x42  # set to 0x41 or 0x42 as required

def debug(msg):
    print("[*]", msg)

def decodeHex(input_file, output_file):
    """
    Read input_file line by line, extract valid hex byte pairs,
    write resulting bytes to output_file.
    """
    byte_count = 0
    skipped_lines = 0
    with open(input_file, 'r', errors='ignore') as infile, open(output_file, 'wb') as outfile:
        for lineno, line in enumerate(infile, start=1):
            # find all two-hex-digit groups; this will ignore "0x" and addresses etc.
            pairs = re.findall(r'[0-9A-Fa-f]{2}', line)
            if not pairs:
                skipped_lines += 1
                continue
            hexstr = ''.join(pairs)
            try:
                data = bytes.fromhex(hexstr)
            except ValueError as e:
                # very defensive: if still odd-length somehow, drop last nibble
                if len(hexstr) % 2 == 1:
                    debug(f"Odd nibble count on line {lineno}, dropping last nibble")
                    hexstr = hexstr[:-1]
                    if not hexstr:
                        skipped_lines += 1
                        continue
                    data = bytes.fromhex(hexstr)
                else:
                    raise
            outfile.write(data)
            byte_count += len(data)

    debug(f"Hex → bin: wrote {byte_count} bytes (skipped {skipped_lines} non-hex lines).")

def decodeb64(input_file, output_file):
    """
    Read whole file as bytes (this assumes your hex->bin produced base64 text),
    then base64-decode and write result.
    """
    with open(input_file, 'rb') as infile:
        b64_data = infile.read()

    try:
        decoded_data = base64.b64decode(b64_data, validate=True)
    except Exception:
        # try a more forgiving decode (ignore invalid chars/newlines)
        decoded_data = base64.b64decode(b64_data, validate=False)

    with open(output_file, 'wb') as outfile:
        outfile.write(decoded_data)

    debug(f"Base64 decoded → wrote {len(decoded_data)} bytes.")

def decodeXOR(input_file, output_file, xor_key):
    with open(input_file, 'rb') as infile:
        data = infile.read()
    reconstructed = bytearray((b ^ xor_key) & 0xFF for b in data)
    with open(output_file, 'wb') as outfile:
        outfile.write(reconstructed)
    debug(f"XOR with 0x{xor_key:02x} → wrote {len(reconstructed)} bytes.")

if __name__ == "__main__":
    # quick checks
    for fn in (HEX_INPUT_FILE,):
        if not os.path.exists(fn):
            print(f"ERROR: required file not found: {fn}")
            sys.exit(1)

    try:
        decodeHex(HEX_INPUT_FILE, BIN_OUTPUT_FILE)
    except Exception as e:
        print("Error during hex decoding:", e)
        sys.exit(1)

    try:
        decodeb64(BIN_OUTPUT_FILE, B64_OUTPUT_FILE)
    except Exception as e:
        print("Error during base64 decoding:", e)
        sys.exit(1)

    try:
        decodeXOR(B64_OUTPUT_FILE, FINAL_OUTPUT_FILE, XOR_KEY)
    except Exception as e:
        print("Error during XOR decoding:", e)
        sys.exit(1)

    print("Reconstruction complete. Output:", FINAL_OUTPUT_FILE)
