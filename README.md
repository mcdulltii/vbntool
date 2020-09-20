# vbntool

A tool to extract data and the quarantined file from .vbn files created by Symantec Endpoint Protection.

REF: [Unquarantine VBN Files](https://malwaremaloney.blogspot.com/2018/03/symantec-endpoint-protection-vbn-files.html)

## NOTE

This tool is forked from [Justin's VBNTool](https://github.com/JustinOng/vbntool)

This repo contains improvements upon the above repo:

1. Reading huge files

```python
CHUNK_SIZE = 1024

def read_chunks(filename, chunk_size = CHUNK_SIZE):
    while True:
        data = filename.read(chunk_size)
        if not data:
            break
        yield [chr(i) for i in data]

def xor(data, key):
    new_data = bytearray()
    for i in data:
        new_data.append(ord(i) ^ int(key, 16))
    return new_data
```

2. Unquarantining .vbn files with basic quarantine format

```python
if (unpack("<Q", xor([chr(i) for i in vbn[qfm_offset+24:qfm_offset+32]], '0x5A'))[0] >= len(vbn)):
	infile = open(args.vbn_file, "rb")
	infile.seek(qfm_offset)
	outfile = open(out_name, "wb")
	for piece in read_chunks(infile):
		outfile.write(xor(piece, '0x5A'))
```

#### The below information is referred from the repo mentioned above.

## Requirements

Python 3

## Usage

```shell
> python vbntool.py -h
usage: vbntool.py [-h] [-v] [-l] [-i] [-o [OUTPUT]] vbn_file

Parse a Symantec Quarantine File (*.vbn)

positional arguments:
  vbn_file              Provide a .vbn file to extract information from

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Enable verbose output
  -l, --logline         Displays metadata from the embedded log line
  -i, --ignore          Extract quarantine file even if hash does not match
  -o [OUTPUT], --output [OUTPUT]
                        Name to save quarantined file as. Defaults to original
                        name if this flag is provided without a value
```

The tool will just print information about the file if no arguments are provided:

```shell
> python vbntool.py 5D4A3899.VBN
[INFO ] Loaded 5D4A3899.VBN (109428 bytes)
[INFO ] Quarantined File was at: C:\Users\a\Desktop\2019-06-12-malware-EXE-from-80.85.155.70.exe
[INFO ] Quarantine File created at 2019-06-19T21:28:57
[INFO ] Quarantined File has SHA1 hash: 2552e23ba01ccbfa9f8cf5a8b4ef29b8173cfe0e
[INFO ] Quarantined File has size: 100352 bytes
[INFO ] Quarantine file hash verified ok
[INFO ] Pass -o/--output to extract the quarantined file
```

### Extracting Quarantined File
To extract the quarantined file, pass the `-o/--output` argument. If `-o/--output` is specified without a file name, the initial file name is used:

```shell
> python vbntool.py 5D4A3899.VBN -o
[INFO ] Loaded 5D4A3899.VBN (109428 bytes)
[INFO ] Quarantined File was at: C:\Users\a\Desktop\2019-06-12-malware-EXE-from-80.85.155.70.exe
[INFO ] Quarantine File created at 2019-06-19T21:28:57
[INFO ] Quarantined File has SHA1 hash: 2552e23ba01ccbfa9f8cf5a8b4ef29b8173cfe0e
[INFO ] Quarantined File has size: 100352 bytes
[INFO ] Quarantine file hash verified ok
[INFO ] Writing 100352 bytes to 2019-06-12-malware-EXE-from-80.85.155.70.exe
```

If a file name is specified, it is used instead:

```shell
> python vbntool.py 5D4A3899.VBN -o out.exe
[INFO ] Loaded 5D4A3899.VBN (109428 bytes)
[INFO ] Quarantined File was at: C:\Users\a\Desktop\2019-06-12-malware-EXE-from-80.85.155.70.exe
[INFO ] Quarantine File created at 2019-06-19T21:28:57
[INFO ] Quarantined File has SHA1 hash: 2552e23ba01ccbfa9f8cf5a8b4ef29b8173cfe0e
[INFO ] Quarantined File has size: 100352 bytes
[INFO ] Quarantine file hash verified ok
[INFO ] Writing 100352 bytes to out.exe
```

The tool will warn if the file hash stated in the .vbn file differs from the hash of the extracted file. Pass the `-i/--ignore` argument to extract the quarantined file anyway

```shell
> python vbntool.py 5D4A3899.VBN -o
[INFO ] Loaded 5D4A3899.VBN (109428 bytes)
[INFO ] Quarantined File was at: C:\Users\a\Desktop\2019-06-12-malware-EXE-from-80.85.155.70.exe
[INFO ] Quarantine File created at 2019-06-19T21:28:57
[INFO ] Quarantined File has SHA1 hash: 2552e23ba01ccbfa9f8cf5a8b4ef29b8173cfe0e
[INFO ] Quarantined File has size: 100352 bytes
[WARNING] Actual SHA1(e57b0077000981d43435c749d98b7981ceb6773e) of the quarantined file does not match stated SHA1(2552e23ba01ccbfa9f8cf5a8b4ef29b8173cfe0e)!
[WARNING] Pass -i/--ignore to extract the quarantined file anyway
```

## Log Line

The .vbn file contains a log line that provides a context for the quarantined file. Pass `-l/--logline` to print this logline:

```shell
> python vbntool.py 5D4A3899.VBN -l
[INFO ] Loaded 5D4A3899.VBN (109428 bytes)
[INFO ] Quarantined File was at: C:\Users\a\Desktop\2019-06-12-malware-EXE-from-80.85.155.70.exe
[INFO ] [LOG] Time: 2019-06-19 06:28:57
[INFO ] [LOG] Event: INFECTION
[INFO ] [LOG] Category: INFECTION
[INFO ] [LOG] Logger: Real_Time
[INFO ] [LOG] Computer: DESKTOP-DUK1SA5
[INFO ] [LOG] User: a
[INFO ] [LOG] File: C:\Users\a\Desktop\2019-06-12-malware-EXE-from-80.85.155.70.exe
[INFO ] [LOG] Wanted Action 1: Quarantine
[INFO ] [LOG] Wanted Action 2: Leave Alone
[INFO ] [LOG] Real Action: Quarantine
[INFO ] [LOG] Virus Type: 256
[INFO ] [LOG] Flags: EB_ACCESS_DENIED FA_SCANNING_FILEEB_N_OVERLAYS (N_REPSEED_SCAN)
[INFO ] [LOG] ScanID: 1560950609
[INFO ] [LOG] Group ID: 0
[INFO ] [LOG] VBin_ID: 1565145241
[INFO ] [LOG] Virus ID: 55172
[INFO ] [LOG] Quarantine Forward Status: 0
[INFO ] [LOG] Access: 0
[INFO ] [LOG] SND_Status: 0
[INFO ] [LOG] Still Infected: 0
[INFO ] [LOG] Def Sequence Number: 0
[INFO ] [LOG] Clean Info: 0
[INFO ] [LOG] Delete Info: 4
[INFO ] [LOG] Backup ID: 0
[INFO ] [LOG] GUID: {054D2BD6-182C-408B-9A82-259389DCB121}
[INFO ] [LOG] Status: 0
[INFO ] [LOG] Log Session GUID: ba8186b7-7f31-4e9c-86c8-79806bd12c34
[INFO ] [LOG] VBin Session ID: 1279262720
[INFO ] [LOG] Dynamic Categoryset ID: SCANW_CATEGORY_SET_MALWARE
[INFO ] [LOG] Display Name To Use: Application Name
[INFO ] [LOG] Reputation Disposition: Good
[INFO ] [LOG] Reputation Confidence: 0
[INFO ] [LOG] First Seen: 0
[INFO ] [LOG] Reputation Prevalence: 0
[INFO ] [LOG] CIDS State: 0
[INFO ] [LOG] Behavior Risk Level: 0
[INFO ] [LOG] Detection Type: Traditional
[INFO ] [LOG] Scan Duration: 0
[INFO ] [LOG] Scan Start Time: 2019-06-19 06:28:57
[INFO ] [LOG] TargetApp Type: Normal
[INFO ] Quarantine File created at 2019-06-19T21:28:57
[INFO ] Quarantined File has SHA1 hash: 2552e23ba01ccbfa9f8cf5a8b4ef29b8173cfe0e
[INFO ] Quarantined File has size: 100352 bytes
[INFO ] Quarantine file hash verified ok
[INFO ] Pass -o/--output to extract the quarantined file
```

Do note that the line has been parsed according to https://support.symantec.com/us/en/article.tech100099.html and still has some minor issues.
