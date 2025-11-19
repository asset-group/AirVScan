# AirVScan

This repository contains execution code, test cases and specification documents used during AirVScan evaluation. 

## Test Cases

There are many small files in test cases and we put all our test cases in an archive `captures.7z`.
The structure inside `captures.7z` looks like:
```plain
├───cypress-bt
│   ├───benign
│   │   ├───t1
│   └───mut
│       ├───1-field
│       │   └───t1
│       │       └───prompts
│       │           ├───check_attack
│       │           │   ├───noise
│       │           │   └───normal
│       │           └───root_cause
│       │               ├───noise
│       │               └───normal
│       └───2-field
│           └───t1
```
The hierarchy is `<tested-device>` > `type of test case (e.g. benign and mut)` > `n-field` > `test case` > `prompts`. The PoC attack codes and logs to generate malicious test cases are included here. Specifically, there are four kinds of captures:
1. `capture_bluetooth.pcapng`: Normal capture without noise, with fuzzed packet information.
2. `capture_bluetooth_noise.pcapng`: Noisy capture with fuzzed packet information. 
3. `capture_bluetooth_no_original.pcapng`: Normal capture without noise and fuzzed information
4. `capture_bluetooth_noise_no_original.pcapng`: Noisy capture without noise and fuzzed information

Note that AirVScan only use captures without fuzzed packet information.
The prompts (noise, normal, with/without context, full and diff) are put together with test cases as well. 

## Results

The results for Bluetooth, 5G NR and Giraffe are placed in `results/` folder in `CSV` format.

## Specification Documents

There are many small files of protocol specification documents and we put those documents in an archive `documents.7z`.

## Evaluation Code

- `airvscan.py`: main code to run AirVScan
- `crawl_sharetechnote.py`: crawl 5G articles from https://www.sharetechnote.com/
- `gen_modbus_packets.py`: generate Modbus (Giraffe) packet sequences
- `generate_prompt_modbus.py` and `generate_prompt.py`: generate prompts 
- `init_db.py` and `init.sql`: we store our results in a sqlite database and these two are used to initialize the database. 
- `obfuscate_packets.py` and `replace_modbus_docs.py`: logic of obfuscating Modbus packet sequence.
- `pickle_packets.py`: transform PCAP files to easier data structure. Note that WDissector[^1] environment is needed.
- `rag_import.py`, `rag_init.py` and `rag_utils.py`: document search

## Evaluation Setup

For packet dissection, WDissector[^1] environment is needed and related setup documentations can be found in [^1]. AirVScan is written by Python and it is advised to run AirVScan on Python>=3.11.


[^1]: https://asset-group.github.io/disclosures/5ghoul/
