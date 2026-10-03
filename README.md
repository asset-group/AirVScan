# AirVScan

AirVScan is an automated evaluation framework for protocol vulnerability detection and root-cause analysis using Large Language Models (LLMs). It analyzes packet traces from wireless and network protocols (Bluetooth Classic/BLE, 5G NR RRC/NAS, and Modbus) to determine whether an attack or anomaly occurred, identify abnormal packets, pinpoint mutated fields, and diagnose root causes.

![](images/experiment_process.png)
*Workflow of AirVScan*

## System Overview

AirVScan operates on network packet captures (pcap/pcapng) across multiple protocols, mutation depths, and noise conditions. The pipeline consists of:

1. **Packet Dissection and Trace Diffing**: Traces are parsed using Wireshark and WDissector to extract protocol state, filter labels, and structured layer fields.
2. **Prompt Synthesis and RAG Retrieval**: Test case prompts are generated in multiple modes (`full`, `diff`, `full+context`, `diff+context`). Context modes query an embedded Milvus vector store (`milvus_demo.db`) containing indexed 3GPP, Bluetooth Core, and Modbus specifications to inject relevant standard clauses.
3. **LLM Inference**: The runner (`airvscan.py`) executes queries concurrently across targeted models (Gemini, OpenAI, Grok) with structured Pydantic schemas, retry logic, and context window guards.
4. **Evaluation and Benchmarking**: Automated scripts (`evaluation/mark_res_correct.py`) and a terminal interface (`evaluation/mark_reasoning_correct.py`) validate model verdicts and reasoning chains against ground truth.

## Repository Structure

```
├── airvscan.py                 Main evaluation runner querying LLMs and storing results
├── captures.7z                 Compressed archive containing all evaluation test cases
├── documents.7z                Compressed archive containing protocol specification documents
├── constants.example.py        Template configuration file
├── init.sql                    SQLite database schema for evaluation results
├── init_db.py                  Script to initialize the SQLite results database
├── json_flatten.py             Flattens nested Wireshark dissection trees
├── llm_utils.py                LLM client wrapper (OpenAI, Gemini, Grok) with retry handling
├── pyproject.toml              Ruff linter and code formatting configuration
├── rag_utils.py                Milvus search interface and embedding utilities
├── requirements.txt            Python dependencies
├── utils.py                    Core pcap dissection, trace diffing, and WDissector helpers
├── utils_types.py              Data models, TypedDicts, and Pydantic schemas
├── data_prep/                  One-shot prompt and dataset preparation scripts
│   ├── convert_5guest_testcase.py  Converts 5G security testing samples into test cases
│   ├── gen_desc.py                 Extracts and generates 5G terminology explanations
│   ├── gen_modbus_packets.py       Synthesizes normal, mutated, and reordered Modbus packets
│   ├── generate_prompt.py          Builds prompt text files for Bluetooth and 5G test cases
│   ├── generate_prompt_modbus.py   Builds prompt text files for Modbus test cases
│   ├── helper.py                   Preprocesses pcap captures and extracts Wireshark labels
│   ├── obfuscate_packets.py        Generates obfuscation dictionary for zero-shot testing
│   ├── pickle_packets.py           Pre-caches pcapng captures into pickle files
│   ├── rag_init.py                 Initializes Milvus collections for RAG retrieval
│   ├── rag_import.py               Ingests markdown protocol specifications into Milvus
│   └── replace_modbus_docs.py      Obfuscates Modbus specification documents
├── evaluation/                 Model accuracy and reasoning evaluation tools
│   ├── mark_reasoning_correct.py   Textual terminal UI for reviewing LLM reasoning traces
│   └── mark_res_correct.py         Benchmarks LLM detection accuracy against ground truth
├── prompts/                    Prompt templates, RAG query logic, and response schemas
│   ├── my_prompts.py               Core prompt assembly and RAG specification retrieval
│   ├── my_prompts_check_attack.py  Attack detection prompt templates and output schemas
│   └── my_prompts_root_cause.py    Root cause diagnostic prompt templates and schemas
├── glossary/                   Wireshark field glossaries and description dictionaries
├── results/                    Benchmark evaluation CSV datasets and PDF figures
│   ├── README.md               Detailed documentation of results datasets and figures
│   ├── 5G NR.csv               Evaluation metrics on 5G NR protocol test cases
│   ├── Bluetooth.csv           Evaluation metrics on Bluetooth protocol test cases
│   ├── Giraffe.csv             Evaluation metrics on Giraffe (Modbus) test cases
│   ├── fig_legend_best5.pdf    Standalone visual legend for Best@5 metric
│   ├── fig_legend_majority5.pdf Standalone visual legend for Majority@5 metric
│   ├── rq1_full/               RQ1 overall performance figures (best5/ and majority5/)
│   ├── context_impact_diff/    Context impact under differential prompts
│   ├── context_impact_full/    Context impact under full prompts
│   ├── noise_impact_diff/      Noise resilience under differential prompts
│   └── noise_impact_full/      Noise resilience under full prompts
└── images/                     Workflow figures and diagrams
```

## Test Cases and Specification Documents

To keep repository clone size lightweight, all evaluation packet traces and specification documents are packaged into high-compression 7z archives: `captures.7z` and `documents.7z`.

### Extracting Archives

```bash
# Extract evaluation captures into captures/
7z x captures.7z

# Extract specification markdown documents into documents/
7z x documents.7z
```

### Captures Structure

Once extracted, the `captures/` folder has the following hierarchy:
```plain
captures/
├── cypress-bt/
│   ├── benign/
│   │   └── t1/
│   └── mut/
│       ├── 1-field/
│       │   └── t1/
│       │       └── prompts/
│       │           ├── check_attack/
│       │           │   ├── noise/
│       │           │   └── normal/
│       │           └── find_attack_vector/
│       │               ├── noise/
│       │               └── normal/
│       └── 2-field/
├── esp32-bt/
├── oneplus-fiveg/
└── mock-modbus/
```

The hierarchy is `<tested-device>` > `type of testcase (benign, mut, dup, reorder, 5guest)` > `n-field` > `test case` > `prompts`.
Four kinds of packet captures are generated for each test case:
1. `capture_bluetooth.pcapng`: Normal capture without noise, with fuzzed packet annotations.
2. `capture_bluetooth_noise.pcapng`: Noisy capture with fuzzed packet annotations.
3. `capture_bluetooth_no_original.pcapng`: Normal capture without noise and without fuzzed packet annotations.
4. `capture_bluetooth_noise_no_original.pcapng`: Noisy capture without fuzzed packet annotations.

AirVScan operates strictly on captures without fuzzed packet annotations (`*_no_original.pcapng`).

### Specification Documents Structure

The `documents/` folder contains Markdown-converted clauses from official specification bodies:
- `documents/bt/`: Bluetooth Core v4.2 specifications.
- `documents/fiveg/`: 3GPP 5G specifications including NAS (24.501), RLC (38.322), and RRC (38.331).
- `documents/modbus/`: Modbus Application Protocol v1.1b3 specification.

## Evaluation Results and Figures

The [`results/`](results/) folder contains all benchmark evaluation outputs across models (`gemini-2.5-pro`, `grok-4`, `o3`):

1. **Protocol CSV Datasets**:
   - `results/5G NR.csv`: Evaluation metrics on 5G NR test cases (including 5G security testing samples `5guest-nas` and `5guest-rrc`).
   - `results/Bluetooth.csv`: Evaluation metrics on Bluetooth test cases.
   - `results/Giraffe.csv`: Evaluation metrics on Giraffe (Modbus) test cases.
2. **Vector PDF Figures**:
   Figures are plotted using Type-42 TrueType vector fonts and partitioned into two evaluation metric paradigms:
   - `best5/`: Best@5 metric (correct detection/reasoning in $\ge 1$ of 5 trials).
   - `majority5/`: Majority@5 metric (correct detection/reasoning in $\ge 3$ of 5 trials).
   Covering:
   - `rq1_full/`: Overall performance across all test categories for each protocol.
   - `context_impact_diff/`: Impact of specification context under differential prompts.
   - `context_impact_full/`: Impact of specification context under full-trace prompts.
   - `noise_impact_diff/`: Resilience against background noise under differential prompts.
   - `noise_impact_full/`: Resilience against background noise under full-trace prompts.
   - Standalone legends: `fig_legend_best5.pdf` and `fig_legend_majority5.pdf`.

See [`results/README.md`](results/README.md) for full descriptions of all columns and metrics.

## Setup

### Prerequisites

- Linux (Ubuntu 20.04/22.04 recommended)
- Python 3.12 (via Conda or virtual environment)
- Wireshark / TShark (version 4.1+) with WDissector bindings
- `p7zip-full` (`7z`) for archive extraction

Install Python dependencies:
```bash
pip install -r requirements.txt
```

### Configuration

Copy the sample configuration file and configure API keys and paths:

```bash
cp constants.example.py constants.py
```

Update `constants.py` with:
- LLM API credentials (`LLM_API_KEY`, `LLM_API_URL`, `GOOGLE_KEY`).
- Path to `tshark` and `editcap` binaries.
- WDissector state machine and model configuration paths.

### Initializing the Results Database

To create a new results database using the provided schema:

```bash
python3 init_db.py
```

## Usage

### 1. Data and Prompt Preparation

Pre-generated prompts and capture pickles are located under `captures/` after extraction. If regenerating datasets or prompts from raw traces:

- Pre-cache packet dissections:
  ```bash
  python3 data_prep/pickle_packets.py
  ```
- Generate evaluation prompts (Bluetooth and 5G):
  ```bash
  python3 data_prep/generate_prompt.py
  ```
- Generate Modbus test cases and prompts:
  ```bash
  python3 data_prep/gen_modbus_packets.py
  python3 data_prep/generate_prompt_modbus.py
  ```

### 2. Running Evaluation

Run the canonical evaluation runner:

```bash
python3 airvscan.py
```

The runner:
- Scans `captures/` for prompt files.
- Checks `llm_res_final.sqlite3` to skip prompts that have already been evaluated.
- Checks context window boundaries for each model before dispatching queries.
- Executes queries concurrently using a thread pool.
- Validates LLM responses against Pydantic schemas (`CheckAttackRes`, `Stage1Res`).
- Saves structured outputs into `llm_res_final.sqlite3`.

### 3. Evaluating Results

To automatically verify LLM response correctness against ground truth:

```bash
python3 evaluation/mark_res_correct.py
```

To interactively review and label reasoning traces using the terminal UI:

```bash
python3 evaluation/mark_reasoning_correct.py
```

Key controls in the reasoning review UI:
- `T`: Mark reasoning as correct (`reasoning_correct = 1`).
- `F`: Mark reasoning as incorrect (`reasoning_correct = 0`).
- `N` / `Space`: Skip current record.
- `Q`: Quit.
