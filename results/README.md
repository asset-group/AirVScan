# AirVScan Evaluation Results and Figures

This directory contains experimental evaluation data and complete high-resolution figures accompanying the paper.

## Directory Structure

```text
results/
├── README.md
├── 5G NR.csv
├── Bluetooth.csv
├── Giraffe.csv
├── fig_legend_best5.pdf
├── fig_legend_majority5.pdf
├── rq1_full/
│   ├── best5/
│   │   ├── 5G NR.pdf
│   │   ├── Bluetooth.pdf
│   │   └── Giraffe.pdf
│   └── majority5/
│       ├── 5G NR.pdf
│       ├── Bluetooth.pdf
│       └── Giraffe.pdf
├── context_impact_full/
│   ├── best5/
│   │   ├── 5G NR.pdf
│   │   ├── Bluetooth.pdf
│   │   └── Giraffe.pdf
│   └── majority5/
│       ├── 5G NR.pdf
│       ├── Bluetooth.pdf
│       └── Giraffe.pdf
├── context_impact_diff/
│   ├── best5/
│   │   ├── 5G NR.pdf
│   │   ├── Bluetooth.pdf
│   │   └── Giraffe.pdf
│   └── majority5/
│       ├── 5G NR.pdf
│       ├── Bluetooth.pdf
│       └── Giraffe.pdf
├── noise_impact_full/
│   ├── best5/
│   │   ├── 5G NR.pdf
│   │   └── Bluetooth.pdf
│   └── majority5/
│       ├── 5G NR.pdf
│       └── Bluetooth.pdf
└── noise_impact_diff/
    ├── best5/
    │   ├── 5G NR.pdf
    │   └── Bluetooth.pdf
    └── majority5/
        ├── 5G NR.pdf
        └── Bluetooth.pdf
```

## Data Files

The CSV files provide aggregated evaluation results across three communication protocols:
- `5G NR.csv`: Evaluation metrics on 5G NR protocol test cases (including `5guest-nas` and `5guest-rrc`).
- `Bluetooth.csv`: Evaluation metrics on Bluetooth protocol test cases.
- `Giraffe.csv`: Evaluation metrics on Giraffe (Modbus) protocol test cases.

### Column Descriptions

- `case_type`: Category of the test case (`benign`, `dup`, `mut-1-field`, `mut-2-field`, `mut-3+-field`, `reorder`, `reorder-noword`, `5guest-nas`, `5guest-rrc`).
- `noise_type`: Traffic background condition (`normal` without background noise, `noise` with injected background traffic).
- `prompt_type`: Evaluation objective:
  - `check_attack`: Attack detection task.
  - `root_cause`: Root-cause / attack vector localization task.
- `prompt_mode`: Prompt construction representation:
  - `full`: Complete trace representation without specification context.
  - `full+context`: Complete trace representation with specification context.
  - `diff`: Differential trace representation without specification context.
  - `diff+context`: Differential trace representation with specification context.
- Model columns (`gemini-2.5-pro`, `grok-4`, `o3`):
  - `{model}_res_best_5`: Cases with correct detection in at least 1 of 5 trials (Best@5).
  - `{model}_res_maj_5`: Cases with correct detection in at least 3 of 5 trials (Majority@5).
  - `{model}_reasoning_best_5`: Cases with correct reasoning in at least 1 of 5 trials (Best@5).
  - `{model}_reasoning_maj_5`: Cases with correct reasoning in at least 3 of 5 trials (Majority@5).
  - `{model}_count`: Total number of evaluated test cases under this condition.

## Figures

All figures are vector PDFs plotted across two evaluation metric paradigms:
- `best5/`: Aggregations under the Best@5 metric (at least 1 correct out of 5 trials).
- `majority5/`: Aggregations under the Majority@5 metric (at least 3 correct out of 5 trials).

### Figure Subdirectories

- `rq1_full/`: Overall performance comparisons across all test categories for each protocol.
- `context_impact_full/`: Impact of specification context when using full-trace prompts.
- `context_impact_diff/`: Impact of specification context when using differential prompts.
- `noise_impact_full/`: Resilience against background noise under full-trace prompts.
- `noise_impact_diff/`: Resilience against background noise under differential prompts.
- `fig_legend_best5.pdf` / `fig_legend_majority5.pdf`: Standalone visual legends for hatches and model color keys.
