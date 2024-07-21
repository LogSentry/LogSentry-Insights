# Network Traffic Analysis
## Table of Contents

- [Overview](#overview)
- [Files](#files)
    - [FLOWpy.py](#flowpypy)
    - [Dataport.ipynb](#dataportipynb)
    - [git-workflow.ps1](#gitworkflowps1)
- [Installation](#installation)
- [Contributing](#contributing)
- [License](#license)

## Overview

This repository contains scripts and notebooks for analyzing network traffic. The project includes a Python script for extracting network features, a Jupyter notebook for interactive data exploration, and a PowerShell script for managing Git workflows.

## Files

### FLOWpy.py

**Description:**
`FLOWpy.py` is a Python script designed for the extraction and analysis of network flow statistics from .pcap files. It handles large datasets efficiently, supports multi-threaded processing, and includes capabilities for CUDA acceleration if available.

**Key Features:**

- Network Flow Statistics Extraction: Extracts various statistics from network traffic such as packet counts, byte counts, and flow metrics.
- Chunk Processing: Handles large files by processing them in chunks to avoid memory issues.
- Multi-Threading: Uses multiple threads to process .pcap files concurrently, improving performance.
- CUDA Support: Checks for CUDA availability and utilizes it for accelerated processing if possible.
- Recursive and Compressed File Handling: Supports recursive directory processing and extraction from .tar.gz archives.
- Logging: Includes logging functionality to aid in debugging and monitoring.

**Usage Example:**

```bash
python FLOWpy.py -i /path/to/input -o /path/to/output [options]
```

### Dataport.ipynb

**Description:**
`Dataport.ipynb` is a Jupyter notebook that provides an interactive environment for analyzing and visualizing network traffic data. It allows users to explore data processed by `FLOWpy.py`, generate plots, and perform statistical analyses.

**Key Features:**

- Interactive Exploration: Engage with network data through interactive widgets and visualizations.
- Data Visualization: Create plots and graphs to understand network traffic patterns and statistics.
- Analysis: Perform statistical analyses to derive insights from the network data.

**How to Use:**

Open the notebook in Jupyter:

```bash
jupyter notebook Dataport.ipynb
```

Follow the instructions within the notebook to interact with the data and generate visualizations.

### git-workflow.ps1

**Description:**
`git-workflow.ps1` is a PowerShell script designed to automate common Git operations, facilitating efficient version control and workflow management.

**Key Features:**

- Commit Changes: Automate the commit process with specified commit messages.
- Push to Remote: Push local changes to a remote repository with ease.
- Branch Management: Simplify branch creation and switching.

**Usage Example:**

```powershell
.\git-workflow.ps1 -task commit -message "Commit message"
```

## Installation

Clone the repository:

```bash
git clone https://github.com/LogSentry/LogSentry-Insights/tree/test
cd network-traffic-analysis
```

Install Python dependencies:

```bash
pip install scapy numpy psutil
```

Install Jupyter (if not already installed):

```bash
pip install jupyter
```

Ensure you have PowerShell installed for running `git-workflow.ps1`.

## Contributing

If you have suggestions or improvements, feel free to submit a pull request or open an issue.

## License

This project is licensed under the MIT License - see the LICENSE file for details.