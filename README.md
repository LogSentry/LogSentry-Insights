# Network Traffic Analysis
## Table of Contents

- [Overview](#overview)
- [Files](#files)
    - [FLOWpy.py](#flowpypy)
    - [Dataport.ipynb](#dataportipynb)
    - [git-workflow.ps1](#gitworkflowps1)
    - [LogicInsights_LLM_TransferLearning.ipynb](#logicinsights_llm_transferlearningipynb)
    - [LayerbyLayer.ipynb](#layerbylayeripynb)
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

```
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

```
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

## Installation

Clone the repository:

```
git clone https://github.com/LogSentry/LogSentry-Insights/tree/test
cd network-traffic-analysis
```

Install Python dependencies:

```
pip install scapy numpy psutil
```

Install Jupyter (if not already installed):

```
pip install jupyter
```

Ensure you have PowerShell installed for running `git-workflow.ps1`.

### LogicInsights_LLM_TransferLearning.ipynb

**Description:**
`LogicInsights_LLM_TransferLearning.ipynb` is a Jupyter Notebook that demonstrates the process of transfer learning using a pre-trained Language Model (LLM) for a specific task. It includes steps for data preparation, model architecture modification, training, and evaluation. The notebook is designed to be user-friendly and provides detailed explanations for each step.

**Key Features:**

- **Data Preparation**: 
  - Loads and preprocesses the dataset, including tokenization and normalization.
  - Handles various data formats and ensures compatibility with the model.
- **Model Architecture**: 
  - Utilizes a pre-trained Language Model.
  - Modifies the architecture for the specific task by traning it.
  - Supports customization of model parameters and layers.
- **Training**: 
  - Defines training parameters such as learning rate, batch size, and number of epochs.
  - Implements techniques to prevent overfitting, such as dropout and early stopping.
  - Provides real-time monitoring of training progress with visualizations.
- **Evaluation**: 
  - Evaluates the model using metrics such as accuracy, precision, recall, and F1-score.
- **Output**: 
  - Provides final evaluation metrics and visualizations of the results.
  - Saves the trained model and evaluation reports for future use.
  - Generates detailed logs for tracking the experiment.

# Example usage of git-workflow.ps1
```
.\git-workflow.ps1 -commit "Fix bug #123" -push
```
**Key Features:**

- Commit Changes: Automate the commit process with specified commit messages.
- Push to Remote: Push local changes to a remote repository with ease.
- Branch Management: Simplify branch creation and switching.

### LayerbyLayer.ipynb

**Description:**
`LayerbyLayer.ipynb` is a Jupyter Notebook that provides an in-depth exploration of neural network layers and their operations. It includes detailed explanations and visualizations of various layers, their forward and backward propagation, and the role of each layer in training a neural network.

**Key Features:**

- **Layer-by-Layer Analysis**: 
  - Explains the purpose and function of different types of neural network layers (e.g., Dense, Convolutional).
  - Provides visualizations of layer operations and their impact on the data.
- **Forward Propagation**: 
  - Demonstrates how data flows through each layer during forward propagation.
- **Backward Propagation**: 
  - Illustrates how gradients are calculated and propagated backward through the network.
- **Gradient Computation**: 
  - Includes detailed derivations and examples of gradient calculations for various layers.
  - Shows how gradients are used to update weights and biases.

**How to Use:**

Open the notebook in Jupyter:

```
jupyter notebook LayerbyLayer.ipynb
```

Follow the instructions within the notebook to explore neural network layers and their operations.

## Installation

Clone the repository:

```
git clone https://github.com/LogSentry/LogSentry-Insights/tree/test
cd network-traffic-analysis
```

Install Python dependencies:

```
pip install scapy numpy psutil
```

Install Jupyter (if not already installed):

```
pip install jupyter
```

## Installation

Clone the repository:

```
git clone https://github.com/LogSentry/LogSentry-Insights/tree/test
cd network-traffic-analysis
```

Install Python dependencies:

```
pip install scapy numpy psutil
```

Install Jupyter (if not already installed):

```
pip install jupyter
```

Ensure you have PowerShell installed for running `git-workflow.ps1`.

## Contributing

If you have suggestions or improvements, feel free to submit a pull request or open an issue.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
