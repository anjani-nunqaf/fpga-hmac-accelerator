# FPGA-based HMAC Cryptographic Coprocessor for Secure I2C Communication

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Language](https://img.shields.io/badge/Language-SystemVerilog%20%26%20Python-blue.svg)

## Overview

This repository contains the hardware design files (SystemVerilog) and host software (Python) for a lightweight HMAC cryptographic coprocessor. The design is implemented on an FPGA and communicates with a host system (e.g., a single-board computer) via the I2C interface. This project was developed as part of a research initiative to enhance the security of modular hardware extensions, specifically in the context of the **Laptop Merah Putih** national initiative.

The primary goal is to address the inherent lack of security in the I2C protocol by implementing a robust challenge-response authentication mechanism. This allows a host system to securely verify the identity of a connected daughterboard and protect against physical access attacks such as eavesdropping, spoofing, and replay attacks.

The accelerator is modular and supports **HMAC-SHA1**, **HMAC-SHA256**, and **HMAC-SHA512**.

## Key Features

-   **Hardware Acceleration:** Offloads computationally intensive HMAC operations from the host CPU to dedicated FPGA logic.
-   **Modular Design:** Easily adaptable for SHA-1, SHA-256, and SHA-512 by substituting the respective hash core.
-   **Secure I2C Protocol:** Implements a challenge-response authentication protocol using a nonce to prevent replay attacks and HMAC for integrity and authenticity.
-   **Platform:** Designed and verified on an Intel Cyclone V FPGA (Terasic DE10-Standard board) with a Raspberry Pi as the host controller.

## System Architecture

The system consists of a host controller (Raspberry Pi) and an FPGA-based coprocessor. They communicate over a physical I2C bus. The FPGA design is hierarchical, containing three main modules:

1.  **I2C Slave to AXI4-Lite Master Bridge:** This module acts as the translator. It receives low-level I2C commands from the host and converts them into standard AXI4-Lite bus transactions.
2.  **HMAC Control Logic (`control_logic.sv`):** The "brain" of the accelerator. This module contains the AXI4-Lite slave interface and a finite-state machine (FSM) that implements the two-pass HMAC algorithm sequence.
3.  **SHA Core:** The computational engine that performs the underlying hash function (e.g., `sha512_core.v`).



## Repository Structure
'''
├── constraints/          # Timing constraint files (.sdc)
├── doc/                  # Additional documentation (research paper, diagrams)
├── hdl/                  # HDL source files (SystemVerilog)
│   ├── sha1/
│   ├── sha256/
│   └── sha512/
├── host_sw/              # Host software (Python scripts for testing)
├── .gitignore            # Specifies files to be ignored by Git
└── README.md             # This file '''
