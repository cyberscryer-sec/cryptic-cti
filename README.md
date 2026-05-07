# cryptic-cti

A compact cyber threat collections-support project focused on transforming noisy multilingual cybercrime leads into structured, analyst-usable outputs.

## Overview

`cryptic-cti` is a Python-based workflow that demonstrates how messy English- and Chinese-language reporting related to credential theft, infostealers, malware tooling, and cybercrime ecosystem activity can be normalized, clustered, enriched, and converted into analyst-oriented outputs.

The project is designed around a realistic collections-support problem:

> How can multilingual, low-signal cybercrime reporting be transformed into structured intelligence that analysts can quickly interpret and act on?

Rather than functioning as a full-scale threat intelligence platform, this project focuses on one operationally important layer of the workflow:

* multilingual normalization
* entity consistency
* lead clustering
* IOC extraction
* analyst-facing summarization

The workflow emphasizes practical CTI engineering concepts including data normalization, extraction pipelines, confidence scoring, clustering logic, and structured export generation.

---

# Current Capabilities

* Multilingual normalization (English + Chinese)
* Entity extraction and canonicalization
* IOC extraction workflows
* Alias and terminology normalization
* Cluster construction and merging
* Analyst-oriented summary generation
* Confidence scoring support
* Structured JSON/CSV exports
* Extensible output pipeline architecture

---

# Design Goals

This project intentionally prioritizes:

* realistic CTI workflow modeling
* explainable transformations
* structured outputs
* multilingual handling
* modular pipeline architecture

The goal is not to automate intelligence analysis end-to-end, but to reduce noisy collections data into cleaner analyst-ready signal.

---

# Pipeline Stages

The workflow currently consists of four primary stages:

1. Metadata Parsing  
   Extracts and structures source metadata from raw lead text.

2. Semantic Extraction  
   Performs multilingual entity extraction and candidate identification.

3. Classification  
   Applies category and activity classification logic to extracted entities.

4. Normalization  
   Canonicalizes aliases, malware names, activities, and related entities into structured outputs.

After normalization, the workflow supports multiple export paths for generating structured analyst-facing outputs.

---

# Technologies Used

* Python
* Pydantic
* GLiNER
* JSON/YAML configuration workflows
* Structured export pipelines
* Rule-based normalization systems

---

# Running the Project

## Clone the repository

```bash
git clone https://github.com/<your-username>/cryptic-cti.git
cd cryptic-cti
```

## Install dependencies

```bash
pip install -r requirements.txt
```

## Run the workflow

```bash
python main.py
```

---


# Current Scope

This repository is currently focused on:

* credential theft ecosystems
* infostealer-related lead normalization
* multilingual cybercrime reporting
* collections-support workflow prototyping

The project uses lawful sample data and synthetic examples for demonstration purposes.

---

# Roadmap

Planned future improvements include:

* STIX export support
* Additional language coverage
* Improved clustering confidence logic
* Additional collection-source adapters
* Analyst review/triage workflows
* Enhanced report generation
* IOC-enriched detection generation
* Expanded testing and validation coverage

---

# Disclaimer

This project is intended for educational, research, and portfolio purposes only.

No intrusion, unauthorized access, credential abuse, or operational malicious activity is performed or supported by this repository.

All examples are either synthetic, sanitized, or derived from lawful open-source reporting.

---

# License

MIT License
