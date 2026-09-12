# Threat Intelligence Automation & Infrastructure as Code Security

This repository contains the complete deliverables for the Arzens Engineering Internship Program (Advanced Track) — Week 06-07 Combined Assignment. 

The project bridges the gap between cybersecurity automation and secure cloud infrastructure by implementing a robust Threat Intelligence (TI) enrichment pipeline and deploying a secure, compliant cloud environment using Infrastructure as Code (IaC).

## 🚀 Project Overview

The project is divided into two major components:

### Part A: Threat Intelligence Automation (Week 06)
A production-grade Threat Intelligence pipeline designed to aggregate, enrich, and manage Indicators of Compromise (IOCs) for an Enterprise SOC.
*   **Task 1: Architecture Design** - Theoretical design of a highly scalable TI platform addressing rate limiting, caching, and false-positive prevention.
*   **Task 2: TI Enrichment Engine** - A Python CLI tool that queries VirusTotal, AbuseIPDB, and AlienVault OTX to dynamically score and enrich IOCs (IPs, domains, hashes).
*   **Task 3: IOC Manager & Automation** - A Python-based lifecycle management system to track IOC confidence over time, automatically expire stale indicators, and generate blocklists for SIEM ingestion.

### Part B: Infrastructure as Code Security (Week 07)
A secure provisioning and configuration management pipeline for cloud deployments.
*   **Task 4: IaC Security Architecture** - Theoretical design for secure state management, secrets externalization, drift detection, and compliance validation.
*   **Task 5: Terraform Secure Infrastructure** - Declarative AWS infrastructure provisioning (VPC, private S3 buckets, hardened EC2 instances) featuring encrypted remote state.
*   **Task 6: Ansible Hardening & Compliance** - Imperative OS hardening playbooks utilizing CIS benchmark concepts (UFW firewalls, SSH hardening, Fail2ban, Auditd).

## 📂 Repository Structure

```text
📦 Threat-Intelligence-Automation-and-Infrastructure-as-Code-Security
├── 📁 Task1_Architecture/
│   ├── architecture_design.md     # Architecture documentation
│   └── architecture_design.pdf    # PDF export of architecture
├── 📁 Task2_Enrichment/
│   ├── ti_enricher.py             # Python enrichment engine
│   ├── config.yaml                # External API credentials template
│   └── sample_indicators.csv      # Sample IOCs for testing
├── 📁 Task3_IOC_Manager/
│   ├── ioc_manager.py             # Python IOC lifecycle manager
│   ├── ioc_config.yaml            # Manager thresholds & config
│   └── blocklist.txt              # Sample SIEM export output
├── 📁 Task4_IaC_Architecture/
│   ├── iac_security.md            # IaC architecture documentation
│   └── iac_security.pdf           # PDF export of IaC architecture
├── 📁 Task5_Terraform/
│   ├── main.tf                    # AWS Resource definitions
│   ├── variables.tf               # Terraform input variables
│   ├── outputs.tf                 # Terraform outputs
│   └── terraform.tfvars.example   # Secrets template
└── 📁 Task6_Ansible/
    ├── site.yml                   # Main playbook
    ├── ansible.cfg                # Ansible configurations
    └── roles/                     # Common, Security, and Compliance roles
```

## 🛠️ Technologies & Tools Used
*   **Languages:** Python, HCL (HashiCorp Configuration Language), YAML
*   **Cloud & Provisioning:** AWS (EC2, S3, VPC), Terraform
*   **Configuration Management:** Ansible
*   **Security APIs:** VirusTotal API v3, AbuseIPDB API v2, AlienVault OTX API
*   **OS Hardening:** UFW, Fail2ban, Auditd, SSHd configurations

## ⚙️ How to Use

### 1. Threat Intelligence Tools
Navigate to `Task2_Enrichment/` and populate `config.yaml` with your respective API keys.
```bash
python ti_enricher.py --input-file sample_indicators.csv --format table
```

Navigate to `Task3_IOC_Manager/` to process and export the enriched data.
```bash
python ioc_manager.py --expire-check --export-blocklist --generate-report
```

### 2. Infrastructure as Code (Terraform)
Navigate to `Task5_Terraform/` and configure your `terraform.tfvars`. Ensure your AWS CLI is authenticated.
```bash
terraform init
terraform plan
terraform apply
```

### 3. Server Hardening (Ansible)
After Terraform outputs the public IP of the EC2 instance, navigate to `Task6_Ansible/`, update the IP in `hosts.ini`, and run the playbook to harden the server.
```bash
ansible-playbook -i hosts.ini site.yml
```

## 📜 License
This project was developed for the Arzens Engineering Internship Program. 
