# Secure Infrastructure Provisioning

This folder contains the Terraform configuration to provision a secure AWS infrastructure.

## Requirements
- Terraform v1.5+
- AWS CLI configured with appropriate credentials.

## Setup Instructions

1. **Initialize Terraform:**
   ```bash
   terraform init
   ```

2. **Configure Variables:**
   Copy the example variables file and update it with your IP address and a globally unique S3 bucket name.
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   ```

3. **Plan the Deployment:**
   Review the resources that will be created.
   ```bash
   terraform plan -out=tfplan
   ```

4. **Apply the Configuration:**
   Deploy the infrastructure to AWS.
   ```bash
   terraform apply tfplan
   ```

## Security Features Implemented
- **VPC & Subnets:** Custom VPC with a public subnet and internet gateway.
- **Security Groups:** Restricts ingress to SSH (from a specific IP only), HTTP, and HTTPS.
- **EC2 Instance:** Uses the latest Ubuntu 22.04 AMI, authenticates via dynamically generated RSA key pair, and saves the `.pem` file locally with restricted permissions (0400).
- **S3 Bucket:** Enforces private access, enables object versioning, and applies default AES-256 server-side encryption.
