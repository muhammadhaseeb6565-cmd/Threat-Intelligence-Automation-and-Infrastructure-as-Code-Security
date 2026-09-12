# Ansible Configuration Management

This folder contains Ansible playbooks to harden the provisioned cloud infrastructure.

## Structure
- `ansible.cfg`: Global Ansible settings.
- `hosts.ini`: Inventory file (update with your EC2 public IP).
- `site.yml`: Main playbook orchestrating all roles.
- `security.yml`: Playbook for applying only the security role.
- `roles/`:
  - `common`: System updates and base packages.
  - `security`: SSH hardening, UFW firewall, fail2ban, auditd.
  - `compliance`: CIS-like checks and report generation.

## Execution

1. **Update Inventory:**
   Edit `hosts.ini` and replace the placeholder IP with the `instance_public_ip` output from Terraform.

2. **Run Full Provisioning:**
   ```bash
   ansible-playbook -i hosts.ini site.yml
   ```
   This will run all roles and generate a `compliance_report.txt` locally.

3. **Run Security Only:**
   ```bash
   ansible-playbook -i hosts.ini security.yml
   ```

4. **Verify Compliance:**
   Check the generated `compliance_report.txt` in this directory to view the pass/fail status of the security controls.
