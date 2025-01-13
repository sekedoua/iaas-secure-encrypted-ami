# Secure AMI Creation and Deployment

This repository contains the necessary code and workflows to automate the creation of a secure, encrypted Amazon Machine Image (AMI) and deploy it as an EC2 instance. The process ensures that the AMI and instance follow AWS security best practices by using encryption and controlled access.

---

## **Features**
- **Encrypted AMI Creation:** Automates the creation of an AMI with encryption using AWS KMS.
- **GitHub Actions Workflow:** Provides a pre-configured GitHub Actions workflow to manage and validate AMI creation and instance deployment.
- **Security Best Practices:**
  - Configures security groups with restricted access.
  - Ensures encrypted root volumes for EC2 instances.
- **Customizable Inputs:** Supports user-defined configurations such as instance type, base AMI ID, and security group.

---

## **Directory Structure**
```plaintext
.
├── .github/
│   └── workflows/
│       └── secure_ami.yml  # GitHub Actions workflow for Secure AMI creation
├── requirements.txt         # Python dependencies for the project
├── secure_ami.py            # Python script to create and validate a secure AMI
├── .gitignore               # Files to ignore in version control
├── README.md                # Project documentation

