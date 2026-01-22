# Terraform Infrastructure Documentation

## Files discovered
- `samples/terraform/network.tf`
- `samples/terraform/security.tf`

## High-level intent
This section explains what the Terraform configuration is building and how it is wired together, with extra emphasis on **security, authentication/authorization, and network segmentation**.

## Resources

### Networking: `aws_vpc`
**What this is:** Creates a Virtual Private Cloud (VPC) to isolate resources in a private network boundary.
**Key concerns:** `CIDR planning`, `segmentation`, `logging`, `least privilege routing`

#### `aws_vpc.main`
- File: `samples/terraform/network.tf`
- Purpose: Creates a Virtual Private Cloud (VPC) to isolate resources in a private network boundary.
- Notable configuration:
  - **CIDR**: `10.20.0.0/16`
  - Enable DNS: `enable_dns_support=true`, `enable_dns_hostnames=true`
- Config keys (partial): `cidr_block`, `enable_dns_support`, `enable_dns_hostnames`, `tags`

### Networking: `aws_subnet`
**What this is:** Creates a subnet inside a VPC. Used for public/private segmentation and AZ placement.
**Key concerns:** `public vs private`, `route tables`, `NAT design`, `AZ redundancy`

#### `aws_subnet.public_a`
- File: `samples/terraform/network.tf`
- Notable configuration:
  - **Subnet CIDR**: `10.20.1.0/24`
  - **Availability Zone**: `us-east-1a`
  - **Public IP on launch**: `true`

#### `aws_subnet.private_app_a`
- File: `samples/terraform/network.tf`
- Notable configuration:
  - **Subnet CIDR**: `10.20.11.0/24`
  - **Availability Zone**: `us-east-1a`
  - **Public IP on launch**: `unknown`

#### `aws_subnet.private_data_a`
- File: `samples/terraform/network.tf`
- Notable configuration:
  - **Subnet CIDR**: `10.20.21.0/24`
  - **Availability Zone**: `us-east-1a`

### Security: `aws_security_group`
**What this is:** Defines stateful firewall rules for inbound/outbound traffic.
**Key concerns:** `least privilege ports`, `no 0.0.0.0/0 on admin ports`, `egress control`, `tagging/ownership`

#### `aws_security_group.alb_sg`
- File: `samples/terraform/security.tf`
- Notable configuration:
  - **Ingress rules**: 1
  - **Egress rules**: 1

#### `aws_security_group.app_sg`
- File: `samples/terraform/security.tf`
- Notable configuration:
  - **Ingress rules**: 1
  - **Egress rules**: 1

## Security & segmentation checklist (opinionated)
- Prefer **private subnets** for app + data; only expose an ALB/API gateway publicly.
- Avoid SSH/RDP from `0.0.0.0/0`. Use SSM Session Manager or a bastion with strict allowlists.
- Enable **VPC Flow Logs** and **CloudTrail**; centralize logs.
- Encrypt data at rest (KMS) and in transit (TLS).
- Use Secrets Manager/SSM for secrets; do not commit credentials.
- Minimize security group egress; prefer explicit allowlists for sensitive tiers.
