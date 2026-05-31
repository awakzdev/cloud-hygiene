from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_ENV: str = "dev"
    APP_SECRET: str = "dev-secret"
    JWT_SECRET: str = "dev-jwt"
    JWT_ALG: str = "HS256"

    DATABASE_URL: str = "postgresql+psycopg://hygiene:hygiene@db:5432/hygiene"
    REDIS_URL: str = "redis://redis:6379/0"

    DEV_MODE: bool = False
    TRUST_PRINCIPAL_ARN: str = "arn:aws:iam::000000000000:root"
    API_PUBLIC_URL: str = "http://localhost:8000"
    FRONTEND_URL: str = "http://localhost:5173"

    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    # If set, only emails from this domain are accepted via Google OAuth (login + link).
    GOOGLE_ALLOWED_DOMAIN: str = ""
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    GITHUB_INTEGRATION_CALLBACK_PATH: str = "/v1/auth/github/callback"
    # Shared secret for verifying inbound GitHub webhook signatures (X-Hub-Signature-256) on the
    # IaC PR/push scan trigger. Empty => the webhook endpoint rejects everything (fail closed).
    GITHUB_WEBHOOK_SECRET: str = ""

    GITLAB_CLIENT_ID: str = ""
    GITLAB_CLIENT_SECRET: str = ""
    GITLAB_INTEGRATION_CALLBACK_PATH: str = "/v1/integrations/gitlab/callback"

    RESEND_API_KEY: str = ""
    DIGEST_FROM: str = "hygiene@example.com"

    # Fernet key for encrypting role_arn + external_id at rest.
    # Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    ENCRYPTION_KEY: str = "IqebDQNnegvXTO6n5gdTpVcZGXXE35Fcdh2hwT7oQxM="

    # Public URL of the read-only CloudFormation template a customer launches
    # in their own AWS account. Must be fetchable by CloudFormation in the
    # customer's account (S3 object URL — GitHub raw URLs are not reliable).
    # Override in prod to pin a versioned object when the template changes.
    CFN_TEMPLATE_URL: str = (
        "https://amzn-s3-vigil.s3.us-east-1.amazonaws.com/infra/vigil-stack.yaml"
    )
    # Parent connector stack + IAM role names (nested child templates).
    CFN_STACK_NAME: str = "VigilAccountConnector"
    CFN_STACK_NAME_LEGACY: str = "VigilReadOnly"
    CFN_SCANNER_ROLE_NAME: str = "VigilScannerRole"
    # Legacy split-stack policy-gen role (pre-unified connector); derive_advanced_role_arn maps these.
    CFN_POLICY_GENERATION_ROLE_NAME: str = "VigilPolicyGenerationRole"
    CFN_SCANNER_ROLE_NAME_LEGACY: str = "VigilReadOnlyScannerRole"
    CFN_REMEDIATION_AUTOMATION_ROLE_NAME: str = "VigilRemediationAutomationRole"
    CFN_REMEDIATION_TEMPLATE_URL: str = (
        "https://amzn-s3-vigil.s3.us-east-1.amazonaws.com/infra/vigil-remediation-ssm.yaml"
    )
    CFN_REMEDIATION_SSM_TEMPLATE_URL: str = (
        "https://amzn-s3-vigil.s3.us-east-1.amazonaws.com/infra/vigil-remediation-ssm.yaml"
    )

    # Customer remediation automation home region.
    REMEDIATION_AUTOMATION_REGION: str = "us-east-1"
    REMEDIATION_SSM_DOCUMENT_NAME: str = "Vigil-RemediationPlanExecutor"
    REMEDIATION_PLAN_TTL_MINUTES: int = 60

    # When True (default) hitting /v1/auth/{github,gitlab,google} *without*
    # a link_token creates a new user+org if no existing user matches the
    # IdP id or email. Set False to require explicit signup (recommended
    # once you have paying customers — prevents accidental fragmentation
    # when a user signs in via a personal IdP under a different email).
    ALLOW_SSO_SIGNUP: bool = True

    # Optional Ed25519 seed (32 bytes, base64) to sign evidence pack checksum manifests.
    # Generate: python -c "import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
    EVIDENCE_PACK_SIGNING_KEY: str = ""

    # Immutable evidence vault (WORM) — uploads on evidence-pack export when enabled.
    # Base S3 location for archived packs, e.g. s3://vigil-worm-storage/vigil
    EVIDENCE_VAULT_ENABLED: bool = False
    EVIDENCE_VAULT_S3_URI: str = ""
    EVIDENCE_VAULT_S3_REGION: str = ""
    EVIDENCE_VAULT_OBJECT_LOCK_MODE: str = "GOVERNANCE"
    EVIDENCE_VAULT_RETENTION_DAYS: int = 365
    # none | presigned | approved_link (future auditor read path)
    EVIDENCE_VAULT_AUDITOR_ACCESS_MODE: str = "none"

    # Go HCL patch binary (repo-aware Terraform PRs). Default: /usr/local/bin/hclpatch
    HCLPATCH_BIN: str = "/usr/local/bin/hclpatch"
    # Skip terraform fmt/validate when binary missing (dev only).
    TERRAFORM_VALIDATE_SKIP: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
