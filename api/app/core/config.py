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

    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    GITHUB_INTEGRATION_CALLBACK_PATH: str = "/v1/auth/github/callback"

    GITLAB_CLIENT_ID: str = ""
    GITLAB_CLIENT_SECRET: str = ""
    GITLAB_INTEGRATION_CALLBACK_PATH: str = "/v1/integrations/gitlab/callback"

    RESEND_API_KEY: str = ""
    DIGEST_FROM: str = "hygiene@example.com"

    # Fernet key for encrypting role_arn + external_id at rest.
    # Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    ENCRYPTION_KEY: str = "IqebDQNnegvXTO6n5gdTpVcZGXXE35Fcdh2hwT7oQxM="

    # Public URL of the read-only CloudFormation template a customer launches
    # in their own AWS account. Pin to a versioned S3 object or a tagged
    # GitHub raw URL in production so a launched-yesterday stack and a
    # launched-today stack reference the exact same template.
    # Defaults are safe for dev; override in prod via env.
    CFN_TEMPLATE_URL: str = (
        "https://raw.githubusercontent.com/awakzdev/Vigil/main/infra/cfn/vigil-readonly-role.yaml"
    )

    # When True (default) hitting /v1/auth/{github,gitlab,google} *without*
    # a link_token creates a new user+org if no existing user matches the
    # IdP id or email. Set False to require explicit signup (recommended
    # once you have paying customers — prevents accidental fragmentation
    # when a user signs in via a personal IdP under a different email).
    ALLOW_SSO_SIGNUP: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
