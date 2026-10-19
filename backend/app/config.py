import os


def _db_url(url: str) -> str:
    # Render entrega postgres://... ; SQLAlchemy necesita postgresql+psycopg2://
    if url.startswith("postgres://"):
        url = "postgresql+psycopg2://" + url[len("postgres://"):]
    elif url.startswith("postgresql://"):
        url = "postgresql+psycopg2://" + url[len("postgresql://"):]
    return url


def _bool(v: str) -> bool:
    return v.strip().lower() in {"1", "true", "yes", "si", "sí"}


class Settings:
    def __init__(self) -> None:
        e = os.environ.get
        self.env = e("APP_ENV", "development")
        self.database_url = _db_url(e("DATABASE_URL", "sqlite:///./bankshield.db"))
        self.secret_key = e("SECRET_KEY", "dev-insecure-change-me")
        self.token_minutes = int(e("TOKEN_MINUTES", "60"))
        self.admin_email = e("ADMIN_EMAIL", "admin@bankshield.local")
        self.admin_password = e("ADMIN_PASSWORD", "")
        self.seed_demo = _bool(e("SEED_DEMO", "false"))
        # dominios bancarios autorizados (dominio registrable), separados por coma
        self.bank_domains = [
            d.strip().lower()
            for d in e(
                "BANK_DOMAINS",
                "bcp.com.pe,viabcp.com,bbva.pe,interbank.pe,scotiabank.com.pe,banbif.com.pe",
            ).split(",")
            if d.strip()
        ]
        # umbrales: bajo, medio, alto, critico
        t = [float(x) for x in e("RISK_THRESHOLDS", "15,35,60,80").split(",")]
        self.thresholds = t
        self.rate_limit_per_min = int(e("RATE_LIMIT_PER_MIN", "120"))
        self.batch_max = int(e("BATCH_MAX", "50"))
        self.model_dir = e("MODEL_DIR", os.path.join(os.path.dirname(__file__), "ml", "artifacts"))
        self.feed_urls = [u.strip() for u in e("THREAT_FEED_URLS", "").split(",") if u.strip()]
        self.feed_max_bytes = int(e("FEED_MAX_BYTES", str(20 * 1024 * 1024)))
        self.feed_stale_hours = int(e("FEED_STALE_HOURS", "48"))
        self.n8n_webhook_url = e("N8N_WEBHOOK_URL", "")
        self.n8n_webhook_secret = e("N8N_WEBHOOK_SECRET", "")
        self.anthropic_api_key = e("ANTHROPIC_API_KEY", "")
        self.llm_model = e("LLM_MODEL", "claude-sonnet-4-6")
        self.static_dir = e("STATIC_DIR", os.path.join(os.path.dirname(__file__), "..", "static"))


settings = Settings()
