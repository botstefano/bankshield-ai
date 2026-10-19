import json
import os
import threading

import joblib

from ..config import settings
from ..services.url_features import feature_vector

_lock = threading.Lock()
_model = None
_meta: dict = {}


def _paths():
    return os.path.join(settings.model_dir, "model.joblib"), os.path.join(settings.model_dir, "metrics.json")


def load(train_if_missing: bool = True) -> None:
    global _model, _meta
    with _lock:
        mp, jp = _paths()
        if not os.path.exists(mp) and train_if_missing:
            from .train import _synth, train
            urls, labels = _synth(4000)
            train(urls, labels, "synthetic-demo")
        if os.path.exists(mp):
            _model = joblib.load(mp)
            if os.path.exists(jp):
                _meta = json.load(open(jp))


def version() -> str:
    return _meta.get("version", "none")


def metadata() -> dict:
    return _meta


def predict_proba(features: dict) -> float | None:
    if _model is None:
        return None
    return float(_model.predict_proba([feature_vector(features)])[0][1])
