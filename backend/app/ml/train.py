"""Entrenamiento y comparación de modelos.

Uso:
  python -m app.ml.train                      # dataset SINTÉTICO de demostración
  python -m app.ml.train --csv phiusil.csv --url-col URL --label-col label --legit-label 1

IMPORTANTE: el dataset sintético solo sirve para que la plataforma funcione de inmediato.
Sus métricas NO representan desempeño real. Para resultados reales entrena con PhiUSIIL u otro
dataset público (revisa licencia y el significado de la etiqueta antes de usarlo).
"""
import argparse
import json
import os
import random
import time
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from ..config import settings
from ..services.url_features import (BlockedTarget, InvalidUrl, feature_vector, features_from_url,
                                     registrable_domain, normalize_url)

WORDS = ["alpha", "river", "stone", "cloud", "green", "market", "pixel", "north", "swift", "bright", "oak", "delta",
         "lumen", "orbit", "maple", "tango", "violet", "harbor", "nova", "zenith"]
PATHS = ["", "/", "/about", "/products/item", "/blog/post-1", "/contact", "/help/faq", "/news/2024/story"]
BENIGN_TLD = ["com", "org", "net", "pe", "io", "edu", "com.pe"]
BAD_TLD = ["xyz", "top", "tk", "click", "icu", "buzz", "ml", "cyou"]


def _synth(n: int, seed: int = 7) -> tuple[list[str], list[int]]:
    rnd = random.Random(seed)
    brands = [d for d in settings.bank_domains]
    urls, labels = [], []
    for _ in range(n):
        if rnd.random() < 0.5:  # legítima
            kind = rnd.random()
            if kind < 0.3:
                d = rnd.choice(brands)
                sub = rnd.choice(["www.", "", "online.", "banca."])
                path = rnd.choice(["/", "/personas", "/login", "/ayuda/contacto"])
                urls.append(f"https://{sub}{d}{path}")
            else:
                d = rnd.choice(WORDS) + rnd.choice(["", "-"]) + rnd.choice(WORDS) + "." + rnd.choice(BENIGN_TLD)
                urls.append(f"https://{rnd.choice(['www.', ''])}{d}{rnd.choice(PATHS)}")
            labels.append(0)
        else:  # phishing
            kind = rnd.random()
            b = rnd.choice(brands)
            token = b.split(".")[0]
            if kind < 0.3:
                typo = list(token)
                i = rnd.randrange(len(typo))
                typo[i] = rnd.choice("01lio") if rnd.random() < .5 else rnd.choice("abcdefghijklmnopqrstuvwxyz")
                urls.append(f"https://{''.join(typo)}{rnd.choice(['', '-seguro', '-online'])}.{rnd.choice(BENIGN_TLD + BAD_TLD)}/login")
            elif kind < 0.5:
                urls.append(f"http://{token}.{rnd.choice(['secure', 'verify', 'login'])}-{rnd.choice(WORDS)}.{rnd.choice(BAD_TLD)}/account/update")
            elif kind < 0.65:
                ip = ".".join(str(rnd.randint(11, 220)) for _ in range(4))
                urls.append(f"http://{ip}/{token}/verify/login.php")
            elif kind < 0.8:
                urls.append(f"https://{token}.com.{rnd.choice(WORDS)}-{rnd.choice(WORDS)}.{rnd.choice(BAD_TLD)}/clave/validar?id={rnd.randint(1000, 9999)}")
            elif kind < 0.9:
                urls.append(f"https://{rnd.choice(['bit.ly', 'tinyurl.com', 'cutt.ly'])}/{rnd.choice(WORDS)}{rnd.randint(10, 99)}")
            else:
                urls.append(f"https://{rnd.choice(WORDS)}.{rnd.choice(WORDS)}.{rnd.choice(WORDS)}.{rnd.choice(WORDS)}-{rnd.choice(WORDS)}.{rnd.choice(BAD_TLD)}/signin/confirm/account")
            labels.append(1)
    return urls, labels


def _load_csv(path, url_col, label_col, legit_label):
    import csv
    urls, labels = [], []
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.DictReader(f):
            urls.append(row[url_col])
            labels.append(0 if str(row[label_col]).strip() == str(legit_label) else 1)
    return urls, labels


def _metrics(y, proba, thr=0.5):
    pred = (proba >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y, pred), "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred), "f1": f1_score(y, pred), "specificity": tn / max(1, tn + fp),
        "roc_auc": roc_auc_score(y, proba), "pr_auc": average_precision_score(y, proba),
        "fpr": fp / max(1, fp + tn), "fnr": fn / max(1, fn + tp),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def train(urls, labels, dataset_name, out_dir=None) -> dict:
    out_dir = out_dir or settings.model_dir
    os.makedirs(out_dir, exist_ok=True)
    X, y, groups = [], [], []
    seen = set()
    for u, l in zip(urls, labels):
        if u in seen:
            continue  # deduplicado
        try:
            p = normalize_url(u)
            X.append(feature_vector(features_from_url(u)))
        except (InvalidUrl, BlockedTarget):
            continue
        seen.add(u)
        y.append(l)
        groups.append(registrable_domain(p["host"]))
    X, y, groups = np.array(X), np.array(y), np.array(groups)
    # separación por dominio para evitar fuga entre entrenamiento y prueba
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    tr_idx, te_idx = next(gss.split(X, y, groups))
    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=1)
    t_idx, v_idx = next(gss2.split(X[tr_idx], y[tr_idx], groups[tr_idx]))
    t_idx, v_idx = tr_idx[t_idx], tr_idx[v_idx]
    candidates = {
        "logistic_regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000)),
        "random_forest": RandomForestClassifier(n_estimators=120, random_state=42, n_jobs=-1),
        "gradient_boosting": GradientBoostingClassifier(random_state=42),
    }
    results, best_name, best_pr = {}, None, -1
    for name, model in candidates.items():
        model.fit(X[t_idx], y[t_idx])
        pv = model.predict_proba(X[v_idx])[:, 1]
        pr = average_precision_score(y[v_idx], pv)
        results[name] = {"validation_pr_auc": pr}
        if pr > best_pr:
            best_name, best_pr = name, pr
    best = candidates[best_name]
    best.fit(X[tr_idx], y[tr_idx])  # reentrena con train+val
    t0 = time.perf_counter()
    proba = best.predict_proba(X[te_idx])[:, 1]
    infer_ms = (time.perf_counter() - t0) / max(1, len(te_idx)) * 1000
    test = _metrics(y[te_idx], proba)
    version = f"{best_name}-{datetime.now(timezone.utc):%Y%m%d%H%M}"
    meta = {
        "version": version, "algorithm": best_name, "dataset": dataset_name,
        "n_samples": int(len(y)), "class_balance": {"legit": int((y == 0).sum()), "phishing": int((y == 1).sum())},
        "split": "GroupShuffleSplit por dominio (train/val/test)", "features": __import__("app.services.url_features", fromlist=["x"]).FEATURE_ORDER,
        "candidates": results, "test_metrics": test, "inference_ms_per_url": infer_ms,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "warning": "DATASET SINTÉTICO DE DEMOSTRACIÓN: las métricas no son representativas." if dataset_name.startswith("synthetic") else "",
    }
    joblib.dump(best, os.path.join(out_dir, "model.joblib"))
    with open(os.path.join(out_dir, "metrics.json"), "w") as f:
        json.dump(meta, f, indent=2, default=float)
    return meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv")
    ap.add_argument("--url-col", default="URL")
    ap.add_argument("--label-col", default="label")
    ap.add_argument("--legit-label", default="1", help="valor de la etiqueta que significa legítima (verifica en la ficha del dataset)")
    ap.add_argument("--n", type=int, default=6000)
    a = ap.parse_args()
    if a.csv:
        urls, labels = _load_csv(a.csv, a.url_col, a.label_col, a.legit_label)
        name = os.path.basename(a.csv)
    else:
        urls, labels = _synth(a.n)
        name = "synthetic-demo"
    meta = train(urls, labels, name)
    print(json.dumps({k: meta[k] for k in ("version", "dataset", "n_samples", "test_metrics")}, indent=2, default=float))


if __name__ == "__main__":
    main()
