"""
FEPD Anomaly Clusterer
=======================

Groups similar anomalous events using DBSCAN (density-based) or KMeans.

• DBSCAN is the default — it finds clusters of arbitrary shape and
  automatically labels noise points as cluster -1.
• KMeans is the fallback when DBSCAN produces no meaningful clusters.
• Cluster descriptions are generated from feature centroids.

Usage:
    clusterer = AnomalyClusterer()
    labels = clusterer.cluster(X_anomalies)          # ndarray of ints
    descriptions = clusterer.describe_clusters(X, feature_names, labels)
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

try:
    from sklearn.cluster import DBSCAN, KMeans
    from sklearn.preprocessing import StandardScaler
    _HAS_SKLEARN = True
except ImportError:
    _HAS_SKLEARN = False


class AnomalyClusterer:
    """Cluster anomalous forensic events."""

    def __init__(
        self,
        method: str = "dbscan",
        eps: float = 0.8,
        min_samples: int = 3,
        n_clusters: int = 5,
        max_samples: int = 50_000,
    ):
        """
        Args:
            method: 'dbscan' or 'kmeans'.
            eps: DBSCAN neighbourhood radius.
            min_samples: DBSCAN minimum core-point count.
            n_clusters: Number of clusters for KMeans fallback.
            max_samples: Down-sample if more events than this.
        """
        self._method = method.lower()
        self._eps = eps
        self._min_samples = min_samples
        self._n_clusters = n_clusters
        self._max_samples = max_samples

        self._labels: Optional[np.ndarray] = None
        self._cluster_centres: Optional[np.ndarray] = None

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def cluster(self, X: np.ndarray) -> np.ndarray:
        """
        Cluster the feature matrix *X* and return integer cluster labels.

        Returns:
            ndarray of shape (n_samples,) with cluster IDs.
            -1 means noise (DBSCAN) or unassigned.
        """
        if not _HAS_SKLEARN:
            logger.warning("scikit-learn not installed — all points labelled cluster 0")
            return np.zeros(len(X), dtype=int)

        if len(X) < 3:
            return np.full(len(X), -1, dtype=int)

        # Down-sample if needed
        if len(X) > self._max_samples:
            rng = np.random.default_rng(42)
            idx = rng.choice(len(X), self._max_samples, replace=False)
            X_sub = X[idx]
        else:
            X_sub = X
            idx = None

        # Normalise
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_sub)

        # Replace NaN/Inf that may come from constant columns
        X_scaled = np.nan_to_num(X_scaled, nan=0.0, posinf=0.0, neginf=0.0)

        if self._method == "kmeans":
            labels = self._run_kmeans(X_scaled)
        else:
            labels = self._run_dbscan(X_scaled)
            # If DBSCAN finds only noise, fall back to KMeans
            unique = set(labels)
            if unique == {-1} or len(unique) < 2:
                logger.info("DBSCAN found no meaningful clusters — falling back to KMeans")
                labels = self._run_kmeans(X_scaled)

        # Map back if down-sampled
        if idx is not None:
            full_labels = np.full(len(X), -1, dtype=int)
            full_labels[idx] = labels
            labels = full_labels

        self._labels = labels
        return labels

    # ------------------------------------------------------------------
    # DBSCAN
    # ------------------------------------------------------------------

    def _run_dbscan(self, X: np.ndarray) -> np.ndarray:
        model = DBSCAN(eps=self._eps, min_samples=self._min_samples)
        labels = model.fit_predict(X)
        logger.info(
            "DBSCAN: %d clusters, %d noise points",
            len(set(labels) - {-1}),
            int((labels == -1).sum()),
        )
        return labels

    # ------------------------------------------------------------------
    # KMeans
    # ------------------------------------------------------------------

    def _run_kmeans(self, X: np.ndarray) -> np.ndarray:
        k = min(self._n_clusters, len(X))
        model = KMeans(n_clusters=k, n_init=10, random_state=42)
        labels = model.fit_predict(X)
        self._cluster_centres = model.cluster_centers_
        logger.info("KMeans: %d clusters", k)
        return labels

    # ------------------------------------------------------------------
    # Cluster descriptions
    # ------------------------------------------------------------------

    def describe_clusters(
        self,
        X: np.ndarray,
        feature_names: List[str],
        labels: Optional[np.ndarray] = None,
    ) -> Dict[int, str]:
        """
        Generate a human-readable description for each cluster.

        Returns:
            {cluster_id: "description string"}
        """
        if labels is None:
            labels = self._labels
        if labels is None:
            return {}

        descriptions: Dict[int, str] = {}
        unique_clusters = sorted(set(labels))

        for cid in unique_clusters:
            if cid == -1:
                mask = labels == -1
                descriptions[-1] = f"Noise / unclustered ({int(mask.sum())} events)"
                continue

            mask = labels == cid
            cluster_X = X[mask]
            if len(cluster_X) == 0:
                continue

            centroid = cluster_X.mean(axis=0)
            top_features = self._top_features_from_centroid(centroid, feature_names)
            desc_parts = [f"Cluster {cid} ({int(mask.sum())} events)"]
            for feat, val in top_features[:3]:
                desc_parts.append(f"{feat}={val:.2f}")
            descriptions[cid] = " | ".join(desc_parts)

        return descriptions

    @staticmethod
    def _top_features_from_centroid(
        centroid: np.ndarray, feature_names: List[str], top_n: int = 5
    ) -> List[Tuple[str, float]]:
        """Return the top-N features by absolute centroid value."""
        pairs = list(zip(feature_names, centroid))
        pairs.sort(key=lambda p: abs(p[1]), reverse=True)
        return pairs[:top_n]

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def labels(self) -> Optional[np.ndarray]:
        return self._labels

    @property
    def n_clusters(self) -> int:
        if self._labels is None:
            return 0
        return len(set(self._labels) - {-1})
