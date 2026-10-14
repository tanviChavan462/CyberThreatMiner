"""
Threat Group Clustering Module.
Supports:
1. K-Means clustering (Euclidean & Jaccard distance).
2. Hierarchical Agglomerative Clustering (Jaccard metric with average/complete linkage).
3. 2D Dimensionality Reduction (PCA) for cluster visualization.
4. Per-cluster frequent itemset mining and dominant kill-chain tactics profiling.
"""
from typing import Dict, List, Any, Optional
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans, AgglomerativeClustering
from sklearn.metrics import silhouette_score, davies_bouldin_score, calinski_harabasz_score
from sklearn.decomposition import PCA
from scipy.spatial.distance import pdist, squareform
from backend.algorithms.apriori import AprioriMiner


def cluster_threat_groups(
    df: pd.DataFrame,
    technique_info: Dict[str, Dict[str, Any]],
    k: int = 4,
    method: str = "kmeans",
    metric: str = "jaccard",
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Clusters threat groups based on their technique profiles.

    Args:
        df: Binary DataFrame (rows: threat groups, columns: techniques).
        technique_info: Metadata dictionary for techniques (names, tactics).
        k: Number of clusters.
        method: 'kmeans' or 'hierarchical'.
        metric: 'jaccard' or 'euclidean'.
        random_state: Random seed.

    Returns:
        Cluster summary with silhouette, Davies-Bouldin, Calinski-Harabasz, 2D PCA coordinates, and cluster profiles.
    """
    X = df.astype(int).values
    n_samples, n_features = X.shape

    if n_samples < 5:
        return {"error": "Insufficient groups for clustering"}

    # Compute clustering quality metric curves across k=2..8
    sil_scores: Dict[int, float] = {}
    db_scores: Dict[int, float] = {}
    ch_scores: Dict[int, float] = {}
    hier_jaccard_sil: Dict[int, float] = {}

    sil_metric = "jaccard" if metric == "jaccard" else "euclidean"
    X_mat = X.astype(bool) if sil_metric == "jaccard" else X

    for candidate_k in range(2, min(9, n_samples)):
        try:
            # K-Means model
            km = KMeans(n_clusters=candidate_k, n_init=10, random_state=random_state)
            km_labels = km.fit_predict(X)

            if len(np.unique(km_labels)) > 1:
                sil_scores[candidate_k] = round(float(silhouette_score(X_mat, km_labels, metric=sil_metric)), 3)
                db_scores[candidate_k] = round(float(davies_bouldin_score(X, km_labels)), 3)
                ch_scores[candidate_k] = round(float(calinski_harabasz_score(X, km_labels)), 1)
            else:
                sil_scores[candidate_k] = 0.0
                db_scores[candidate_k] = 0.0
                ch_scores[candidate_k] = 0.0

            # Hierarchical Agglomerative with Jaccard metric
            hier_model = AgglomerativeClustering(n_clusters=candidate_k, metric="jaccard", linkage="average")
            hier_labels = hier_model.fit_predict(X.astype(bool))
            if len(np.unique(hier_labels)) > 1:
                hier_jaccard_sil[candidate_k] = round(float(silhouette_score(X.astype(bool), hier_labels, metric="jaccard")), 3)
            else:
                hier_jaccard_sil[candidate_k] = 0.0
        except Exception:
            sil_scores[candidate_k] = 0.0
            db_scores[candidate_k] = 0.0
            ch_scores[candidate_k] = 0.0
            hier_jaccard_sil[candidate_k] = 0.0

    best_k = max(sil_scores, key=sil_scores.get) if sil_scores else k

    # Fit requested model
    k_chosen = max(2, min(k, n_samples - 1))
    if method == "hierarchical":
        final_model = AgglomerativeClustering(n_clusters=k_chosen, metric=sil_metric, linkage="average")
        labels = final_model.fit_predict(X)
    else:
        final_model = KMeans(n_clusters=k_chosen, n_init=10, random_state=random_state)
        labels = final_model.fit_predict(X)

    # 2D PCA projection for visualization
    pca = PCA(n_components=2, random_state=random_state)
    coords_2d = pca.fit_transform(X)
    var_explained = [round(float(v) * 100, 1) for v in pca.explained_variance_ratio_]

    # Structure threat group plot points
    group_names = list(df.index)
    pca_points = []
    for i, gname in enumerate(group_names):
        pca_points.append({
            "group": gname,
            "x": round(float(coords_2d[i, 0]), 3),
            "y": round(float(coords_2d[i, 1]), 3),
            "cluster": int(labels[i]),
            "basket_size": int(df.iloc[i].sum())
        })

    # Cluster-specific profiling
    miner = AprioriMiner()
    clusters_data = []

    for c in range(k_chosen):
        group_mask = (labels == c)
        c_groups = [group_names[i] for i, m in enumerate(group_mask) if m]
        c_df = df.iloc[group_mask]

        if len(c_groups) == 0:
            continue

        # Top individual techniques in cluster
        tech_shares = c_df.mean().sort_values(ascending=False).head(8)
        top_techs = []
        dominant_tactics_counter: Dict[str, int] = {}

        for tid, share in tech_shares.items():
            t_name = technique_info.get(tid, {}).get("name", tid)
            top_techs.append({
                "id": tid,
                "label": f"{tid} {t_name}",
                "share": round(float(share), 2)
            })

            for tac in technique_info.get(tid, {}).get("tactics", []):
                dominant_tactics_counter[tac] = dominant_tactics_counter.get(tac, 0) + 1

        top_tactics = sorted(dominant_tactics_counter.items(), key=lambda x: x[1], reverse=True)[:3]

        # Per-cluster frequent itemsets (min_support = 0.5 within cluster)
        c_txs = [set(c_df.columns[c_df.iloc[row_idx] == 1]) for row_idx in range(len(c_df))]
        c_itemsets, _ = miner.mine(c_txs, min_support=0.45, max_len=3)
        c_multi_itemsets = [
            {
                "items": [f"{t} {technique_info.get(t, {}).get('name', t)}" for t in sorted(s)],
                "support": round(sup, 2)
            }
            for s, sup in sorted(c_itemsets.items(), key=lambda x: (-len(x[0]), -x[1]))
            if len(s) >= 2
        ][:5]

        clusters_data.append({
            "cluster": c,
            "cluster_id": c + 1,
            "size": len(c_groups),
            "groups": c_groups[:10],
            "all_groups": c_groups,
            "top_techniques": top_techs,
            "dominant_tactics": [t[0] for t in top_tactics],
            "frequent_itemsets": c_multi_itemsets
        })

    return {
        "method": method,
        "metric": metric,
        "k": k_chosen,
        "silhouette": sil_scores,
        "davies_bouldin": db_scores,
        "calinski_harabasz": ch_scores,
        "hierarchical_jaccard_silhouette": hier_jaccard_sil,
        "quality_metrics": {
            "silhouette": sil_scores,
            "davies_bouldin": db_scores,
            "calinski_harabasz": ch_scores,
            "hierarchical_jaccard": hier_jaccard_sil
        },
        "best_k": best_k,
        "pca_variance_ratio": var_explained,
        "pca_points": pca_points,
        "clusters": clusters_data
    }
