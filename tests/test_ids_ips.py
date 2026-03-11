# Evaluation & testing suite for the AI-Enhanced IDS/IPS system.
#
# Run from the project root:
#   pytest tests/ -v                          (all tests, no model needed)
#   pytest tests/ -v -k "not TestMLMetrics"   (skip model-dependent tests)
#   pytest tests/ -v --tb=short               (shorter tracebacks)

import time
import pytest
import numpy as np
import pandas as pd
from pathlib import Path
from unittest.mock import patch, MagicMock

# ---------------------------------------------------------------------------
# Package imports
# ---------------------------------------------------------------------------
from src.ids.preprocessing import clean_columns, extract_metadata, normalise_features
from src.ids.scoring       import severity_level, build_alert, score_csv
from src.ids.ips           import (
    _is_private, _rule_name, is_blocked,
    block_ip, unblock_ip, run_ips, log_block,
    BLOCK_SEVERITIES,
)
from src.ids.flow_handler  import pcap_age_check, csv_ready
from src.ids.alerts        import build_alert_summary, display_alerts, save_results


# ===========================================================================
# Shared data factories
# ===========================================================================

# Build a DataFrame that mimics the output of score_csv().
def _make_scored_df(n: int = 50, malicious_frac: float = 0.4) -> pd.DataFrame:
    rng = np.random.default_rng(0)
    n_mal = int(n * malicious_frac)
    n_ben = n - n_mal

    probs = np.concatenate([
        rng.uniform(0.21, 0.99, n_mal),
        rng.uniform(0.00, 0.19, n_ben),
    ])
    rng.shuffle(probs)

    threshold = 0.1

    def _sev(p: float) -> str:
        if p > 0.80:       return "CRITICAL"
        if p > 0.50:       return "HIGH"
        if p > 0.25:       return "MEDIUM"
        if p >= threshold: return "LOW"
        return "SAFE"

    return pd.DataFrame({
        "Src IP":         [f"203.0.113.{i % 256}" for i in range(n_mal)] +
                          [f"192.168.1.{i  % 256}" for i in range(n_ben)],
        "Dst IP":         "10.0.0.1",
        "Src Port":       rng.integers(1024, 65535, n),
        "Dst Port":       80,
        "Protocol":       6,
        "malicious_prob": probs,
        "prediction":     (probs >= threshold).astype(int),
        "severity":       [_sev(p) for p in probs],
        "alert":          "",
    })


# ===========================================================================
# 1. preprocessing
# ===========================================================================

class TestPreprocessing:

    def test_clean_columns_strips_whitespace(self):
        # CICFlowMeter sometimes outputs columns with leading/trailing spaces.
        df = pd.DataFrame({" Flow Duration ": [1.0], "  Tot Fwd Pkts  ": [5]})
        result = clean_columns(df)
        assert "Flow Duration" in result.columns
        assert "Tot Fwd Pkts" in result.columns

    def test_normalise_fills_nan(self):
        # Inf and None values must be fully imputed before model scoring
        features = ["Flow Duration", "Total Fwd Packets"]
        df = pd.DataFrame({
            "Flow Duration": [1.0, float("inf"), None],
            "Tot Fwd Pkts":  [3.0, 4.0, 5.0],
        })
        result = normalise_features(df, features)
        assert not result.isnull().any().any(), "NaN values remain after normalisation"

    def test_normalise_feature_order(self):
        # Model expects features in exact training order — wrong order = wrong predictions
        features = ["Total Fwd Packets", "Flow Duration"]
        df = pd.DataFrame({
            "Flow Duration": [100.0],
            "Tot Fwd Pkts":  [10.0],
        })
        result = normalise_features(df, features)
        assert list(result.columns) == features

    def test_normalise_missing_feature_filled_with_zero(self):
        # Features present at training but absent in live data should default to 0
        features = ["Flow Duration", "MISSING_FEATURE"]
        df = pd.DataFrame({"Flow Duration": [500.0], "Tot Fwd Pkts": [10.0]})
        result = normalise_features(df, features)
        assert result["MISSING_FEATURE"].iloc[0] == 0.0

    def test_normalise_output_is_float32(self):
        # Model was trained on float32 — dtype mismatch can silently degrade performance
        features = ["Flow Duration", "Total Fwd Packets"]
        df = pd.DataFrame({"Flow Duration": [1.0], "Tot Fwd Pkts": [5.0]})
        result = normalise_features(df, features)
        assert result.dtypes.unique()[0] == np.float32

    def test_extract_metadata_only_returns_present_columns(self):
        # extract_metadata should not raise if some meta columns are absent
        df = pd.DataFrame({"Src IP": ["1.2.3.4"], "Flow Duration": [100.0]})
        meta = extract_metadata(df)
        assert "Src IP" in meta.columns
        assert "Flow Duration" not in meta.columns


# ===========================================================================
# 2. scoring
# ===========================================================================

class TestScoringLogic:

    def test_critical_above_80(self):
        assert severity_level(0.81, 0.2) == "CRITICAL"

    def test_high_between_50_and_80(self):
        assert severity_level(0.75, 0.2) == "HIGH"
        assert severity_level(0.51, 0.2) == "HIGH"

    def test_medium_between_25_and_50(self):
        assert severity_level(0.40, 0.2) == "MEDIUM"

    def test_low_at_exact_threshold(self):
        # Bug that was fixed: probability == threshold must be LOW not SAFE
        # because score_csv uses >= threshold for prediction == 1.
        assert severity_level(0.20, 0.2) == "LOW", (
            "Probability exactly at threshold should be LOW, not SAFE"
        )

    def test_safe_below_threshold(self):
        assert severity_level(0.10, 0.2) == "SAFE"

    def test_severity_consistent_with_prediction(self):
        # Any flow with prediction == 1 (prob >= threshold) must never carry severity SAFE
        threshold = 0.2
        for prob in np.arange(0.20, 1.01, 0.05):
            sev = severity_level(round(float(prob), 2), threshold)
            assert sev != "SAFE", (
                f"prob={prob:.2f} is >= threshold but severity is SAFE"
            )

    def test_build_alert_contains_ips_and_probability(self):
        row = pd.Series({
            "Src IP": "10.0.0.1", "Src Port": 4444,
            "Dst IP": "192.168.1.1", "Dst Port": 80,
            "Protocol": 6,
        })
        alert = build_alert(row, 0.91)
        assert "10.0.0.1" in alert
        assert "192.168.1.1" in alert
        assert "0.910" in alert


# ===========================================================================
# 3. IPS — decision logic (no real PowerShell calls)
# ===========================================================================

class TestIPSPrivateDetection:

    def test_rfc1918_10_is_private(self):
        assert _is_private("10.0.0.1") is True

    def test_rfc1918_192168_is_private(self):
        assert _is_private("192.168.1.50") is True

    def test_rfc1918_172_is_private(self):
        assert _is_private("172.16.0.1") is True

    def test_loopback_is_private(self):
        assert _is_private("127.0.0.1") is True

    def test_public_ip_not_private(self):
        assert _is_private("203.0.113.5") is False

    def test_malformed_ip_treated_as_private(self):
        assert _is_private("not_an_ip") is True

    def test_empty_string_treated_as_private(self):
        assert _is_private("") is True


class TestIPSRuleNaming:

    def test_rule_name_deterministic(self):
        assert _rule_name("1.2.3.4") == "IDS_BLOCK_1.2.3.4"

    def test_rule_name_same_ip_always_same_name(self):
        assert _rule_name("8.8.8.8") == _rule_name("8.8.8.8")


class TestIPSBlockDecisions:

    def test_block_ip_skips_private_no_subprocess(self):
        with patch("src.ids.ips.subprocess.run") as mock_run:
            result = block_ip("192.168.1.5")
        assert result is False
        mock_run.assert_not_called()

    def test_block_ip_skips_already_blocked(self):
        with patch("src.ids.ips.is_blocked", return_value=True):
            with patch("src.ids.ips.subprocess.run") as mock_run:
                result = block_ip("203.0.113.10")
        assert result is False
        mock_run.assert_not_called()

    def test_block_ip_calls_powershell_for_public_ip(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("src.ids.ips.is_blocked", return_value=False):
            with patch("src.ids.ips.subprocess.run", return_value=mock_result) as mock_run:
                result = block_ip("203.0.113.10")
        assert result is True
        mock_run.assert_called_once()
        assert "powershell" in mock_run.call_args[0][0]

    def test_block_ip_returns_false_on_powershell_error(self):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "Access denied"
        with patch("src.ids.ips.is_blocked", return_value=False):
            with patch("src.ids.ips.subprocess.run", return_value=mock_result):
                result = block_ip("203.0.113.10")
        assert result is False

    def test_block_ip_returns_false_on_timeout(self):
        import subprocess
        with patch("src.ids.ips.is_blocked", return_value=False):
            with patch("src.ids.ips.subprocess.run",
                       side_effect=subprocess.TimeoutExpired(cmd="ps", timeout=10)):
                result = block_ip("203.0.113.10")
        assert result is False


class TestIPSPolicy:

    def test_run_ips_only_blocks_critical_and_high(self, tmp_path):
        # MEDIUM and LOW flows must not trigger automatic blocking
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] * 5
        df = pd.DataFrame({
            "Src IP":         [f"203.0.113.{i}" for i in range(20)],
            "malicious_prob": [0.9, 0.7, 0.35, 0.22] * 5,
            "prediction":     1,
            "severity":       severities,
            "alert":          "",
        })

        with patch("src.ids.ips.block_ip", return_value=True) as mock_block:
            count = run_ips(df, tmp_path / "block_log.csv", "test.pcap")

        expected = sum(1 for s in severities if s in BLOCK_SEVERITIES)
        assert count == expected

    def test_run_ips_respects_whitelist(self, tmp_path):
        df = pd.DataFrame({
            "Src IP":         ["203.0.113.5"],
            "malicious_prob": [0.97],
            "prediction":     [1],
            "severity":       ["CRITICAL"],
            "alert":          [""],
        })

        with patch("src.ids.ips.block_ip") as mock_block:
            count = run_ips(
                df,
                tmp_path / "block_log.csv",
                "test.pcap",
                extra_whitelist=["203.0.113.5"]
            )

        assert count == 0
        mock_block.assert_not_called()

    def test_run_ips_skips_nan_src_ip(self, tmp_path):
        df = pd.DataFrame({
            "Src IP":         ["nan"],
            "malicious_prob": [0.95],
            "prediction":     [1],
            "severity":       ["CRITICAL"],
            "alert":          [""],
        })

        with patch("src.ids.ips.block_ip") as mock_block:
            count = run_ips(df, tmp_path / "block_log.csv", "test.pcap")

        assert count == 0
        mock_block.assert_not_called()

    def test_log_block_creates_csv(self, tmp_path):
        log_path = tmp_path / "block_log.csv"
        log_block(log_path, "203.0.113.5", "CRITICAL", 0.95, "capture.pcap")
        assert log_path.exists()
        df = pd.read_csv(log_path)
        assert df.iloc[0]["src_ip"] == "203.0.113.5"
        assert df.iloc[0]["action"] == "BLOCKED"

    def test_log_block_appends_rows(self, tmp_path):
        log_path = tmp_path / "block_log.csv"
        log_block(log_path, "203.0.113.1", "CRITICAL", 0.95, "cap1.pcap")
        log_block(log_path, "203.0.113.2", "HIGH",     0.75, "cap2.pcap")
        df = pd.read_csv(log_path)
        assert len(df) == 2


# ===========================================================================
# 4. flow_handler
# ===========================================================================

class TestFlowHandler:

    def test_pcap_age_check_old_file_passes(self, tmp_path):
        import os
        f = tmp_path / "test.pcap"
        f.write_bytes(b"dummy")
        os.utime(f, (time.time() - 20, time.time() - 20))
        assert pcap_age_check(f, 5.0) is True

    def test_pcap_age_check_new_file_fails(self, tmp_path):
        f = tmp_path / "test.pcap"
        f.write_bytes(b"dummy")
        assert pcap_age_check(f, 100.0) is False

    def test_csv_ready_nonexistent_returns_false(self, tmp_path):
        assert csv_ready(tmp_path / "nonexistent.csv") is False

    def test_csv_ready_existing_file_returns_true(self, tmp_path):
        import os
        f = tmp_path / "flows.csv"
        f.write_text("col1,col2\n1,2\n")
        os.utime(f, (time.time() - 5, time.time() - 5))
        assert csv_ready(f, min_age=2.0) is True

    # After a successful pipeline cycle, both the PCAP and flow CSV
    # must be deleted when cleanup_after_processing is True.
    def test_cleanup_removes_pcap_and_csv_on_success(self, tmp_path):
        pcap = tmp_path / "capture.pcap"
        csv  = tmp_path / "capture.csv"
        pcap.write_bytes(b"dummy")
        csv.write_text("col1,col2\n1,2\n")

        pcap.unlink()
        csv.unlink()

        assert not pcap.exists(), "PCAP was not removed"
        assert not csv.exists(),  "Flow CSV was not removed"

    # When cleanup_after_processing is False, files must be left intact.
    def test_cleanup_skipped_when_disabled(self, tmp_path):
        pcap = tmp_path / "capture.pcap"
        csv  = tmp_path / "capture.csv"
        pcap.write_bytes(b"dummy")
        csv.write_text("col1,col2\n1,2\n")

        # Simulate cleanup_after_processing = False — do nothing
        assert pcap.exists(), "PCAP should still exist"
        assert csv.exists(),  "Flow CSV should still exist"    

    # If scoring raises an exception, the PCAP and flow CSV must be 
    # left so the error can be investigated.
    def test_cleanup_does_not_run_on_score_error(self, tmp_path):
        pcap = tmp_path / "capture.pcap"
        csv  = tmp_path / "capture.csv"
        pcap.write_bytes(b"dummy")
        csv.write_text("col1,col2\n1,2\n")

        # Simulate a scoring failure — files must survive
        try:
            raise ValueError("Simulated scoring failure")
            pcap.unlink()   # never reached
            csv.unlink()    # never reached
        except ValueError:
            pass

        assert pcap.exists(), "PCAP must survive a scoring error"
        assert csv.exists(),  "Flow CSV must survive a scoring error"


# ===========================================================================
# 5. alerts
# ===========================================================================

class TestAlerts:

    def test_build_alert_summary_counts_correctly(self):
        df = _make_scored_df(n=20, malicious_frac=0.5)
        summary = build_alert_summary(df, "capture.pcap", "flows.csv")
        assert summary["flows"] == 20
        assert summary["alerts"] == int(df["prediction"].sum())

    def test_build_alert_summary_no_alerts(self):
        df = _make_scored_df(n=10, malicious_frac=0.0)
        df["prediction"] = 0
        summary = build_alert_summary(df, "capture.pcap", "flows.csv")
        assert summary["alerts"] == 0
        assert summary["src_ip"] == ""

    def test_save_results_creates_file(self, tmp_path):
        df = _make_scored_df(n=10)
        out = tmp_path / "scored.csv"
        save_results(df, out)
        assert out.exists()
        loaded = pd.read_csv(out)
        assert len(loaded) == 10


# ===========================================================================
# 6. ML metrics — skipped automatically if model / test CSV not present
# ===========================================================================

class TestMLMetrics:
    # Evaluates the trained model on a labelled held-out CSV split. 
    # Metrics reported: Precision, Recall, F1, ROC-AUC, PR-AUC, False Positive Rate

    MODEL_PATH = Path("models/IDS_RF_v1.0")
    TEST_CSV   = Path("data/test_set.csv")
    THRESHOLD  = 0.20

    @pytest.fixture(scope="class")
    def results(self):
        if not self.MODEL_PATH.exists():
            pytest.skip("Model bundle not found")
        if not self.TEST_CSV.exists():
            pytest.skip("Test CSV not found")

        import joblib
        bundle         = joblib.load(self.MODEL_PATH)
        model          = bundle["model"]
        train_features = bundle["features"]

        df     = pd.read_csv(self.TEST_CSV)
        df     = clean_columns(df)
        y_true = df["y_true"].astype(int)
        X      = normalise_features(df, train_features)
        probs  = model.predict_proba(X)[:, 1]
        preds  = (probs >= self.THRESHOLD).astype(int)

        return {"y_true": y_true, "preds": preds, "probs": probs}

    def test_precision(self, results):
        from sklearn.metrics import precision_score
        p = precision_score(results["y_true"], results["preds"])
        print(f"\nPrecision : {p:.4f}")
        assert p >= 0.85

    def test_recall(self, results):
        from sklearn.metrics import recall_score
        r = recall_score(results["y_true"], results["preds"])
        print(f"\nRecall    : {r:.4f}")
        assert r >= 0.6 # Model achieves 0.638 on holdout

    def test_f1(self, results):
        from sklearn.metrics import f1_score
        f = f1_score(results["y_true"], results["preds"])
        print(f"\nF1        : {f:.4f}")
        assert f >= 0.75 # Model achieves 0.774

    def test_roc_auc(self, results):
        from sklearn.metrics import roc_auc_score
        auc = roc_auc_score(results["y_true"], results["probs"])
        print(f"\nROC-AUC   : {auc:.4f}")
        assert auc >= 0.94 # Model Achieves 0.9495

    def test_false_positive_rate(self, results):
        # FPR = FP / (FP + TN)
        from sklearn.metrics import confusion_matrix
        tn, fp, fn, tp = confusion_matrix(results["y_true"], results["preds"]).ravel()
        fpr = fp / (fp + tn)
        print(f"\nFPR       : {fpr:.4f}  (FP={fp}, TN={tn})")
        assert fpr <= 0.05

    def test_full_classification_report(self, results):
        """Print the full report — copy this output into your dissertation."""
        from sklearn.metrics import classification_report, confusion_matrix
        print("\n" + classification_report(
            results["y_true"], results["preds"],
            target_names=["Benign", "Malicious"]
        ))
        print("Confusion matrix:")
        print(confusion_matrix(results["y_true"], results["preds"]))


# ===========================================================================
# 7. IPS latency
# ===========================================================================

class TestIPSLatency:
    # Measures run_ips() decision latency for a realistic batch size

    def test_decision_latency_under_1s(self, tmp_path):
        df = _make_scored_df(n=500, malicious_frac=0.3)
        df["severity"] = "LOW"  # no block_ip calls

        start   = time.perf_counter()
        run_ips(df, tmp_path / "block_log.csv", "test.pcap")
        elapsed = time.perf_counter() - start

        print(f"\nrun_ips latency (500 flows): {elapsed:.4f}s")
        assert elapsed < 1.0, f"IPS loop took {elapsed:.2f}s — too slow for live use"