from app.enrichment.cache import IOC_Cache
from app.enrichment.virustotal import VirusTotalEnricher


def test_cache_save_and_read(tmp_path):
    cache = IOC_Cache(str(tmp_path / "cache.json"))

    result = {
        "ioc": "192.0.2.10",
        "status": "ANALYZED",
        "malicious": 2,
    }

    cache.set("192.0.2.10", result)

    assert cache.get("192.0.2.10") == result


def test_offline_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "")

    cache = IOC_Cache(str(tmp_path / "cache.json"))
    enricher = VirusTotalEnricher(api_key="", cache=cache)

    result = enricher.enrich("192.0.2.10")

    assert result["status"] == "OFFLINE"
    assert result["ioc"] == "192.0.2.10"
    assert result["cached"] is False


def test_cached_result_is_reused(tmp_path):
    cache = IOC_Cache(str(tmp_path / "cache.json"))

    cache.set(
        "192.0.2.10",
        {
            "ioc": "192.0.2.10",
            "status": "ANALYZED",
            "malicious": 2,
            "suspicious": 0,
            "harmless": 5,
            "undetected": 10,
            "cached": False,
        },
    )

    enricher = VirusTotalEnricher(api_key="test-key", cache=cache)
    result = enricher.enrich("192.0.2.10")

    assert result["status"] == "ANALYZED"
    assert result["malicious"] == 2
    assert result["cached"] is True
