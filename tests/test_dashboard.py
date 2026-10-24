import io
import json
from unittest.mock import patch
import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest
from sentinel.config import ROOT


def app():
    return AppTest.from_file(str(ROOT / "app.py")).run(timeout=60)


def selector(page, label):
    return next(x for x in page.selectbox if x.label == label)


def test_default_and_all_mandatory_scenarios():
    page = app()
    assert not page.exception
    assert next(x.value for x in page.metric if x.label == "Flows analysed") == "2,880"
    assert isinstance(json.loads(page.json[0].value)["needs_review"], bool)
    for scenario in ["benign", "port_scan", "dos", "brute_force", "ambiguous"]:
        selector(page, "Scenario").select(scenario).run(timeout=60)
        assert not page.exception
        counts = next(
            x.value
            for x in page.dataframe
            if list(x.value.columns) == ["actual", "predicted"]
        )
        if scenario != "ambiguous":
            assert counts.actual.sum() == 720
        else:
            assert counts.actual.sum() > 0


@pytest.mark.parametrize("auth_present", [True, False])
def test_minimal_upload_with_optional_auth(minimal, auth_present):
    if not auth_present:
        minimal = minimal.drop(columns="failed_logins")
    with patch("streamlit.radio", return_value="Upload flow CSV"), patch(
        "streamlit.file_uploader", return_value=io.StringIO(minimal.to_csv(index=False))
    ):
        page = app()
    assert not page.exception and not page.error
    assert any("Ground truth is unavailable" in item.value for item in page.info)


def test_invalid_and_empty_uploads(minimal):
    for frame in [minimal.assign(packets=-1), minimal.iloc[:0]]:
        with patch("streamlit.radio", return_value="Upload flow CSV"), patch(
            "streamlit.file_uploader",
            return_value=io.StringIO(frame.to_csv(index=False)),
        ):
            page = app()
        assert not page.exception and page.error
