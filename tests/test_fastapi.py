from api.main import app


def test_fastapi_app():
    assert app is not None
