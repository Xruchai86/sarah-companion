import os, sys, pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.fake_opn import FakeOpn
from app.store import Store


@pytest.fixture
def fw():
    f = FakeOpn()
    yield f
    f.stop()


@pytest.fixture
def store(tmp_path):
    return Store(str(tmp_path / 'data'))
