import json
import pytest
from lowtide.ops import Engagement
from lowtide.store import Store

SCOPE = {"engagement": "T", "window": {"start": "2020-01-01T00:00:00Z", "end": "2099-01-01T00:00:00Z"},
         "in_scope": {"hosts": ["*.lab.example", "10.99.0.0/16", "127.0.0.1"]}, "out_of_scope": ["bad.lab.example", "10.99.250.0/24"],
         "forbidden_actions": ["denial-of-service"], "roles": {"control_team": ["pat"]}, "tripwires": ["external_party"]}


@pytest.fixture
def home(tmp_path):
    return tmp_path / ".lt"


@pytest.fixture
def mk(home):
    def make(op="alice", cfg=None, scope=None):
        st = Store(home)
        if not st.exists():
            st.init("T", "client", op)
            st.scope_path.write_text(json.dumps(scope or SCOPE))
            if cfg:
                c = json.loads(st.config_path.read_text()); c.update(cfg); st.config_path.write_text(json.dumps(c))
        return Engagement(st, op)
    return make


@pytest.fixture
def eng(mk):
    return mk()
