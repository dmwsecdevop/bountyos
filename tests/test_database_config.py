import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api.database import normalize_database_url

def test_database_url_normalization():
    assert normalize_database_url('sqlite:///./bountyos.db') == 'sqlite:///./bountyos.db'
    assert normalize_database_url('postgresql://u:p@h:5432/db').startswith('postgresql+psycopg://')
    assert normalize_database_url('postgresql+psycopg://u:p@h/db') == 'postgresql+psycopg://u:p@h/db'

def test_cloud_sql_socket_detection_shape():
    url=normalize_database_url('postgresql://u:secret@/bountyos?host=/cloudsql/p:r:i')
    assert 'postgresql+psycopg://' in url
    assert '/cloudsql/' in url
