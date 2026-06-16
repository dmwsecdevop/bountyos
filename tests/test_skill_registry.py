import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api.services.skill_registry import all_skills, get_skill, approval_required_skills

def test_skills_exist_and_sqlmap_requires_approval():
    names={s['name'] for s in all_skills()}
    assert {'subfinder','sqlmap','nmap','debate_engine','apktool'} <= names
    assert get_skill('sqlmap')['requires_approval'] is True
    assert get_skill('nmap')['risk_level'] == 'high'
    assert any(s['name']=='adb' for s in approval_required_skills())
