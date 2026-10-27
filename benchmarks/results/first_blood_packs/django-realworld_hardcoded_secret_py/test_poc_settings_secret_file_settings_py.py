"""[secret-file] settings.py 的 PoC 骨架（M45 PoC 合成器）。

规则层判定：hardcoded_secret = True
目标位置：settings.py:1
运行：pytest test_poc_secret_file_settings_py.py -q
"""
import pytest


@pytest.fixture
def client():
    """离线占位：真实环境应替换成 app.test_client() 或 requests.Session。"""
    raise NotImplementedError("请在此接入被测应用的测试客户端")


ATTACKER = "attacker"
VICTIM = "victim"


def test_forged_admin_token_with_hardcoded_secret(client):
    """用代码里的硬编码密钥离线签发管理员 JWT，验证其可被用于伪造身份。"""
    import jwt
    forged = jwt.encode({"sub": "admin", "role": "admin"},
                        '2^f+3@v7$v1f8yt0!s)3-1t$)tlp+xm17=*g))_xoi&&9m#2a&', algorithm="HS256")
    resp = client.get("[secret-file] settings.py", params={"id": "1"}, headers={"Authorization": "Bearer " + forged})
    assert resp.status_code != 200, "硬编码密钥可伪造管理员 Token"
