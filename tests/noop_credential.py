from typing import Optional, Any

from azure.core.credentials import TokenCredential, AccessToken


class NoopCredential(TokenCredential):

    def get_token(
            self, *scopes: str, claims: Optional[str] = None, tenant_id: Optional[str] = None, **kwargs: Any
    ) -> AccessToken:
        return AccessToken(token="Dummy", expires_on=2 ^ 30)
