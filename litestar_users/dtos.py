from litestar.dto import DataclassDTO

from litestar_users.schema import OAuth2AuthorizeSchema


class OAuthAuthorizeDTO(DataclassDTO[OAuth2AuthorizeSchema]):
    """OAuth authorize DTO."""
