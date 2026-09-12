from pydantic import EmailStr

from ..base import BaseResponseSchema, BaseSchema


class Login(BaseSchema):
    email: EmailStr
    password: str


class Token(BaseSchema):
    access_token: str
    refresh_token: str
    token_type: str


class RefreshToken(BaseSchema):
    refresh_token: str


class Logout(BaseSchema):
    refresh_token: str
