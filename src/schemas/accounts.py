from pydantic import BaseModel, EmailStr, Field


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserResponseSchema(BaseModel):
    id: int
    email: EmailStr


class UserRegistrationResponseSchema(UserResponseSchema):
    pass


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class RefreshTokenRequestSchema(BaseModel):
    refresh_token: str = Field(..., min_length=1)


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str = Field(..., min_length=1)
    password: str


class MessageResponseSchema(BaseModel):
    message: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str = Field(..., min_length=1)


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
