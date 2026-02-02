from datetime import datetime
from typing import cast

from config import get_jwt_auth_manager
from database import RefreshTokenModel
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from src.schemas.accounts import PasswordResetRequestSchema, UserLoginRequestSchema, RefreshTokenRequestSchema, \
    PasswordResetCompleteRequestSchema
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload
from src.schemas.accounts import UserActivationRequestSchema


from src.database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,

)
from src.schemas.accounts import (
    UserRegistrationRequestSchema,
    UserResponseSchema,
)

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):

    result = await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    result = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    user_group = result.scalar_one()

    user = UserModel(
        email=user_data.email,
        group_id=cast(int, user_group.id),
    )

    try:
        user.password = user_data.password
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    try:
        db.add(user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=cast(int, user.id))
        db.add(activation_token)

        await db.commit()

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return UserResponseSchema(
        id=user.id,
        email=user.email,
    )


@router.post("/activate/")
async def activate_user(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserModel)
        .where(UserModel.email == data.email)
        .options(joinedload(UserModel.activation_token))
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    token = user.activation_token

    if (
        not token
        or token.token != data.token
        or token.expires_at < datetime.utcnow()
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True
    await db.delete(token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/")
async def request_password_reset(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        result = await db.execute(
            select(UserModel).where(UserModel.email == data.email)
        )
        user = result.scalar_one_or_none()

        if user and user.is_active:

            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )

            reset_token = PasswordResetTokenModel(user_id=user.id)
            db.add(reset_token)
            await db.commit()

        return {
            "message": "If you are registered, you will receive an email with instructions."
        }

    except SQLAlchemyError:
        await db.rollback()
        return {
            "message": "If you are registered, you will receive an email with instructions."
        }


@router.post("/reset-password/complete/")
async def reset_password_complete(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        result = await db.execute(
            select(UserModel).where(UserModel.email == data.email)
        )
        user = result.scalar_one_or_none()

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        result = await db.execute(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        reset_token = result.scalar_one_or_none()

        if not reset_token or reset_token.token != data.token:
            if reset_token:
                await db.delete(reset_token)
                await db.commit()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        if reset_token.expires_at < datetime.utcnow():
            await db.delete(reset_token)
            await db.commit()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        user.password = data.password

        await db.delete(reset_token)
        await db.commit()

        return {"message": "Password reset successfully."}

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/login/",
    status_code=status.HTTP_201_CREATED,
)
async def login_user(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        result = await db.execute(
            select(UserModel).where(UserModel.email == data.email)
        )
        user = result.scalar_one_or_none()

        if not user or not user.verify_password(data.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated.",
            )

        payload = {
            "sub": str(user.id),
            "user_id": user.id,
        }

        access_token = jwt_manager.create_access_token(payload)
        refresh_token = jwt_manager.create_refresh_token(payload)

        await db.execute(
            delete(RefreshTokenModel).where(
                RefreshTokenModel.user_id == user.id
            )
        )

        db.add(
            RefreshTokenModel(
                user_id=user.id,
                token=refresh_token,
            )
        )

        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post("/refresh/")
async def refresh_access_token(
    data: RefreshTokenRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:

        try:
            payload = jwt_manager.decode_refresh_token(data.refresh_token)
        except BaseSecurityError as exc:
            if "expired" in str(exc).lower():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Token has expired.",
                )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token.",
            )

        user_id = payload.get("user_id") or payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token.",
            )

        result = await db.execute(
            select(RefreshTokenModel).where(
                RefreshTokenModel.token == data.refresh_token
            )
        )
        refresh_token_obj = result.scalar_one_or_none()

        if not refresh_token_obj:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found.",
            )

        result = await db.execute(
            select(UserModel).where(UserModel.id == int(user_id))
        )
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )

        access_payload = {
            "sub": str(user.id),
            "user_id": user.id,
        }
        new_access_token = jwt_manager.create_access_token(access_payload)

        return {
            "access_token": new_access_token,
            "token_type": "bearer",
        }

    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not refresh access token.",
        )
