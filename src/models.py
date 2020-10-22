'''OIDC server example'''

import time
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2TokenMixin,
    OAuth2AuthorizationCodeMixin
)
from src.database import Base


class User(Base):  # pylint: disable=R0903
    '''User class example'''

    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(100), unique=True)

    def get_user_id(self):
        '''Fetch user identifier'''
        return self.id


class OAuth2Client(Base, OAuth2ClientMixin):
    '''OAuth2Client class example'''

    __tablename__ = 'oauth2_client'

    id = Column(Integer, primary_key=True)


class OAuth2AuthorizationCode(Base, OAuth2AuthorizationCodeMixin):
    '''OAuth2AuthorizationCode class example'''

    __tablename__ = 'oauth2_code'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'))
    user = relationship('User')

    def is_expired(self):
        return self.auth_time + 300 < time.time()


class OAuth2Token(Base, OAuth2TokenMixin):
    '''OAuth2Token class example'''

    __tablename__ = 'oauth2_token'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'))
    user = relationship('User')

    def is_refresh_token_active(self):
        '''Check if refresh token is active'''
        if self.revoked:
            return False
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at >= time.time()
