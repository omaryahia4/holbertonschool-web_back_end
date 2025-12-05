#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound

from user import Base, User


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Saves a user to the database"""
        user = User()
        user.email = email
        user.hashed_password = hashed_password

        session = self._session

        session.add(user)
        session.commit()

        return user

    def find_user_by(self, **kwargs) -> User:
        """
        Returns the first row found in the users table
        as filtered by the arguments kwargs
        """
        session = self._session
        try:
            query = session.query(User).filter_by(**kwargs)
            user = query.first()
            if not user:
                raise NoResultFound
            return query.first()
        except InvalidRequestError:
            raise

    def update_user(self, user_id: int, **kwargs) -> None:
        """Updates the user's attributes"""
        session = self._session
        user = self.find_user_by(id=user_id)

        for k, v in kwargs.items():
            if hasattr(user, k):
                setattr(user, k, v)
            else:
                raise ValueError
        session.add(user)
        session.commit()
        return None
