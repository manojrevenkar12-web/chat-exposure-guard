from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text

from ..db import Base


class Character(Base):
    __tablename__ = "characters"

    id = Column(Integer, primary_key=True)
    creator_id = Column(ForeignKey("users.id"), nullable=False)
    name = Column(String(80), nullable=False)
    description = Column(Text, nullable=False)  # written by the creator in the character editor
    greeting = Column(Text, default="")
    is_community = Column(Boolean, default=True)
