from typing import Optional, List
from sqlalchemy import  ForeignKey
from sqlalchemy.ext.asyncio import  create_async_engine, async_sessionmaker
from sqlalchemy import String 
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, declared_attr, relationship
import uuid
# объект для подключения ядро базы данных
engine = create_async_engine(url="sqlite+aiosqlite:///app/BD.db", echo=True)

class Base(DeclarativeBase):
    __abstract__ = True
    
    @declared_attr.directive
    def __tablename__(cls) -> str:
        return f"{cls.__name__.lower()}s"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    
# создаем модель таблицы связей таблиц users и devices
session_factory = async_sessionmaker(bind=engine)

async def create_table(engine):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    
# определяем модели классов для пользователя и устройства
class User(Base):
      
    uuid: Mapped[str] = mapped_column(String,unique=True, default = str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String, unique=True)
    name: Mapped[str] = mapped_column(String)
    password: Mapped[str] = mapped_column(String)
    token: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    devices: Mapped[List["Device"]] = relationship("Device", back_populates="user")

class Device(Base):
    
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    state: Mapped[str] = mapped_column(String)
    user: Mapped["User"] = relationship("User", back_populates="devices")
