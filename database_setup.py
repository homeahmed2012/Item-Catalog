from sqlalchemy import Column, ForeignKey, Integer, String, TIMESTAMP, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)


class Catalog(Base):
    __tablename__ = 'catalog'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)

    @property
    def serialize(self):
        """serialize the catalog"""
        return {
            'id': self.id,
            'title': self.name
        }


class CatalogItem(Base):
    __tablename__ = 'catalog_item'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    description = Column(String(250))
    catalog_id = Column(Integer, ForeignKey('catalog.id'))
    user_id = Column(Integer, ForeignKey('user.id'))
    created = Column(TIMESTAMP, server_default=func.now())
    catalog = relationship(Catalog)
    user = relationship(User)

    @property
    def serialize(self):
        """serialize the item"""
        return {
            'id': self.id,
            'title': self.name,
            'description': self.description,
            'cat_id': self.catalog_id
        }


engine = create_engine('postgresql://catalog:12345@localhost/catalog')

Base.metadata.create_all(engine)
