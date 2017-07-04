from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import User, Base, Catalog, CatalogItem

engine = create_engine('postgresql://catalog:12345@localhost/catalog')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()


catalog1 = Catalog(name="Soccer")
catalog2 = Catalog(name="Basketball")
catalog3 = Catalog(name="Baseball")
catalog4 = Catalog(name="Frisbee")
catalog5 = Catalog(name="Snowboarding")
catalog6 = Catalog(name="Rock Climbing")
catalog7 = Catalog(name="Foosball")
catalog8 = Catalog(name="Skating")
catalog9 = Catalog(name="Hockey")

session.add(catalog1)
session.add(catalog2)
session.add(catalog3)
session.add(catalog4)
session.add(catalog5)
session.add(catalog6)
session.add(catalog7)
session.add(catalog8)
session.add(catalog9)
session.commit()

print("added menu items!")
