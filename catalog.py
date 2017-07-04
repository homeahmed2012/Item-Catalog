from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, desc, exists
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Catalog, CatalogItem
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(open('/var/www/catalog/client_secrets.json', 'r').read())['web']['client_id']

engine = create_engine('postgresql://catalog:12345@localhost/catalog')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


def getCatalogName(catalog_id):
    catalog = session.query(Catalog).get(catalog_id)
    if catalog:
        return catalog.name
    else:
        return None


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('/var/www/catalog/client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    (ret,), = session.query(exists().where(User.email == data['email']))
    if not ret:
        newUser = User(name=data['name'],
                       email=data['email'])
        session.add(newUser)
        session.commit()
    response = make_response(json.dumps('successful login.'),
                             200)
    response.headers['Content-Type'] = 'application/json'
    return response


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']
    if access_token is None:
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        return redirect(url_for('mainPage'), code=302)
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/')
@app.route('/catalog')
def mainPage():
    cats = session.query(Catalog).all()
    items = session.query(CatalogItem).order_by(desc(CatalogItem.created)).limit(10)
    items_catalog = []
    for item in items:
        items_catalog.append((item, getCatalogName(item.catalog_id)))
    if 'username' in login_session:
        return render_template("catalogs.html",
                               login="logout",
                               login_url="/gdisconnect",
                               cats=cats,
                               items=items_catalog)
    else:
        return render_template("catalogs.html",
                               login="login",
                               login_url="/login",
                               cats=cats,
                               items=items_catalog)


@app.route('/catalog/<string:category_name>/items')
def showItems(category_name):
    cats = session.query(Catalog).all()
    category_id = session.query(Catalog).filter_by(name=category_name).one().id
    items = session.query(CatalogItem).filter_by(catalog_id=category_id)
    if 'username' in login_session:
        return render_template("show_catalog_items.html",
                               login="logout",
                               login_url="/gdisconnect",
                               cats=cats,
                               catalog_name=category_name,
                               items=items)
    else:
        return render_template("show_catalog_items.html",
                               login="login",
                               login_url="/login",
                               cats=cats,
                               catalog_name=category_name,
                               items=items)


@app.route('/catalog/<string:catalog_name>/<string:item_name>')
def showItem(catalog_name, item_name):
    catalog_id = session.query(Catalog).filter_by(name=catalog_name).one().id
    item = session.query(CatalogItem).filter_by(name=item_name,
                                                catalog_id=catalog_id).one()
    if item:
        if 'username' in login_session:
            user = session.query(User).filter_by(email=login_session['email']).one()
            if user.id != item.user_id:
                return render_template('show_item.html',
                                       item=item,
                                       login="logout",
                                       login_url="/gdisconnect",
                                       )
            else:
                return render_template('show_item.html',
                                       item=item,
                                       login="logout",
                                       login_url="/gdisconnect",
                                       user=user
                                       )
        else:
            return render_template('show_item.html',
                                   item=item,
                                   login="login",
                                   login_url="/login"
                                   )
    else:
        return "error Item not found"


@app.route('/catalog/add', methods=['GET', 'POST'])
def addItem():
    if 'username' not in login_session:
        return redirect(url_for('mainPage'), code=302)
    user = session.query(User).filter_by(name=login_session['username']).one()
    if request.method == 'POST':
        newItem = CatalogItem(name=request.form['title'],
                              description=request.form['description'],
                              catalog_id=request.form['catalog_id'],
                              user_id=user.id)
        session.add(newItem)
        session.commit()
        return redirect(url_for('mainPage'), code=302)
    else:
        catalogs = session.query(Catalog).all()
        return render_template('add_item.html',
                               cats=catalogs,
                               login='logout',
                               login_url='/gdisconnect'
                               )


@app.route('/catalog/<string:item_name>/edit', methods=['GET', 'POST'])
def editItem(item_name):
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    user = session.query(User).filter_by(email=login_session['email']).one()
    item = session.query(CatalogItem).filter_by(name=item_name).one()
    if user.id != item.user_id:
        return "error you can modify your items only."
    if request.method == 'POST':
        item.name = request.form['title']
        item.description = request.form['description']
        item.catalog_id = request.form['catalog_id']
        session.add(item)
        session.commit()
        return redirect(url_for('mainPage'))
    else:
        catalogs = session.query(Catalog).all()
        return render_template('edit_item.html',
                               item=item,
                               cats=catalogs,
                               login='logout',
                               login_url='/gdisconnect')


@app.route('/catalog/<string:item_name>/delete', methods=['GET', 'POST'])
def delItem(item_name):
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    user = session.query(User).filter_by(email=login_session['email']).one()
    item = session.query(CatalogItem).filter_by(name=item_name).one()
    if user.id != item.user_id:
        return "error you can modify your items only."
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        return redirect(url_for('mainPage'))
    else:
        return render_template('delete_item.html',
                               login='logout',
                               login_url='/gdisconnect'
                               )


@app.route('/catalog.json')
def api():
    catalogs = session.query(Catalog).all()
    result = []
    for cat in catalogs:
        items = session.query(CatalogItem).filter_by(catalog_id=cat.id).all()
        serialize_cat = cat.serialize
        serialize_cat['items'] = [i.serialize for i in items]
        result.append(serialize_cat)
    return jsonify(Category=result)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run()
