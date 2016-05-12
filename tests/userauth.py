import bottle
import os
import time
from redis import StrictRedis
from bmf.simpledb import Connection
from bmf.bottleplugin.userauth import RedisLockoutManager, SqlSessionStorage, UserStore, SecurityScheme, UserAuthPlugin, AuthenticationException

def test_session_storage(session_storage):
    assert session_storage.get_user_id('test') is None
    session_id = os.urandom(16).hex()
    assert session_storage.get_user_id(session_id) is None
    user_id = 0
    session_storage.store(session_id, user_id, 10)
    assert session_storage.get_user_id(session_id) == user_id
    user_id = 1
    session_storage.store(session_id, user_id, 10)
    assert session_storage.get_user_id(session_id) == user_id
    session_storage.expire_by_user(user_id+1)
    assert session_storage.get_user_id(session_id) == user_id
    session_storage.expire_by_user(user_id, session_id)
    assert session_storage.get_user_id(session_id) == user_id
    session_storage.expire(session_id)
    assert session_storage.get_user_id(session_id) is None
    user_id = 2
    session_id = os.urandom(16).hex()
    session_storage.store(session_id, user_id, 1)
    assert session_storage.get_user_id(session_id) == user_id
    time.sleep(2)
    assert session_storage.get_user_id(session_id) is None
    session_storage.store(session_id, user_id, 1)
    session_storage.refresh(session_id, 3)
    time.sleep(2)
    assert session_storage.get_user_id(session_id) == user_id

def test_lockout_manager(redis):
    user_id = 1
    m = RedisLockoutManager(redis, 3, 2)
    m.clear_lockouts(user_id)
    ip = '0.0.0.0'
    assert not m.is_locked_out(ip, user_id)
    m.authentication_attempt(ip, user_id, False)
    assert not m.is_locked_out(ip, user_id)
    m.authentication_attempt(ip, user_id, False)
    assert not m.is_locked_out(ip, user_id)
    m.authentication_attempt(ip, user_id, False)
    assert m.is_locked_out(ip, user_id)
    m.clear_lockouts(user_id)
    assert not m.is_locked_out(ip, user_id)
    for i in range(10):
        m.authentication_attempt(ip, user_id, False)
    assert m.is_locked_out(ip, user_id)
    m.authentication_attempt(ip, user_id, True)
    assert not m.is_locked_out(ip, user_id)
    for i in range(10):
        m.authentication_attempt(ip, user_id, False)
    ip2 = '1.1.1.1'
    for i in range(10):
        m.authentication_attempt(ip2, user_id, False)
    assert len(m.get_lockouts(user_id)) == 2
    m.authentication_attempt(ip, user_id, True)
    assert len(m.get_lockouts(user_id)) == 1
    time.sleep(3)
    assert len(m.get_lockouts(user_id)) == 0

def test_user_store(db):
    username = 'test2'
    db.execute('delete from user where username=%s', username)
    user_id = db.replace('user', username=username, role='reader')
    user_store = UserStore(db)
    user = user_store.get_user_by_username(username)
    assert user.id == user_id
    user = user_store.get_user_by_username(username.upper())
    assert user.id == user_id
    user = user_store.get_user_by_username(username.lower())
    assert user.id == user_id
    user = user_store.get_user_by_id(user_id)
    assert user.id == user_id
    # get users that do not exist
    user_store.update_password(user.id, 'foo')
    assert not user_store.check_password(user, 'bar')
    user = user_store.get_user_by_id(user_id)
    assert user_store.check_password(user, 'foo')
    user = user_store.get_user_by_username('no such user')
    assert user is None
    user = user_store.get_user_by_username(-1)
    assert user is None

def test_security_scheme(redis, db):
    
    user_store = UserStore(db)
    lockout_manager = RedisLockoutManager(redis, 3, 2)
    scheme = SecurityScheme(user_store, lockout_manager)
    
    def test_auth(username, password, ip):
        try:
            return scheme.authenticate(username, password, ip)
        except AuthenticationException as e:
            return str(e)
    
    username = 'test1'
    password = 'foo'
    ip = '0.0.0.0'
    db.execute('delete from user where username=%s', username)
    user_id = db.replace('user', username=username, role='reader')
    
    user = test_auth(None, password, ip)
    assert user == 'Authentication required.'
    user = test_auth('no such user', password, ip)
    assert user == 'User does not exist.'
    db.update('user', 'username', username, status='disabled')
    user = test_auth(username, password, ip)
    assert user == 'Account disabled.'
    db.update('user', 'username', username, status='enabled')
    scheme.update_password(user_id, password)
    user = test_auth(username, password, ip)
    assert user.id == user_id
    user = test_auth(username, password + 'wrong', ip)
    assert 'Incorrect password.' == user
    for i in range(10):
        user = test_auth(username, password + 'wrong', ip)
    assert 'Too many authentication failures' in user
    user = test_auth(username, password + 'wrong', ip)
    time.sleep(3)
    user = test_auth(username, password, ip)
    assert user.id == user_id
    
    # test disabled users
    assert scheme.authorize(user, None) is None
    db.update('user', 'username', username, status='disabled')
    user = user_store.get_user_by_id(user_id)
    assert scheme.authorize(user, None) == 'Account disabled.'
    db.update('user', 'username', username, status='enabled')
    user = user_store.get_user_by_id(user_id)
    assert not scheme.authorize(user, None)
    user.permissions = 'read write'
    assert scheme.authorize(user, 'read') is None
    assert scheme.authorize(user, 'write') is None
    assert scheme.authorize(user, 'read write') is None
    assert scheme.authorize(user, 'delete') == 'Insufficient privileges.'
    assert scheme.authorize(user, 'delete write') is None
    user.role = 'superuser'
    assert scheme.authorize(user, 'delete') is None
    user.role = 'peon'
    assert scheme.authorize(user, 'delete')

def test_plugin(redis, db):
    
    session_storage = SqlSessionStorage(db)
    user_store = UserStore(db)
    lockout_manager = RedisLockoutManager(redis, 3, 2)
    security_scheme = SecurityScheme(user_store, lockout_manager)
    user_id = user_store.get_user_by_username('test1').id
    security_scheme.update_password(user_id, '12345')
    
    plugin = UserAuthPlugin('secret', user_store, session_storage, security_scheme)
    
    app = bottle.Bottle()
    app.install(plugin)

    @app.get('/hello/<name>')
    def index(name):
        return 'hello' + name
        
    @app.get('/auth/<foo>')
    def auth(user, foo):
        return repr(user)
        
    import traceback
    
    @app.get('/logout')
    def logout():
        plugin.session_logout()
        return 'out'
        
    @app.get('/logout2')
    def logout2(user):
        plugin.logout_other_sessions(user_id)
        return 'out'
        
    @app.get('/login/<username>/<password>')
    def login(username, password):
        try:
            user = security_scheme.authenticate(username, password, bottle.request.remote_addr)
            plugin.session_login(user.id)
            return repr(user)
        except Exception as e:
            traceback.print_exc()
            return repr(e)
        #return repr(user)
    
    app.run(host='localhost', port=8080)


if __name__ == "__main__":
    
    redis = StrictRedis()
    db = Connection('localhost', 'test')
    
    #test_session_storage(session_storage)
    #test_lockout_manager(redis)
    #test_user_store(db)
    #test_security_scheme(redis, db)
    test_plugin(redis, db)
