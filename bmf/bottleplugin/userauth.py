#!/usr/bin/python

'''
WARNING: Don't use this yet.  Not fully tested yet.
'''

import inspect
import bottle
import os
import datetime
import hmac
import hashlib
import scrypt
import random
import re
import time


def now():
    return int(time.time())

class SqlSessionStorage:
    '''
    CREATE TABLE session(
        id CHAR(32),
        user_id INT NOT NULL,
        expiry BIGINT UNSIGNED NOT NULL,

        KEY(user_id, expiry),
        PRIMARY KEY(id)
    );
    '''
    def __init__(self, db):
        self.db = db
        
    def store(self, session_id, user_id, session_lifetime):
        self.db.replace('session', id=session_id, user_id=user_id, expiry=now() + session_lifetime)
    
    def get_user_id(self, session_id):
        session = self.db.get('select * from session where id=%s and expiry > %s', session_id, now())
        if session:
            return session.user_id
    
    def refresh(self, session_id, session_lifetime):
        self.db.execute('update session set expiry=%s where id=%s', now() + session_lifetime, session_id)
    
    def expire(self, session_id):
        self.db.execute('delete from session where expiry < %s or id=%s', now(), session_id)
        
    def expire_by_user(self, user_id, excluded_session_id=''):
        self.db.execute('delete from session where user_id=%s and id<>%s', user_id, excluded_session_id)


class NullLockoutManager(object):
    def clear_lockouts(self, user_id):
        pass
    
    def get_lockouts(self, user_id):
        return []
    
    def is_locked_out(self, ip, user_id):
        pass
    
    def authentication_attempt(self, ip, user_id, success):
        pass


class RedisLockoutManager(object):
    def __init__(self, redis, lockout_threshold=30, lockout_duration_sec=60*60):
        self.redis = redis
        self.lockout_threshold = lockout_threshold
        self.lockout_duration_sec = lockout_duration_sec

    def clear_lockouts(self, user_id):
        """Clear any lockouts for the given account."""
        for k in self.redis.keys('auth.failures:*:%s' % user_id):
            self.redis.delete(k)
    
    def get_lockouts(self, user_id):
        lockouts = []
        for k in self.redis.keys('auth.failures:*:%s' % user_id):
            k = k.decode('utf-8')
            ip = k.split(':')[1]
            failures = int(self.redis.get(k) or 0)
            if failures >= self.lockout_threshold:
                lockouts.append((ip, self.redis.ttl(k)))
        return lockouts
        
    def is_locked_out(self, ip, user_id):
        key = 'auth.failures:%s:%s' % (ip, user_id)
        failures = int(self.redis.get(key) or 0)
        if failures >= self.lockout_threshold:
            return self.redis.ttl(key)
        
    def authentication_attempt(self, ip, user_id, success):
        key = 'auth.failures:%s:%s' % (ip, user_id)
        if success:
            self.redis.delete(key)
        else:
            self.redis.incr(key)
            self.redis.expire(key, self.lockout_duration_sec)


# wrapper for bottle functions
def require_permission(name):
    def set_permission(f):
        f.__dict__['permission'] = name
        return f
    return set_permission

def scrypt_kdf(password, salt):
    return scrypt.hash(password, salt, N=16384, r=8, p=1, buflen=16).hex()

class UserStore(object):
    '''
    # Minimal User
    CREATE TABLE user (
        id INT NOT NULL AUTO_INCREMENT,
        username VARCHAR(32) NOT NULL,
        salt CHAR(32) NOT NULL DEFAULT '',
        password CHAR(32) NOT NULL DEFAULT '',
        status ENUM('enabled', 'disabled') NOT NULL DEFAULT 'enabled',
        role VARCHAR(32) NOT NULL,
        permissions VARCHAR(128) NOT NULL DEFAULT '',
        
        UNIQUE(username),
        PRIMARY KEY (id)
    );
    '''
    def __init__(self, db, kdf=scrypt_kdf):
        self.db = db
        self.kdf = kdf
    
    def get_user_by_username(self, username):
        return self.db.get('select * from user where username=%s', username)
        
    def get_user_by_id(self, user_id):
        return self.db.get('select * from user where id=%s', user_id)
        
    def check_password(self, user, password):
        return hmac.compare_digest(self.kdf(password, user.salt), user.password)
        
    def update_password(self, user_id, password):
        salt = os.urandom(16).hex()
        self.db.execute('update user set salt=%s, password=%s where id=%s', salt, self.kdf(password, salt), user_id)


class PasswordPolicy(object):
    def generate_password(self, length=8, alphabet='23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'):
        rng = random.SystemRandom()
        while True:
            password = ''.join([rng.choice(alphabet) for x in range(length)])
            if not self.check_password(password):
                return password
    
    def check_password(self, password):
        """Return None on success and an error string otherwise."""
        if len(password) < 8:
            return 'password must be 8 or more characters'
        if not re.search(r'\d', password):
            return 'password must contain at least 1 digit'
        if not re.search(r'[a-zA-Z]', password):
            return 'password must contain at least 1 alphabetic character'


class AuthenticationException(Exception):
    pass

class XsrfTokenException(Exception):
    pass
    
def permissions_check(required, granted):
    '''Users must be granted at least one of the required permissions to pass the check.'''
    required = set((required or '').strip().split())
    granted = set((granted or '').strip().split())
    return bool(required & granted)

class SecurityScheme(object):
    
    def __init__(self, user_store, lockout_manager):
        self.user_store = user_store
        self.lockout_manager = lockout_manager
    
    def authorize(self, user, required_permissions):
        """Returns None on success and an error string otherwise."""
        if user.status != 'enabled':
            return 'Account disabled.'
        if not required_permissions:
            return None
        if user.role != 'superuser' and not permissions_check(required_permissions, user.permissions):
            return 'Insufficient privileges.'
    
    def authenticate(self, username, password, ip=None):
        """Returns a user dict on success and AuthenticationException otherwise."""
        if not username: 
            raise AuthenticationException('Authentication required.')
        user = self.user_store.get_user_by_username(username)
        if not user:
            raise AuthenticationException('User does not exist.')
        elif user.status != 'enabled':
            raise AuthenticationException('Account disabled.')
        
        lockout = self.lockout_manager.is_locked_out(ip, user.id)
        if lockout:
            raise AuthenticationException('Too many authentication failures.  Account locked for %s seconds.' % lockout)
        
        if not self.user_store.check_password(user, password):
            self.lockout_manager.authentication_attempt(ip, user.id, False)
            raise AuthenticationException('Incorrect password.')
        
        self.lockout_manager.authentication_attempt(ip, user.id, True)
        return user

    def update_password(self, user_id, password):
        self.user_store.update_password(user_id, password)
        self.lockout_manager.clear_lockouts(user_id)


class UserAuthPlugin(object):
    name = 'userauth'
    api = 2    
    
    def __init__(
            self,
            xsrf_secret,
            user_store,
            security_scheme,
            session_storage,
            session_lifetime_sec=60*15, # 15 minutes
            secure_cookie=False,
            cookie_name='SESSION',
            cookie_name_xsrf='XSRF-TOKEN',
            realm_name='Private'):
        self.xsrf_secret = xsrf_secret
        self.user_store = user_store
        self.security_scheme = security_scheme
        self.session_storage = session_storage
        self.session_lifetime_sec = session_lifetime_sec
        self.cookie_name = cookie_name
        self.cookie_name_xsrf = cookie_name_xsrf
        self.set_cookie_options = {
            'expires': datetime.datetime.utcnow() + datetime.timedelta(days=90),
        }
        if secure_cookie:
            self.set_cookie_options['secure'] = True
        self.realm_name = realm_name

    def generate_xsrf_token(self, session_id):
        return hmac.new(
            session_id.encode('utf-8'),
            self.xsrf_secret.encode('utf-8'), 
            hashlib.sha256).hexdigest()[:32]

    def get_user(self):
        # check basic auth before session auth
        username, password = bottle.request.auth or (None, None)
        session_id = bottle.request.get_cookie(self.cookie_name)
        if username is not None:
            return self.security_scheme.authenticate(username, password, bottle.request.remote_addr)
        elif session_id:
            user_id = self.session_storage.get_user_id(session_id)
            if user_id is not None:
                user = self.user_store.get_user_by_id(user_id)
                if user is not None:
                    xsrf_token_correct = self.generate_xsrf_token(session_id)
                    xsrf_token = bottle.request.params.get('XSRF-TOKEN', bottle.request.headers.get('X-XSRF-TOKEN', ''))
                    if not hmac.compare_digest(xsrf_token, xsrf_token_correct):
                        raise XsrfTokenException('Invalid XSRF token.')
                    self.session_storage.refresh(session_id, self.session_lifetime_sec)
                    return user

    def apply(self, callback, route):
        args = inspect.getargspec(route.callback)[0]
        if 'user' not in args:
            return callback

        def wrapper(*args, **kwargs):
            try:
                user = self.get_user()
                if user:
                    permissions = callback.__dict__.get('permission', None)
                    authorization_error = self.security_scheme.authorize(user, permissions)
                    if authorization_error:
                        raise bottle.HTTPError(403, authorization_error)
                    kwargs['user'] = user
                    return callback(*args, **kwargs)
                else:
                    raise AuthenticationException('Authentication required.')
            except AuthenticationException as e:
                response = bottle.HTTPError(401, str(e))
                # don't request basic auth from ajax requests
                if not bottle.request.is_xhr:
                    response.headers['WWW-Authenticate'] = 'Basic realm="%s"' % self.realm_name
                raise response
            except XsrfTokenException as e:
                raise bottle.HTTPError(403, str(e))
        
        return wrapper

    def session_login(self, user_id):
        session_id = os.urandom(16).hex()
        self.session_storage.store(session_id, user_id, self.session_lifetime_sec)
        bottle.response.set_cookie(self.cookie_name, session_id, path='/', httponly=True, **self.set_cookie_options)
        xsrf_token = self.generate_xsrf_token(session_id)
        bottle.response.set_cookie(self.cookie_name_xsrf, xsrf_token, path='/', **self.set_cookie_options)
        
    def session_logout(self):
        session_id = bottle.request.get_cookie(self.cookie_name)
        if session_id: 
            self.session_storage.expire(session_id)
            bottle.response.delete_cookie(self.cookie_name, path='/')
            bottle.response.delete_cookie(self.cookie_name_xsrf, path='/')

    def logout_other_sessions(self, user_id):
        session_id = bottle.request.get_cookie(self.cookie_name) or ''
        self.session_storage.expire_by_user(user_id, session_id)