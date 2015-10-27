#!/usr/bin/python

'''
WARNING: Don't use this yet.  Not done/tested yet + doesn't implement XSRF mechanisms yet.
'''

import inspect
import bottle
import os
import datetime

class BaseSessionStorage(object):
    def __init__(self, prefix, redis, get_user_by_user_id):
        self.prefix = prefix
        self.redis = redis
        self.get_user_by_user_id = get_user_by_user_id
    
    def store(self, session_id, user_id, session_lifetime_ms):
        key = self.prefix + session_id
        self.redis.set(key, user_id)
        self.redis.pexpire(key, session_lifetime_ms)
    
    def get_user(self, session_id, session_lifetime_ms=None):
        if session_lifetime_ms:
            self.redis.pexpire(session_id, session_lifetime_ms)
        user_id = self.redis.get(session_id)
        if user_id is not None:
            return self.get_user_by_user_id(user_id)            
    
    def expire(self, session_id):
        self.redis.delete(session_id)
    
    def expire_by_user(self, user_id, excluded_session_id=None):
        # TODO: make more efficient
        for key in self.redis.keys(self.prefix + '*'):
            session_id = key[len(self.prefix):]
            if excluded_session_id != session_id and self.redis.get(key) == user_id:
                self.expire(session_id)


# wrapper for bottle functions
def require_permission(name):
    def set_permission(f):
        f.__dict__['permission'] = name
        return f
    return set_permission


class BasePermissionBasedSecurityScheme(object):
    
    @staticmethod
    def get_user(username):
        users = {
            'herman': {'password': 'xmas', 'permissions': ['read', 'write']},
            'max': {'password': 'cheese', 'permissions': ['read']},
        }
        return users.get(username)
    
    def authorize(self, user, required_permission):
        """Returns None on success and an error string otherwise."""
        if required_permission not in user['permissions']:
            return 'Unauthorized.'
        return None

    def authenticate(self, username, password, ip=None):
        """Returns a user dict on success and an error string otherwise."""
        if not username:
            return 'Authentication required.'
        user = self.get_user(username)
        if not user:
            return 'User "%s" does not exist.' % username

        if user.password != password:
            return 'Incorrect password.'
        else:
            return user


class UserAuthPlugin(object):
    name = 'userauth'
    api = 2
    
    def __init__(
            self, 
            security_scheme, 
            session_storage, 
            session_lifetime_sec=60*15,
            secure_cookie=False,
            cookie_name='session',
            realm_name='Private'):
        self.security_scheme = security_scheme
        self.session_storage = session_storage
        self.session_lifetime_sec = session_lifetime_sec
        self.cookie_name = cookie_name
        self.set_cookie_options = {'expires': datetime.datetime.utcnow() + datetime.timedelta(days=90),}
        if secure_cookie:
            self.set_cookie_options['secure'] = True
        self.realm_name = realm_name
    
    def get_session_user(self):
        session_id = bottle.request.get_cookie(self.cookie_name)
        if session_id:
            return self.session_storage.get_user(session_id)
    
    def get_user(self):
        # check basic auth before session auth
        username, password = bottle.request.auth or (None, None)
        session_id = bottle.request.get_cookie(self.cookie_name)
        if username is not None:
            return self.security_scheme.authenticate(username, password, bottle.request.remote_addr)
        elif session_id:
            return self.session_storage.get_user(session_id, self.session_lifetime_sec * 1000)
        return 'Authentication required.'
    
    def apply(self, callback, route):
        args = inspect.getargspec(route.callback)[0]
        if 'user' not in args:
            return callback

        def wrapper(*args, **kwargs):
            user_or_error = self.get_user()
            if isinstance(user_or_error, dict):
                authorization_error = self.security_scheme.authorize(user_or_error, callback.__dict__.get('permission', None))
                if authorization_error:
                    raise bottle.HTTPError(403, authorization_error)
                kwargs['user'] = user_or_error
                return callback(*args, **kwargs)

            response = bottle.HTTPError(401, str(user_or_error))
            # don't request basic auth from ajax requests
            if not bottle.request.is_xhr:
                response.headers['WWW-Authenticate'] = 'Basic realm="%s"' % self.realm_name
            raise response
        
        return wrapper

    def session_login(self, user_id):
        session_id = os.urandom(16).encode('hex')
        self.session_storage.store(session_id, user_id, self.session_lifetime_sec * 1000)
        bottle.response.set_cookie(self.cookie_name, session_id, path='/', **self.set_cookie_options)
        
    def session_logout(self):
        session_id = bottle.request.get_cookie(self.cookie_name)
        if session_id: 
            self.session_storage.expire(session_id)
            bottle.response.delete_cookie(self.cookie_name, path='/')

    def logout_other_sessions(self, user_id):
        session_id = bottle.request.get_cookie(self.cookie_name) or ''
        self.session_storage.expire_by_user(user_id, session_id)