#!/usr/bin/python

from ..util import never_cache

class NeverCachePlugin(object):
    name = 'nevercache'
    api = 2
    
    def apply(self, callback, route):
        def wrapper(*args, **kwargs):
            never_cache()
            return callback(*args, **kwargs)
        return wrapper