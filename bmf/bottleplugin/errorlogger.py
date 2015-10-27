#!/usr/bin/python

import bottle

class ErrorLoggerPlugin(object):
    """Sends exceptions to Python standard logging."""
    name = 'errorlogger'
    api = 2
    
    def __init__(self, logger):
        self.logger = logger
    
    def apply(self, callback, route):
        def wrapper(*args, **kwargs):
            try:
                return callback(*args, **kwargs)
            except Exception as e:
                # immediately re-raise if this was not caused by a real exception
                if isinstance(e, bottle.HTTPError) and not e.exception:
                    raise
                self.logger.exception('Http 500 Error: %s', e)
                raise
        
        return wrapper