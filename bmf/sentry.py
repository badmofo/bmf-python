#!/usr/bin/python

# this is actually a standard logging handler and not a bottle plugin

import bottle
from raven.handlers.logging import SentryHandler
from raven.utils.wsgi import get_headers, get_environ

def get_bottle_request_data():
    if 'REQUEST_METHOD' in bottle.request.environ:
        body = bottle.request.body.read()
        if len(body) > 1024 * 4:
            body = '[%sb body omitted]' % len(body)
        return {
                'method': bottle.request.method,
                'url': bottle.request.url,
                'query_string': bottle.request.environ.get('QUERY_STRING'),
                'data': body,
                'headers': dict(get_headers(bottle.request.environ)),
                'env': dict(get_environ(bottle.request.environ)),
            }

class BottleSentryHandler(SentryHandler):
    def _emit(self, record, **kwargs):
        data = get_bottle_request_data()
        if data:
            record.__dict__['sentry.interfaces.Http'] = data
        return super(BottleSentryHandler, self)._emit(record, **kwargs)