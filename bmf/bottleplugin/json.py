#!/usr/bin/python

import bottle
from ..util import dumps

class JsonPlugin(object):
    """Turn dist, list, and tuple outputs into application/json responses."""
    name = 'json'
    api  = 2

    def __init__(self, json_dumps=dumps):
        self.json_dumps = json_dumps

    def apply(self, callback, context):
        def wrapper(*a, **ka):
            response = callback(*a, **ka)
            if isinstance(response, (dict, list, tuple)):
                # attempt to serialize, raises exception on failure
                json_response = self.json_dumps(response)
                # set content type only if serialization succesful
                bottle.response.content_type = 'application/json'
                return json_response
            return response
        return wrapper