#!/usr/bin/python

'''
It's usually a better idea to use the torndb package for MySQL connectivity.
The only advantage to using this class is that it won't shit all over itself
if a signal is sent to a process in the middle of a database query.  This can
happen if you are running a web application under gunicorn and soft restart 
it.
'''

import time
import mysql.connector
from mysql.connector import IntegrityError

__all__ = ['Connection', 'IntegrityError']

class Connection(object):
    def __init__(self, host, database, user, password):
        self.c = None
        self.args = {
            'host': host,
            'database': database,
            'user': user,
            'password': password,
            'autocommit': True,
            'buffered': True,
            'sql_mode': 'TRADITIONAL',
            'time_zone': '+0:00',
        }
        self.max_idle_time= 1 * 60 * 60
        self.last_use_time = 0
        self.ensure_connected()
    
    def close(self):
        if getattr(self, "c", None) is not None:
            self.c.close()
            self.c = None

    def __del__(self):
        try:
            self.close()
        except Exception: # sometime get weird attribute errors on shutdown
            pass

    def reconnect(self):
        """Closes the existing database connection and re-opens it."""
        self.close()
        self.c = mysql.connector.connect(**self.args)

    def ensure_connected(self):
        # Mysql by default closes client connections that are idle for
        # 8 hours, but the client library does not report this fact until
        # you try to perform a query and it fails.  Protect against this
        # case by preemptively closing and reopening the connection
        # if it has been idle for too long (1 hour by default).
        idle_time = time.time() - self.last_use_time
        if self.c is None or idle_time > self.max_idle_time:
            self.reconnect()
        self.last_use_time = time.time()

    def cursor(self):
        self.ensure_connected()
        return self.c.cursor()

    def _execute(self, cursor, query, parameters, kwparameters):
        try:
            return cursor.execute(query, kwparameters or parameters)
        except mysql.connector.OperationalError:
            self.close()
            raise

    def query(self, query, *parameters, **kwparameters):
        """Returns a row list for the given query and parameters."""
        cursor = self.cursor()
        try:
            self._execute(cursor, query, parameters, kwparameters)
            column_names = [d[0] for d in cursor.description]
            return [Row(zip(column_names, row)) for row in cursor]
        finally:
            cursor.close()
            
    def get(self, query, *parameters, **kwparameters):
        """Returns the first row returned for the given query."""
        rows = self.query(query, *parameters, **kwparameters)
        if not rows:
            return None
        elif len(rows) > 1:
            raise Exception("Multiple rows returned for Database.get() query")
        else:
            return rows[0]

    def execute_lastrowid(self, query, *parameters, **kwparameters):
        """Executes the given query, returning the lastrowid from the query."""
        cursor = self.cursor()
        try:
            self._execute(cursor, query, parameters, kwparameters)
            return cursor.lastrowid
        finally:
            cursor.close()
    
    execute = execute_lastrowid

    def execute_many(self, query, *parameters, **kwparameters):
        """Executes the given query on multiple rows of data."""
        cursor = self.cursor()
        try:
            return cursor.executemany(query, *parameters, **kwparameters)
        finally:
            cursor.close()


class Row(dict):
    """A dict that allows for object-like property access syntax."""
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)
    