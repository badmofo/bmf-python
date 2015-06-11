#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
import datetime
from decimal import Decimal 
from .util import AttrDict


DEFAULT_NOT_SPECIFIED = '849fd780-ff1e-11e1-9055-442a60fb615e'

class ValidationError(Exception):
    def __init__(self, message, parameter=None):
        """ - parameter: the name of the invalid parameter
            - message: the problem 
        """
        super(ValidationError, self).__init__(message)
        self.parameter = parameter
        
    def __unicode__(self):
        if not self.parameter:
            return self.message
        return "Parameter: '%s' Error: %s" % (self.parameter, self.message)
    
    def __str__(self):
        return self.__unicode__().encode('utf-8')

def validate_bottle(*param_specs):
    from bottle import request
    if request.method == 'POST':
        return validate_bottle_json_post(*param_specs)
    elif request.method == 'GET':
        return validate_bottle_get(*param_specs)

def validate_bottle_json_body():
    from bottle import request, HTTPError
    try:
        if not request.content_type.startswith('application/json'):
            raise HTTPError(400, "Invalid request.  Content-Type must be set to \'application/json\'.")
        if request.json is None or not isinstance(request.json, dict):
            raise HTTPError(400, "Invalid request.  Expected JSON-formatted input parameters in request body.")
    except ValueError, e:
        raise  HTTPError(400, "Invalid request.  Error parsing JSON body: %s" % e)

def validate_bottle_json_post(*param_specs):
    from bottle import request, HTTPError
    if not param_specs: return
    validate_bottle_json_body()
    try:
        return validate_dict(request.json, param_specs)
    except ValidationError, e:
        raise HTTPError(400, "Invalid request.  %s" % e)

def validate_bottle_get(*param_specs):
    from bottle import request, HTTPError
    if not param_specs: return
    try:
        return validate_dict(request.query, param_specs)
    except ValidationError, e:
        raise HTTPError(400, "Invalid request.  %s" % e)

def validate_dict(params, param_specs):
    values = AttrDict()
    for s in param_specs:
        value = Exception # signals undefined
        for name_or_alias in [s.name] + s.aliases:
            if name_or_alias in params:
                value = params[name_or_alias]
                break
        if value is not Exception: # param is defined
            if value == s.default: # bypass checks if already default (useful for None)
                values[s.name] = s.default
            else:
                values[s.name] = s.check(value)
        elif s.is_mandatory():
            raise ValidationError("missing mandatory parameter", s.name)
        else:
            values[s.name] = s.default
    return values

def dump_set(iterable):
    return '[' + ', '.join(["'%s'" % a for a in iterable]) + ']'

class Validators(object):
    @staticmethod
    def positive(value):
        if value < 0:
            raise ValidationError("positive number expected")
        return value
    
    @staticmethod
    def negative(value):
        if value > 0:
            raise ValidationError("negative number expected")
        return value

    @staticmethod
    def strip(value):
        if value is None: return None
        return value.strip()
    
    @staticmethod
    def str_to_int(value):
        if not value: return None
        try:
            return int(value.strip())
        except ValueError:
            raise ValidationError("invalid number")
    
    @staticmethod
    def str_to_bool(value):
        if value is None or value == '': return None
        return not (value.lower() == 'false' or value == '0')

    @staticmethod
    def iso_date(value):
        if not value: return None
        try:
            return datetime.datetime.strptime(value, '%Y-%m-%d')
        except ValueError:
            raise ValidationError("invalid date")
    
    @staticmethod
    def iso_date_str(value):
        if not value: return value
        try:
            return str(datetime.datetime.strptime(value, '%Y-%m-%d').date())
        except ValueError:
            raise ValidationError("invalid date")

    @staticmethod
    def iso_datetime(value):
        if not value: return None
        try:
            return datetime.datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                return datetime.datetime.strptime(value, '%Y-%m-%d')
            except ValueError:
                raise ValidationError("invalid date")
    
    @staticmethod
    def decimal(value):
        return Decimal(str(value)) if isinstance(value, float) else Decimal(value)
    
    @staticmethod
    def uuid(value):
        uuid_re = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.I)
        if not uuid_re.match(value):
            raise ValidationError("invalid uuid")
        return value.lower()
    
    @staticmethod
    def random_uuid(value):
        value = Validators.uuid(value)
        if value.startswith('00000000-0000') or value.endswith('000000000000'):
            raise ValidationError("invalid uuid (expected type 4 random)")
        return value.lower()
    
    @staticmethod
    def e123_intl_phone(value):
        if not re.match(r'^\+[0-9]{7,15}$', value):
            raise ValidationError("invalid e.123 international phone number")
        return value
    
    @staticmethod
    def hex(value):
        if not value: return None
        value = value.strip()
        if not re.match(r'^[A-F0-9]*$', value, re.I) or len(value) % 2 == 1:
            raise ValidationError("not a valid hex-encoded string")
        return value 

    @staticmethod
    def email(value):
        if not value: return None
        value = value.strip()
        if not re.match(r'^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,6}$', value, re.I):
            raise ValidationError("invalid email")
        return value
    
    @staticmethod
    def emails(value):
        if not value: return None
        value = sorted(set([v.lower() for v in value.split()]))
        for v in value:
            try:
                Validators.email(v)
            except ValidationError:
                raise ValidationError("invalid email '%s'" % (v,))
        return '\n'.join(value)
        
    @staticmethod
    def cidr_list(value):
        if value is None: return None
        value = value.replace(',', ' ').strip()
        import netaddr
        try:
            netaddr.IPSet(value.split())
        except:
            raise ValidationError("invalid cidr list")
        return value
    
    @staticmethod
    def regex(regex_str):
        def inner_validate(value):
            if value is None: return None
            if not re.match(regex_str, value):
                raise ValidationError("'%s' not properly formatted" % (value,))
            return value
        return inner_validate

    @staticmethod
    def length(max_length, min_length=0):
        def inner_validate(value):
            if value is None: return None
            if len(value) > max_length:
                raise ValidationError("'%s' exceeds max length %s" % (value, max_length))
            if len(value) < min_length:
                raise ValidationError("'%s' shorter than min length %s" % (value, min_length))            
            return value
        return inner_validate

    @staticmethod
    def one_of(*args):
        def inner_validate(value):
            if value is None: return None
            if value not in args:
                raise ValidationError("'%s' not in %s" % (value, dump_set(args)))
            return value
        return inner_validate
    
    @staticmethod
    def validate_one_of_ignore_case(*args):
        from .util import strip_accents
        args = {strip_accents(a.lower()): a for a in args}
        def inner_validate(value, name):
            if value is None: return None
            v = strip_accents(value.lower())
            if v not in args:
                raise ValidationError("'%s' not in %s" % (value, dump_set(args.values())))
            return args[v]
        return inner_validate


class ParamSpec(object):
    def __init__(self, name, type_spec, validator_filter_spec=None, default=DEFAULT_NOT_SPECIFIED):
        """ - type_spec: s|f|i|a|o|b
            - validator_filter_spec: 
                a list of validation functions
            - default: if not provided assume parameter is mandatory
        """
        self.name = name
        self.aliases = []
        if isinstance(name, (list, tuple)):
            self.name = name[0]
            self.aliases = list(name[1:])
        self.type_spec = type_spec
        self.validator_filter_spec = validator_filter_spec
        self.default = default
        
    def is_mandatory(self):
        return self.default == DEFAULT_NOT_SPECIFIED

    def check(self, value):
        try:
            types = {
                's': ((str, unicode), 'string'),
                'f': ((float, long, int, Decimal), 'float'),
                'i': ((int, long), 'integer'),
                'a': ((list, tuple), 'array'),
                'o': ((dict,), 'object'),
                'b': ((bool), 'boolean'),
            }
            type_classes, type_name = types[self.type_spec]
            if not isinstance(value, type_classes):
                raise ValidationError("must be type '%s'" % (type_name,))
        
            if self.validator_filter_spec:
                if not isinstance(self.validator_filter_spec, (tuple, list)):
                    self.validator_filter_spec = [self.validator_filter_spec]
                for v_f in self.validator_filter_spec:
                    value = v_f(value)
                
            return value
        except ValidationError as e:
            e.parameter = self.name
            raise


if __name__ == "__main__":
    P = ParamSpec
    V = Validators
    
    # TODO: test missing and default
    tests = [
        [P('a', 'i', V.positive), 1, 1, None],
        [P('a', 'i', V.positive), -1, None, True],
        [P('a', 's', V.strip), ' hello ', 'hello', None],
        [P('a', 's', [V.strip, V.length(3)]), ' foo ', 'foo', None],
        [P('a', 's', [V.strip, V.length(3)]), ' foobar ', None, True],
        [P('a', 's', V.emails), 'a@b.com a@i-a.com', 'a@b.com\na@i-a.com', None],
        [P('a', 's', V.emails), 'a@com a@i-a.com', None, True],
        [P('a', 's', V.one_of(u'abcdé', 'abc')), u'abcdé', u'abcdé', None],
        [P('a', 's', V.one_of(u'abcdé', 'abc')), u'a', None, True],
        [P('a', 's', V.regex('\d+')), '1234', '1234', None],
        [P('a', 's', V.regex('\d+')), 'abc', None, True],
        [P('a', 's', V.hex), 'deadbeef001234', 'deadbeef001234', None],
        [P('a', 's', V.hex), 'deadbeef1', None, True],
        [P('a', 's', V.uuid), '7f2151e2-8f2e-4fb9-b3e9-ca9ffd41eebf', '7f2151e2-8f2e-4fb9-b3e9-ca9ffd41eebf',  None],
        [P('a', 's', V.uuid), 'B3E9-CA9FFD41EEBF', None, True],
        [P('a', 's', V.str_to_bool), 'FALSE', False, None],
        [P('a', 's', V.str_to_bool), '1', True, None],
        [P('a', 's', V.iso_date), '2015-12-20', datetime.datetime(2015, 12, 20), None],
        [P('a', 's', V.iso_date), '2015-13-20', None, True],
    ]
    
    for i, (spec, value_in, value_expected, error) in enumerate(tests):
        print 'test', i, ':', value_in, value_expected
        try:
            value_out = validate_dict({'a': value_in}, [spec])['a']
            assert value_out == value_expected, (value_out, value_expected)
            assert error is None
            print value_out
        except ValidationError as e:
            assert error, e
            print e
