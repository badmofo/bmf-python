#!/usr/bin/python

import re
from decimal import Decimal 
import datetime
from .util import AttrDict


DEFAULT_NOT_SPECIFIED = '849fd780-ff1e-11e1-9055-442a60fb615e'

class ValidationError(Exception):
    pass


def validate_bottle(*param_specs):
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
        if s.name in params:
            if params[s.name] == s.default: # bypass checks if already default (useful for None)
                values[s.name] = s.default
            else:
                values[s.name] = s.check(params[s.name])
        elif s.default == DEFAULT_NOT_SPECIFIED:
            raise ValidationError("Missing mandatory parameter '%s'." % s.name)
        else:
            values[s.name] = s.default
    return values

class ParamSpec(object):
    def __init__(self, name, type_spec, validator_filter_spec=None, default=DEFAULT_NOT_SPECIFIED):
        """ - type_spec: s|f|i|a|o
            - validator_filter_spec: 
                positive
                mex_local_phone
                e123_intl_phone
                e123_intl_phone_accept_mex_local
                uuid
                str_to_int
            - default: if not provided assume parameter is mandatory
        """
        self.name = name
        self.type_spec = type_spec
        self.validator_filter_spec = validator_filter_spec
        self.default = default

    def check(self, value):
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
            raise ValidationError("Parameter '%s' must be type %s." % (self.name, type_name))
        
        if self.validator_filter_spec:
            if not isinstance(self.validator_filter_spec, (tuple, list)):
                self.validator_filter_spec = [self.validator_filter_spec]
            for v_f in self.validator_filter_spec:
                if callable(v_f):
                    value = v_f(value, self.name)
                else:
                    value = getattr(self, v_f)(value)
                
        return value

    def positive(self, value):
        if value < 0:
            raise ValidationError("Parameter '%s' must be a positive number." % self.name)
        return value
        
    def negative(self, value):
        if value > 0:
            raise ValidationError("Parameter '%s' must be a negative number." % self.name)
        return value

    def strip(self, value):
        if value is None: return None
        return value.strip()
        
    def str_to_int(self, value):
        if not value: 
            return None
        try:
            return int(value.strip())
        except ValueError:
            raise ValidationError("Parameter '%s' must be a number." % self.name)
    
    def str_to_bool(self, value):
        if value is None or value == '':
            return None
        return not (value.lower() == 'false' or value == '0')

    def iso_date(self, value):
        if not value: return None
        try:
            return datetime.datetime.strptime(value, '%Y-%m-%d')
        except ValueError:
            raise ValidationError("Parameter '%s' must be a valid date." % self.name)

    def iso_datetime(self, value):
        if not value: return None
        try:
            return datetime.datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                return datetime.datetime.strptime(value, '%Y-%m-%d')
            except ValueError:
                raise ValidationError("Parameter '%s' must be a valid date." % self.name)

    def decimal(self, value):
        return Decimal(str(value)) if isinstance(value, float) else Decimal(value)

    def uuid(self, value):
        uuid_re = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.I)
        if not uuid_re.match(value):
            raise ValidationError("Parameter '%s' must be a UUID." % self.name)
        return value.lower()
        
    def random_uuid(self, value):
        value = self.uuid(value)
        if value.startswith('00000000-0000') or value.endswith('000000000000'):
            raise ValidationError("Parameter '%s' must be a Type4 (i.e. Random) UUID." % self.name)
        return value.lower()

    def mex_local_phone(self, value):
        if not re.match(r'^[0-9]{10}$', value):
            raise ValidationError("Parameter '%s' must be a 10-digit MX local phone number (no spaces)." % self.name)
        if value.startswith('0'):
            raise ValidationError("Parameter '%s' cannot start with 0." % self.name)
        return value
        
    def e123_intl_phone(self, value):
        if not re.match(r'^\+[0-9]{7,15}$', value):
            raise ValidationError("Parameter '%s' must be in E.123 international format (no spaces)." % self.name)
        return value
    
    def e123_intl_phone_accept_mex_local(self, value):
        if re.match(r'^[0-9]{10}$', value):
            return '+52' + value
        if not re.match(r'^\+[0-9]{7,15}$', value):
            raise ValidationError("Parameter '%s' must be in E.123 international format (no spaces)." % self.name)
        return value
        
    def hex(self, value):
        if not value: return None
        if not re.match(r'^[A-F0-9]*$', value, re.I) or len(value) % 2 == 1:
            raise ValidationError("Parameter '%s' is not a valid hex-encoded string." % (self.name))
        return value 

    def email(self, value):
        if not value: return None
        if not re.match(r'^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,6}$', value, re.I):
            raise ValidationError("Parameter '%s' is not a valid email." % (self.name))
        return value
        
    def emails(self, value):
        '''Whitespace-separated emails'''
        if not value: return None
        value = sorted(set([v.lower() for v in value.split()]))
        for v in value:
            if not re.match(r'^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,6}$', v, re.I):
                raise ValidationError("Parameter '%s' contains invalid email '%s'." % (self.name, v))
        return '\n'.join(value)


if __name__ == "__main__":
    def must_be_foo(value, name):
        if value != 'foo':
            raise ValidationError("Parameter '%s' must equal 'foo'." % name) 
        return value
    
    P = ParamSpec
    params_spec = [
            P('sender_name', 's'),
            P('sender_phone_number', 's', 'e123_intl_phone'),
            P('beneficiary_name', 's', default=''),
            P('beneficiary_phone_number', 's', 'e123_intl_phone_accept_mex_local', default=''),
            P('billing_reference', 's', 'uuid'),
            P('billing_reference_parity', 'i'),
            P('billing_amount_mxn', 'f', 'positive decimal'.split()),
            P('merchant_fee_usd', 'f', 'positive', default=Decimal(0)),
            P('quote_id', 's'),
            P('marklar', 's', must_be_foo, default=None)
        ]

    params = {
        'sender_name': 'Herman Ryan',
        'sender_phone_number': '+141570293',
        #'beneficiary_phone_number': '1415293',
        'billing_reference': '7ae958be-ff2e-11e1-9f11-442a60fb605e',
        'billing_reference_parity': 0,
        'billing_amount_mxn': 2,
        'merchant_fee_usd': 3,
        'quote_id': 'hello',
        #'marklar': 'not foo',
    }
    print params
    v = validate_dict(params, params_spec)
    import simplejson
    print simplejson.dumps(v, indent=1)
