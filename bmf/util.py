#!/usr/bin/python
# -*- coding: utf-8 -*-

def dumps(*arg, **kwargs):
    import datetime
    import simplejson
    def serialize(obj):
        if isinstance(obj, datetime.date):
            return str(obj)
        elif isinstance(obj, datetime.datetime):
            return str(obj)
        raise TypeError
    kwargs['indent'] = 1 
    kwargs['default'] = serialize
    return simplejson.dumps(*arg, **kwargs) + '\n'


def project(d, fields):
    return dict([(k,v) for k,v in d.iteritems() if k in fields])


def ms():
    import time
    return int(time.time() * 1000)


def strip_accents(s):
    import unicodedata
    if isinstance(s, unicode):
        return ''.join(c for c in unicodedata.normalize('NFD', s)
                         if unicodedata.category(c) != 'Mn')
    else:
        return s


def random_text(length):
    import os
    return os.urandom(length).encode('base64')[:length]


def uuid():     
    import uuid as uuid_lib
    return str(uuid_lib.uuid4())


def is_uuid(s):
    import re
    return isinstance(s, (unicode, str)) and bool(re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', s, re.I))


def datetime_to_ms(dt, timezone=None):
    import calendar
    import dateutil.zoneinfo
    if timezone:
        dt = dt.replace(tzinfo=dateutil.zoneinfo.gettz(timezone))
    return calendar.timegm(dt.utctimetuple()) * 1000 + (dt.microsecond / 1000)


def ms_to_datetime(unixtime_ms, timezone='UTC'):
    import datetime
    import dateutil.zoneinfo
    tz = dateutil.zoneinfo.gettz(timezone)
    return datetime.datetime.fromtimestamp(unixtime_ms/1000.0, tz)


def parse_datetime_to_ms(datetime_formatted, timezone='UTC'):
    import dateutil.parser
    dt = dateutil.parser.parse(datetime_formatted)
    return datetime_to_ms(dt, timezone if not dt.tzinfo else None)


def parse_datetime(datetime_formatted, timezone='UTC'):
    return ms_to_datetime(parse_datetime_to_ms(datetime_formatted, timezone), timezone)


def format_ms(unixtime_ms=None, format='%Y-%m-%d %H:%M:%S', timezone='UTC'):
    if not unixtime_ms:
        unixtime_ms = ms()
    return ms_to_datetime(unixtime_ms, timezone).strftime(format)


def days_in_month(year, month):
    import calendar
    return calendar.monthrange(year, month)[1]


def end_of_day_ms(unixtime_ms=None, timezone='UTC'):
    from datetime import timedelta
    if not unixtime_ms:
        unixtime_ms = ms()
    now = ms_to_datetime(unixtime_ms, timezone)
    tomorrow = now.date() + timedelta(days=1)
    return parse_datetime_to_ms(str(tomorrow), timezone)


def start_of_day_ms(unixtime_ms=None, timezone='UTC'):
    if not unixtime_ms:
        unixtime_ms = ms()
    now = ms_to_datetime(unixtime_ms, timezone)
    return parse_datetime_to_ms(str(now.date()), timezone)
    

def get_day_bounds_ms(day, timezone='UTC'):
    from dateutil.relativedelta import relativedelta
    import datetime
    assert type(day) == datetime.date
    day_start = parse_datetime(str(day), timezone)
    day_end = day_start + relativedelta(days=1)
    return datetime_to_ms(day_start), datetime_to_ms(day_end)-1


def never_cache():
    from bottle import response
    response.add_header('Pragma', 'no-cache')
    response.add_header('Cache-Control', 'no-cache')
    response.set_header('Expires', '-1')


def generate_pin_number(length=12):
    # see knuth impl in http://en.wikipedia.org/wiki/Linear_congruential_generator
    from random import SystemRandom
    rng = SystemRandom()
    pin = rng.choice('123456789') + ''.join([rng.choice('0123456789') for i in range(length - 2)]) 
    parity = ((int(pin) * 6364136223846793005L + 1442695040888963407L) % (2**64)) % 10
    return pin + str(parity)


def send_gmail(username, password, sender, recipients, subject, body, files=[]):
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email.Utils import COMMASPACE, formatdate
    from email import Encoders
    import smtplib
    
    if not recipients:
        return
    if not isinstance(recipients, list):
        recipients = [recipients]

    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = COMMASPACE.join(recipients)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject
    msg.attach(MIMEText(body.encode('utf-8'), 'plain', 'UTF-8'))
    
    for filename, content, mime_type in files:
        part = MIMEBase('application', mime_type)
        part.set_payload(content)
        Encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"' % filename)
        msg.attach(part)

    smtp = smtplib.SMTP('smtp.gmail.com', 587)
    smtp.ehlo()
    smtp.starttls()
    smtp.ehlo()
    smtp.login(username, password)
    smtp.sendmail(sender, recipients, msg.as_string())
    smtp.close()


def initialize_2d(cols, rows, value=None):
    return [[value for _ in range(cols)] for _ in range(rows)]


def rows_to_csv(rows, delimiter=None):
    from cStringIO import StringIO
    import csv
    dialect='excel'
    if delimiter:
        class AlternateDialect(csv.excel): pass
        AlternateDialect.delimiter = delimiter
        dialect = AlternateDialect
    csv_out = StringIO()
    csv_writer = csv.writer(csv_out, dialect=dialect)
    csv_writer.writerows(rows)
    return csv_out.getvalue()


def rows_to_xlsx(data):
    """
    Can pass in either a 2D array ... or a list of dicts with the keys "rows"
    and "name" that will be turned into individual worksheets.
    """
    from pyexcelerate import Workbook
    import cStringIO
    import datetime
    from decimal import Decimal
    if not data:
        sheets = [{'rows': [[]]}]
    elif not isinstance(data[0], dict):
        sheets = [{'rows': data}]
    else:
        sheets = data
    wb = Workbook()
    for j, sheet in enumerate(sheets):
        def fixup_value(v):
            if v is None:
                return ''
            if isinstance(v, datetime.datetime):
                return str(v)
            if isinstance(v, Decimal):
                return float(v)
            if isinstance(v, bool):
                return int(v)
            return v
        rows = [map(fixup_value, row) for row in sheet['rows']]
        wb.new_sheet(sheet.get('name', 'Sheet%d' % (j+1)), data=rows)
    f = cStringIO.StringIO()
    wb._save(f)
    return f.getvalue()


def xlsx_to_rows(filedata, filename='', date_columns=[]):
    import xlrd
    import hashlib
    import tempfile
    import os.path
    import uuid
    import os
    import datetime
    
    date_parse_start = 1
    if date_columns:
        date_parse_start = 0
    
    temp = os.path.join(tempfile.gettempdir(), 'xlsx_to_rows.tmp.%s.xlsx' % uuid.uuid4())
    try:
        f = file(temp, 'w')
        sha1 = hashlib.sha1(filedata).hexdigest()
        f.write(filedata)
        f.close()
        book = xlrd.open_workbook(temp)
        sheet = book.sheet_by_index(0)
        rows = [[c.value for c in sheet.row(i)] for i in xrange(sheet.nrows)]
        # ugly hack for bullshit excel dates
        if rows and rows[0]:
            for i, header in enumerate(rows[0]):
                if unicode(header).endswith('_date') or header == 'date':
                    date_columns.append(i)
            for c in set(date_columns):
                for r in xrange(date_parse_start, len(rows)):
                    try:
                        if isinstance(rows[r][c], (int, float)):
                            d = xlrd.xldate_as_tuple(rows[r][c], book.datemode)
                            rows[r][c] = str(datetime.datetime(*d).date())
                    except:
                        pass
        return {'filename': filename, 'data': rows, 'sha1': sha1}
    finally:
        try:
            os.remove(temp)
        except:
            pass


class FtpResume(object):
    def __init__(self, url, debuglevel=0):
        import urlparse
        parts = urlparse.urlparse(url)
        self.hostname = parts.hostname
        self.username = parts.username
        self.password = parts.password
        self.tls = parts.scheme.lower() == 'ftps'
        self.path = parts.path
        self.ftp = None
        self.debuglevel = debuglevel
        
    def connect(self):
        import ftplib
        if self.ftp:
            try:
                self.ftp.close()
            except:
                pass
        self.ftp = None
        self.ftp = ftplib.FTP_TLS(self.hostname) if self.tls else ftplib.FTP(self.hostname)
        self.ftp.set_debuglevel(self.debuglevel)
        self.ftp.login(self.username, self.password)
        if self.path:
            self.ftp.cwd(self.path)
    
    def nlst(self, pattern):
        return self.ftp.nlst(pattern)
        
    def upload(self, filename, filedata):
        from cStringIO import StringIO
        self.ftp.storbinary('STOR %s' % filename, StringIO(filedata))
    
    def download(self, filename):
        from cStringIO import StringIO
        downloaded = StringIO()
        self.ftp.retrbinary('RETR %s' % filename, downloaded.write)
        return downloaded.getvalue()
        
    def download_with_retry(self, filename, max_attempts=5):
        from cStringIO import StringIO
        self.connect()
        downloaded = StringIO()
        file_size = self.ftp.size(filename)
        while file_size != len(downloaded.getvalue()):
            try:
                if downloaded.tell() != 0:
                    self.ftp.retrbinary('RETR %s' % filename, downloaded.write, len(downloaded.getvalue()))
                else:
                    self.ftp.retrbinary('RETR %s' % filename, downloaded.write)
            except Exception:
                if max_attempts == 0:
                    break
                else:
                    self.connect()
                    max_attempts -= 1
        return downloaded.getvalue()

def download_via_ftp(url, filename):
    ftp = FtpResume(url)
    ftp.connect()
    return ftp.download(filename)

def upload_via_ftp(url, filename, filedata, debuglevel=0):
    ftp = FtpResume(url, debuglevel=debuglevel)
    ftp.connect()
    ftp.upload(filename, filedata)


def find_subdir_in_parent(filepath, subdir, levels=2):
    from os.path import exists, join, dirname, abspath
    filepath = dirname(abspath(filepath))
    for i in xrange(levels):
        conf_dir = join(dirname(filepath), 'conf')
        if exists(conf_dir):
            return conf_dir
        filepath = dirname(filepath)
    raise Exception("could not find subdir '%s'" % subdir)


def recursive_update(original, additional):
    if not additional:
        return
    for key,value in additional.iteritems():
        if key in original and isinstance(value, dict):
            recursive_update(original[key], value)
        else:
            original[key] = value


def load_config(conf_dir):
    import yaml
    import bunch
    from os.path import exists, join
    config = yaml.load(file(join(conf_dir, 'defaults.yaml')))
    if exists(join(conf_dir, 'local.yaml')):
        recursive_update(config, yaml.load(file(join(conf_dir, 'local.yaml'))))
    return bunch.bunchify(config)


def signalproof_sleep(duration):
    """
    Gunicorn gracefully restarts a worker by sending it SIGQUIT every second.
    Python's time.sleep() ends prematurely upon signal delivery.  This function
    runs time.sleep() in a loop until the requested duration actually elapses.
    """
    import time
    end = time.time() + duration
    while True:
        time.sleep(max(0, end - time.time()))
        if end - time.time() < 0.01:
            break


def mysql_utf8(s):
    ''' Makes text safe for MySQL by removing 4-byte unicode chars '''
    import re
    try:
        highpoints = re.compile(u'[\U00010000-\U0010ffff]')
    except re.error:
        # UCS-2 build
        highpoints = re.compile(u'[\uD800-\uDBFF][\uDC00-\uDFFF]')
    return highpoints.sub(u'', s)


def aes_encrypt(plaintext, password):
    # aes-128 cbc pkcs5 padding
    from Crypto.Cipher import AES
    from Crypto import Random
    from Crypto.Hash import SHA256
    padding = AES.block_size - len(plaintext) % AES.block_size
    plaintext_padded = plaintext + chr(padding) * padding
    iv = Random.new().read(AES.block_size)
    key = SHA256.new(password).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(plaintext_padded)


def aes_decrypt(iv_ciphertext, password):
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    key = SHA256.new(password).digest()[:16]
    iv, ciphertext = iv_ciphertext[:16], iv_ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_padded = cipher.decrypt(ciphertext)
    c = plaintext_padded[-1]
    if plaintext_padded.endswith(c * ord(c)):
        return plaintext_padded[0:-ord(c)]


class TicketMinter:
    def __init__(self, secret, grace_time_sec=60*15, realm='DEFAULT'):
        import hashlib
        from Crypto.Cipher import AES
        self.cipher = AES.new(hashlib.sha256(secret).digest())
        self.grace_time_sec = grace_time_sec
        self.realm = realm

    def mint(self):
        import time
        import struct
        plaintext = struct.pack('!d', time.time()) + self.realm
        x = self.cipher.encrypt(plaintext).encode('hex')
        return '-'.join((x[:8], x[8:12], x[12:16], x[16:20], x[20:]))

    def verify(self, ticket):
        import time
        import struct
        try:
            ciphertext = (''.join(ticket.split('-'))).decode('hex')
            if len(ciphertext) != self.cipher.block_size:
                return False
            plaintext = self.cipher.decrypt(ciphertext)
            mint_time = struct.unpack('!d', plaintext[:8])[0]
            return plaintext[8:] == self.realm and mint_time > (time.time() - self.grace_time_sec)
        except:
            return False
                

class AttrDict(dict):
    """A dictionary with attribute-style access. It maps attribute access to
    the real dictionary.  """
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)

    def __getstate__(self):
        return self.__dict__.items()

    def __setstate__(self, items):
        for key, val in items:
            self.__dict__[key] = val

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, dict.__repr__(self))

    def __setitem__(self, key, value):
        return super(AttrDict, self).__setitem__(key, value)

    def __getitem__(self, name):
        return super(AttrDict, self).__getitem__(name)

    def __delitem__(self, name):
        return super(AttrDict, self).__delitem__(name)

    __getattr__ = __getitem__
    __setattr__ = __setitem__

    def copy(self):
        return AttrDict(self)
    
    def _asdict(self):
        """Method used by simplejson."""
        return self