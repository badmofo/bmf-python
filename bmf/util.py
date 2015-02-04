
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


def random_text(n=None):
    import random, os
    if n is None:
        n = random.randint(0, 128)
    return os.urandom(n).encode('base64')[:n]


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
    import random
    pin = random.choice('123456789') + ''.join([random.choice('0123456789') for i in range(length - 2)]) 
    parity = ((int(pin) * 6364136223846793005L + 1442695040888963407L) % (2**64)) % 10
    return pin + str(parity)


def send_gmail(username, password, sender, recipients, subject, body, files=[]):
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email.Utils import COMMASPACE, formatdate
    from email import Encoders
    import smtplib
    assert type(recipients)==list

    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = COMMASPACE.join(recipients)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject
    msg.attach(MIMEText(body))
    
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

def gdata_spreadsheet_login(gmail_username, gmail_password):
    import gdata.spreadsheet.service
    client = gdata.spreadsheet.service.SpreadsheetsService()
    client.email = gmail_username
    client.password = gmail_password
    client.source = ''
    client.account_type = 'GOOGLE'
    client.ProgrammaticLogin()
    return client

def gdata_get_worksheet(gmail_username, gmail_password, spreadsheet_key, max_col, worksheet_id=None):
    import gdata.spreadsheet.service
    client = gdata_spreadsheet_login(gmail_username, gmail_password)
    if worksheet_id is None:
        worksheet_id = 'od6'
    cell_query = gdata.spreadsheet.service.CellQuery()
    cell_query['min-col'] = '1'
    cell_query['max-col'] = str(max_col)
    cell_query['min-row'] = '1'
    feed = client.GetCellsFeed(spreadsheet_key, worksheet_id, query=cell_query)
    max_row = max([int(entry.cell.row) for entry in feed.entry])
    if max_col is None:
        max_col = max([int(entry.cell.col) for entry in feed.entry])
    sheet = initialize_2d(max_col, max_row)
    for entry in feed.entry:
        text = entry.content.text
        text = text.decode('UTF-8').strip()
        row = int(entry.cell.row) - 1
        col  = int(entry.cell.col) - 1
        sheet[row][col] = text
    return sheet


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
        ws = wb.new_sheet(sheet.get('name', 'Sheet%d' % (j+1)), data=rows)
    f = cStringIO.StringIO()
    wb._save(f)
    return f.getvalue()


def upload_via_ftp(host, username, password, filename, filedata, directory, tls=False, debuglevel=0):
    import ftplib
    import cStringIO
    if tls:
        ftp = ftplib.FTP_TLS(host)
    else:
        ftp = ftplib.FTP(host)
    ftp.set_debuglevel(debuglevel)
    ftp.login(username, password)
    ftp.cwd(directory)
    ftp.storbinary('STOR %s' % filename, cStringIO.StringIO(filedata))


class FtpResume(object):
    def __init__(self, hostname, username, password, max_attempts=5):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.ftp = None
        self.max_attempts = max_attempts
        
    def connect(self, path=None):
        import ftplib
        if self.ftp:
            try:
                self.ftp.close()
            except:
                pass
        self.ftp = None
        self.ftp = ftplib.FTP(self.hostname)
        self.ftp.login(self.username, self.password)
        if path:
            self.ftp.cwd(path)
    
    def nlst(self, pattern):
        return self.ftp.nlst(pattern)
    
    def download(self, filename):
        import cStringIO
        downloaded = cStringIO.StringIO()
        ftp.retrbinary('RETR %s' % filename, downloaded.write)
        return downloaded.getvalue()
        
    def download_with_retry(self, filename):
        import cStringIO
        self.connect()
        downloaded = cStringIO.StringIO()
        file_size = self.ftp.size(filename)
        while file_size != len(downloaded.getvalue()):
            try:
                if downloaded.tell() != 0:
                    self.ftp.retrbinary('RETR %s' % filename, downloaded.write, len(downloaded.getvalue()))
                else:
                    self.ftp.retrbinary('RETR %s' % filename, downloaded.write)
            except Exception as myerror:
                if self.max_attempts != 0:
                    self.connect()
                    self.max_attempts -= 1
                else:
                    break
        return downloaded.getvalue()


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