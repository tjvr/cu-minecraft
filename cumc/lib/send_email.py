from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
import smtplib

import os
import sys



DEFAULT_FROM = "CU Minecraft <noreply@example.com>" # TODO config
DEFAULT_RCPT = "Minecraft Admins <admins@example.com>" # TODO config


def make_message(from_address, to_address, subject):
    msg = MIMEMultipart()
    msg['From'] = from_address
    msg['To'] = to_address
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject
    return msg


def email(contents, from_=DEFAULT_FROM, to=DEFAULT_RCPT, subject="[minecraft]",
        reply_to=None):
    msg = make_message(from_, to, subject)
    if reply_to:
        msg['Reply-To'] = reply_to
    msg.attach(MIMEText(contents))
    sendmail(msg, from_, to)


def email_file(from_address, to_address, contents, file_contents, filename):
    msg = make_message(from_address, to_address, "Mailing {}".format(filename))

    msg.attach(MIMEText(contents))

    part = MIMEBase('application', "octet-stream")
    part.set_payload(open(filename, "rb").read())
    Encoders.encode_base64(part)
    part.add_header('Content-Disposition',
                    'attachment; filename="%s"' % filename)
    msg.attach(part)

    sendmail(msg, from_address, to_address)


def sendmail(msg, from_address, to_address):
    composed = msg.as_string()
    s = smtplib.SMTP('localhost')
    #s.set_debuglevel(1)
    s.sendmail(from_address, [to_address], composed)
    s.quit()

