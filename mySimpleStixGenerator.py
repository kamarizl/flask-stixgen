#!/usr/bin/env python
#
# this is quick/dirty script to generate simple/uncomplete stix package.
#
# reference:
#   - https://stixproject.github.io/documentation/idioms/
#

from stix.core import STIXPackage, STIXHeader
from mixbox.idgen import set_id_namespace
from mixbox.namespaces import Namespace
from stix.indicator import Indicator
from cybox.objects.file_object import File
from cybox.common import Hash
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.uri_object import URI
from cybox.objects.email_message_object import EmailMessage, EmailHeader
import warnings


stixTitle = "Ransomware"
stixDescription = "Description for this stix package"
file_hashes = []
filenames = []
ip_addresses = []
urls = []
email_subjects = []
email_sender = []
domain = ['www.google.com.lol']

iocs = {
    'title': stixTitle,
    'desc': stixDescription,
    'hash': file_hashes,
    'fname': filenames,
    'ips': ip_addresses,
    'urls': urls,
    'subject': email_subjects,
    'senders': email_sender,
    'domains': domain
}

# disable warning 'The use of this field has been deprecated' - STIXHeader()
warnings.filterwarnings("ignore")

NAMESPACE = Namespace("http://bimb.com/stix", "bimb")
set_id_namespace(NAMESPACE)


def main(iocs=iocs):

    stix_header = STIXHeader(title=iocs['title'], description=iocs['desc'],
                             package_intents=["Indicators - Watchlist"])

    stix_package = STIXPackage(stix_header=stix_header)

    # add indicator - file hash
    if iocs.get('hash'):
        indicator_file_hash = Indicator(title="Malicious File")
        indicator_file_hash.add_indicator_type("File Hash Watchlist")
        for file_hash in iocs['hash']:
            file_object = File()
            file_object.add_hash(Hash(file_hash))
            file_object.hashes[0].simple_hash_value.condition = "Equals"
            file_object.hashes[0].type_.condition = "Equals"
            indicator_file_hash.add_observable(file_object)
        stix_package.add_indicator(indicator_file_hash)

    # add indicator - file name
    if iocs.get('fname'):
        indicator_filename = Indicator(title="Malicious File Name")
        for file in iocs['fname']:
            file_object = File()
            file_object.file_name = file
            indicator_filename.add_observable(file_object)
        stix_package.add_indicator(indicator_filename)

    # add indicator - ip address
    if iocs.get('ips'):
        indicator_ip = Indicator(title="Malicious IP Address")
        indicator_ip.add_indicator_type("IP Watchlist")
        for ip in iocs['ips']:
            addr = Address(address_value=ip, category=Address.CAT_IPV4)
            addr.condition = "Equals"
            indicator_ip.add_observable(addr)
        stix_package.add_indicator(indicator_ip)

    # add indicator - domains
    if iocs.get('domains'):
        indicator_domains = Indicator(title="Malicious Domains")
        indicator_domains.add_indicator_type("Domain Watchlist")
        for domain in iocs['domains']:
            domain_name = DomainName()
            domain_name.value = domain
            indicator_domains.add_observable(domain_name)
        stix_package.add_indicator(indicator_domains)        
    
    # add indicator - url
    if iocs.get('urls'):
        indicator_url = Indicator(title='Malicious URL')
        indicator_url.add_indicator_type("URL Watchlist")
        for _url in iocs['urls']:
            url = URI()
            url.value = _url
            url.type_ = URI.TYPE_URL
            url.value.condition = "Equals"
            # url.value.condition = "Contains"
            indicator_url.add_observable(url)
        stix_package.add_indicator(indicator_url)

    # add indicator - email subject
    if iocs.get('subject'):
        indicator_email_subject = Indicator(title='Malicious E-mail Subject')
        indicator_email_subject.add_indicator_type("Malicious E-mail")
        for subject in iocs['subject']:
            email_subject_object = EmailMessage()
            email_subject_object.header = EmailHeader()
            email_subject_object.header.subject = subject
            email_subject_object.header.subject.condition = "StartsWith"
            indicator_email_subject.add_observable(email_subject_object)
        stix_package.add_indicator(indicator_email_subject)

    # add indicator - email sender
    if iocs.get('senders'):
        indicator_email_sender = Indicator(title='Malicious E-mail Sender')
        indicator_email_sender.add_indicator_type("Malicious E-mail")
        for sender in iocs['senders']:
            email_sender_object = EmailMessage()
            email_sender_object.header = EmailHeader()
            email_sender_object.header.sender = sender
            email_sender_object.header.sender.condition = "Equals"
            indicator_email_sender.add_observable(email_sender_object)
        stix_package.add_indicator(indicator_email_sender)


    # print(stix_package.to_xml(encoding=None))
    # print(type(stix_package.to_xml(encoding=None)))
    return stix_package.to_xml(encoding=None)
    

if __name__ == '__main__':
    # stix_output = main()
    # print(stix_output)
    main()
    
