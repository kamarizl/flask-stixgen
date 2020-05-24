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
from cybox.objects.uri_object import URI
from cybox.objects.email_message_object import EmailMessage, EmailHeader
import warnings


stixTitle = "Ransomware"
stixDescription = "Description for this stix package"
file_hashes = ['9F98609DB66E171E9E55110DEB7DA553']
filenames = []
ip_addresses = ['127.0.0.127']
urls = []
email_subjects = []

# disable warning 'The use of this field has been deprecated' - STIXHeader()
warnings.filterwarnings("ignore")

NAMESPACE = Namespace("http://bimb.com/stix", "bimb")
set_id_namespace(NAMESPACE)


def main():
    stix_header = STIXHeader(title=stixTitle, description=stixDescription,
                             package_intents=["Indicators - Watchlist"])

    stix_package = STIXPackage(stix_header=stix_header)

    # add indicator - file hash
    if file_hashes:
        indicator_file_hash = Indicator(title="Malicious File")
        indicator_file_hash.add_indicator_type("File Hash Watchlist")
        for file_hash in file_hashes:
            file_object = File()
            file_object.add_hash(Hash(file_hash))
            file_object.hashes[0].simple_hash_value.condition = "Equals"
            file_object.hashes[0].type_.condition = "Equals"
            indicator_file_hash.add_observable(file_object)
        stix_package.add_indicator(indicator_file_hash)

    # add indicator - file name
    if filenames:
        indicator_filename = Indicator(title="Malicious File Name")
        for file in filenames:
            file_object = File()
            file_object.file_name = file
            indicator_filename.add_observable(file_object)
        stix_package.add_indicator(indicator_filename)

    # add indicator - ip address
    if ip_addresses:
        indicator_ip = Indicator(title="Malicious IP Address")
        indicator_ip.add_indicator_type("IP Watchlist")
        for ip in ip_addresses:
            addr = Address(address_value=ip, category=Address.CAT_IPV4)
            addr.condition = "Equals"
            indicator_ip.add_observable(addr)
        stix_package.add_indicator(indicator_ip)

    # add indicator - url
    if urls:
        indicator_url = Indicator(title='Malicious URL')
        indicator_url.add_indicator_type("URL Watchlist")
        for _url in urls:
            url = URI()
            url.value = _url
            url.type_ = URI.TYPE_URL
            url.value.condition = "Equals"
            indicator_url.add_observable(url)
        stix_package.add_indicator(indicator_url)

    # add indicator - email subject
    if email_subjects:
        indicator_email_subject = Indicator(title='Malicious E-mail Subject')
        indicator_email_subject.add_indicator_type("Malicious E-mail")
        for subject in email_subjects:
            email_subject_object = EmailMessage()
            email_subject_object.header = EmailHeader()
            email_subject_object.header.subject = subject
            email_subject_object.header.subject.condition = "StartsWith"
            indicator_email_subject.add_observable(email_subject_object)
        stix_package.add_indicator(indicator_email_subject)

    # print(stix_package.to_xml(encoding=None))
    return stix_package.to_xml(encoding=None)


if __name__ == '__main__':
    main()
