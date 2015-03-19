import json

from neutron.openstack.common import log as logging
from oslo.config import cfg
import requests
from requests import exceptions as req_exc
from neutron.extensions.loadbalancer import IAFTokenError, VIPAlreadyExistsInDNSException


CONF = cfg.CONF

LOG = logging.getLogger(__name__)

CONF.register_group(cfg.OptGroup(name='dns', title='UDNS Configuration'))

UDNS_OPTS = [
    cfg.StrOpt("udns_api_host", default="http://udns-web-1.stratus.phx.qa.ebay.com"),
    cfg.StrOpt("udns_zone", default="dev:stratus.dev.ebay.com,ext:ebaystratus.com"),
    cfg.StrOpt("udns_view", default="dev:ebay-cloud,ext:public"),
    cfg.StrOpt("udns_user", default="_STRATUS_IAAS"),
    cfg.StrOpt("udns_password", default="xxxx")
]
cfg.CONF.register_opts(UDNS_OPTS, group='dns')

class UdnsClient(object):


    def __init__(self):
        self.iaf_token = self._get_iaf_token()

    def _get_APTR_rec_url(self, dns_zone, view, action):
        return "{0}/dns/views/{1}/zones/{2}/recordtypes/aptr/actions/{3}" \
            .format(CONF['dns'].get('udns_api_host'),
                    view,
                    dns_zone,
                    action)

    def _get_A_rec_url(self, view, zone, hostname):
        return "{0}/dns/views/{1}/zones/{2}/recordtypes/a/records/{3}" \
            .format(CONF['dns'].get('udns_api_host'),
                    view,
                    zone,
                    hostname)

    def _get_PTR_rec_url(self, view, zone, resource):
        return "{0}/dns/views/{1}/zones/{2}/recordtypes/ptr/records/{3}" \
            .format(CONF['dns'].get('udns_api_host'),
                    view,
                    zone,
                    resource)

    def _get_A_record(self, view, zone, hostname):
        response = requests.get(self._get_A_rec_url(view, zone, hostname))

        # check if the status code is 404, which means A record does not exists
        if response.status_code == 404:
            return None

        # if status code is > 400 and not 404 then raise an exception.
        elif response.status_code >= 400:
            response.raise_for_status()

        # else return the ip address
        else:
            response_body = json.loads(response.content)
            return response_body['ipAddresses']

    def get_PTR_record(self, cos, ip_address):
        reverse_zone, resource_name = self._get_reverse_zone_name_and_resource_name(ip_address)
        response = requests.get(self._get_PTR_rec_url(self.view(cos), reverse_zone, resource_name))

        # check if the status code is 404, which means PTR record does not exists
        if response.status_code == 404:
            return None

        # if status code is > 400 and not 404 then raise an exception.
        elif response.status_code >= 400:
            response.raise_for_status()

         # else return the fqdn name
        else:
            response_body = json.loads(response.content)
            return response_body['fullyQualifiedName']

    def _get_reverse_zone_name_and_resource_name(self, ip_address):
        ip_address_elements = ip_address.split('.')
        return (ip_address_elements[2] + "." + ip_address_elements[1] + "." + ip_address_elements[0] + ".in-addr.arpa",
                ip_address_elements[3])


    def _a_record_already_exists(self, view, zone, hostname):
        try:
            ip_addresses = self._get_A_record(view, zone, hostname)
        except req_exc.HTTPError as http_exec:
            LOG.error('an error in getting A record', http_exec)
            return True

        if ip_addresses is not None:
            return True
        else:
            return False

    def create_A_PTR_record(self, address, hostname, cos):
        return self._A_PTR_record(address, hostname, cos, action='update')

    def delete_A_PTR_record(self, address, hostname, cos):
        return self._A_PTR_record(address, hostname, cos, action='delete')

    def _A_PTR_record(self, address, hostname, cos, action):

        dns_zone = self.zone(cos)
        view = self.view(cos)

        if action == 'update' and self._a_record_already_exists(view, dns_zone, hostname):
            raise VIPAlreadyExistsInDNSException(vip_name=hostname)

        if not address:
            LOG.info('ip is None')
            return None
        elif not hostname:
            LOG.info('hostname is None')
            return None

        headers = {
            "Authorization": "IAF " + self.iaf_token,
            "Content-Type": "application/json",
            "FORCE_OPERATION": "true"
        }

        fqdn = hostname
        if action == 'update':
            fqdn = hostname + '.' + dns_zone

        body = {"fqdn": "%s" % fqdn,
                "ipAddress": "%s" % address
                }

        LOG.info('udns APTR request payload [%s]' % (body))

        url = self._get_APTR_rec_url(dns_zone, view, action)
        response = requests.post(url,
                                 data=json.dumps(body),
                                 headers=headers)

        str_action = 'created' if action == 'update' else 'deleted'

        if response.status_code == 200:
            LOG.info('A & PTR record %s' % str_action)
            return fqdn
        else:
            LOG.error('Error %s A & PTR record. Error: %s' %
                      (str_action, response.content))
            LOG.error('Url %s' % url)
            LOG.error('Body %s' % body)
            return None

    def _get_iaf_token(self):
        """
        Generates an IAF token using the UDNS end point. If token is generated successfully, it raises an IAFTokenError
        :return: generated iaf token
        :exception: IAFTokenError
        """
        headers = {
            "X-Password": CONF['dns'].udns_password
        }
        url = "{0}/user/{1}/token".format(CONF['dns'].udns_api_host, CONF['dns'].udns_user)
        response = requests.get(url, headers=headers)
        if response.status_code == 200:

            response_data = response.json()
            if 'token' in response_data:
                return response_data['token']
        raise IAFTokenError()

    def zone(self, cos):
        if cos is None:
            return None

        for network_str in CONF['dns'].get('udns_zone').split(','):
            co, sp, network = network_str.partition(':')
            if co == cos:
                return network
        return None

    def view(self, cos):
        if cos is None:
            return None

        for network_str in CONF['dns'].get('udns_view').split(','):
            co, sp, network = network_str.partition(':')
            if co == cos:
                return network
        return None
