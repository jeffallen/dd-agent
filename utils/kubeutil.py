# (C) Datadog, Inc. 2015-2016
# All rights reserved
# Licensed under Simplified BSD License (see LICENSE)

# stdlib
from collections import defaultdict
import logging
import os
import socket
import struct
from urlparse import urljoin

# project
from util import check_yaml
from utils.checkfiles import get_conf_path
from utils.http import retrieve_json
from utils.singleton import Singleton

import requests

log = logging.getLogger('collector')

KUBERNETES_CHECK_NAME = 'kubernetes'


def is_k8s():
    return 'KUBERNETES_PORT' in os.environ


class KubeUtil():
    __metaclass__ = Singleton

    DEFAULT_METHOD = 'http'
    METRICS_PATH = '/api/v1.3/subcontainers/'
    PODS_LIST_PATH = '/pods/'
    DEFAULT_CADVISOR_PORT = 4194
    DEFAULT_KUBELET_PORT = 10255
    DEFAULT_MASTER_PORT = 8080
    DEFAULT_MASTER_NAME = 'kubernetes'  # DNS name to reach the master from a pod.
    CA_CRT_PATH = '/run/secrets/kubernetes.io/serviceaccount/ca.crt'
    AUTH_TOKEN_PATH = '/run/secrets/kubernetes.io/serviceaccount/token'

    POD_NAME_LABEL = "io.kubernetes.pod.name"
    NAMESPACE_LABEL = "io.kubernetes.pod.namespace"

    def __init__(self):
        try:
            config_file_path = get_conf_path(KUBERNETES_CHECK_NAME)
            check_config = check_yaml(config_file_path)
            instance = check_config['instances'][0]
        # kubernetes.yaml was not found
        except IOError as ex:
            log.error(ex.message)
            instance = {}
        except Exception:
            log.error('Kubernetes configuration file is invalid. '
                      'Trying connecting to kubelet with default settings anyway...')
            instance = {}

        self.method = instance.get('method', KubeUtil.DEFAULT_METHOD)
        self.host = instance.get("host") or self._get_default_router()
        self.host_ip = None  # lazy initialization
        self.host_name = os.environ.get('HOSTNAME')

        self.cadvisor_port = instance.get('port', KubeUtil.DEFAULT_CADVISOR_PORT)
        self.kubelet_port = instance.get('kubelet_port', KubeUtil.DEFAULT_KUBELET_PORT)

        self.kubelet_api_url = '%s://%s:%d' % (self.method, self.host, self.kubelet_port)
        self.cadvisor_url = '%s://%s:%d' % (self.method, self.host, self.cadvisor_port)
        self.kubernetes_api_url = 'https://%s/api/v1' % self.DEFAULT_MASTER_NAME

        self.metrics_url = urljoin(self.cadvisor_url, KubeUtil.METRICS_PATH)
        self.pods_list_url = urljoin(self.kubelet_api_url, KubeUtil.PODS_LIST_PATH)
        self.kube_health_url = urljoin(self.kubelet_api_url, 'healthz')

    def get_kube_labels(self, excluded_keys=None):
        pods = self.retrieve_pods_list()
        return self.extract_kube_labels(pods, excluded_keys=excluded_keys)

    def extract_kube_labels(self, pods_list, excluded_keys=None):
        """
        Extract labels from a list of pods coming from
        the kubelet API.
        """
        excluded_keys = excluded_keys or []
        kube_labels = defaultdict(list)
        pod_items = pods_list.get("items") or []
        for pod in pod_items:
            metadata = pod.get("metadata", {})
            name = metadata.get("name")
            namespace = metadata.get("namespace")
            labels = metadata.get("labels")
            if name and labels and namespace:
                key = "%s/%s" % (namespace, name)

                for k,v in labels.iteritems():
                    if k in excluded_keys:
                        continue

                    kube_labels[key].append(u"kube_%s:%s" % (k, v))

        return kube_labels

    def extract_uids(self, pods_list):
        """
        Exctract uids from a list of pods coming from the kubelet API.
        """
        uids = []
        pods = pods_list.get("items") or []
        for p in pods:
            uid = p.get('metadata', {}).get('uid')
            if uid is not None:
                uids.append(uid)
        return uids

    def retrieve_pods_list(self):
        return retrieve_json(self.pods_list_url)

    def filter_pods_list(self, pods_list, host_ip):
        """
        Filter out (in place) pods that are not running on the given host.
        """
        pod_items = pods_list.get('items') or []
        log.debug('Found {} pods to filter'.format(len(pod_items)))

        filtered_pods = []
        for pod in pod_items:
            status = pod.get('status', {})
            if status.get('hostIP') == host_ip:
                filtered_pods.append(pod)
        log.debug('Pods after filtering: {}'.format(len(filtered_pods)))

        pods_list['items'] = filtered_pods
        return pods_list

    def retrieve_json_auth(self, url, auth_token, timeout=10):
        """
        Kubernetes API requires authentication using a token available in
        every pod.

        We try to verify ssl certificate if available.
        """
        verify = self.CA_CRT_PATH if os.path.exists(self.CA_CRT_PATH) else False
        log.debug('ssl validation: {}'.format(verify))
        headers = {'Authorization': 'Bearer {}'.format(auth_token)}
        log.debug('HTTP headers: {}'.format(headers))
        r = requests.get(url, timeout=timeout, headers=headers, verify=verify)
        r.raise_for_status()
        return r.json()

    def get_host_ip(self):
        """
        The host ip address is different from the default router for the pod.
        We get it from the payload returned by the listing pods endpoints from
        kubelet or kuberentes API.
        """
        if self.host_ip is None:
            pod_items = self.retrieve_pods_list().get("items") or []
            for pod in pod_items:
                metadata = pod.get("metadata", {})
                name = metadata.get("name")
                if name == self.host_name:
                    status = pod.get('status', {})
                    self.host_ip = status.get('hostIP')
                    break
        return self.host_ip

    @classmethod
    def _get_default_router(cls):
        """
        Return the IP address of the default router for the pod.
        """
        try:
            with open('/proc/net/route') as f:
                for line in f.readlines():
                    fields = line.strip().split()
                    if fields[1] == '00000000':
                        return socket.inet_ntoa(struct.pack('<L', int(fields[2], 16)))
        except IOError, e:
            log.error('Unable to open /proc/net/route: %s', e)

        return None

    @classmethod
    def get_auth_token(cls):
        """
        Return a string containing the authorization token for the pod.
        """
        try:
            with open(cls.AUTH_TOKEN_PATH) as f:
                return f.read()
        except IOError as e:
            log.error('Unable to read token from {}: {}'.format(cls.AUTH_TOKEN_PATH, e))

        return None
