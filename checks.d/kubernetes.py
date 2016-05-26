# (C) Datadog, Inc. 2010-2016
# All rights reserved
# Licensed under Simplified BSD License (see LICENSE)

"""kubernetes check
Collects metrics from cAdvisor instance
"""
# stdlib
from collections import defaultdict
from fnmatch import fnmatch
import numbers
import re
import time

# 3rd party
import requests
import simplejson as json

# project
from checks import AgentCheck
from config import _is_affirmative
from utils.kubeutil import KubeUtil

NAMESPACE = "kubernetes"
DEFAULT_MAX_DEPTH = 10

DEFAULT_USE_HISTOGRAM = False
DEFAULT_PUBLISH_ALIASES = False
DEFAULT_ENABLED_RATES = [
    'diskio.io_service_bytes.stats.total',
    'network.??_bytes',
    'cpu.*.total']

NET_ERRORS = ['rx_errors', 'tx_errors', 'rx_dropped', 'tx_dropped']

DEFAULT_ENABLED_GAUGES = [
    'memory.usage',
    'filesystem.usage']

GAUGE = AgentCheck.gauge
RATE = AgentCheck.rate
HISTORATE = AgentCheck.generate_historate_func(["container_name"])
HISTO = AgentCheck.generate_histogram_func(["container_name"])
FUNC_MAP = {
    GAUGE: {True: HISTO, False: GAUGE},
    RATE: {True: HISTORATE, False: RATE}
}

EVENT_TYPE = 'kubernetes'


class Kubernetes(AgentCheck):
    """ Collect metrics and events from kubelet """

    pod_names_by_container = {}

    def __init__(self, name, init_config, agentConfig, instances=None):
        if instances is not None and len(instances) > 1:
            raise Exception('Kubernetes check only supports one configured instance.')
        AgentCheck.__init__(self, name, init_config, agentConfig, instances)
        self.kubeutil = KubeUtil()
        if not self.kubeutil.host:
            raise Exception('Unable to get default router and host parameter is not set')

        self._last_event_collection_ts = defaultdict(lambda: None)

    def _perform_kubelet_checks(self, url):
        service_check_base = NAMESPACE + '.kubelet.check'
        is_ok = True
        try:
            r = requests.get(url)
            for line in r.iter_lines():

                # avoid noise; this check is expected to fail since we override the container hostname
                if line.find('hostname') != -1:
                    continue

                matches = re.match('\[(.)\]([^\s]+) (.*)?', line)
                if not matches or len(matches.groups()) < 2:
                    continue

                service_check_name = service_check_base + '.' + matches.group(2)
                status = matches.group(1)
                if status == '+':
                    self.service_check(service_check_name, AgentCheck.OK)
                else:
                    self.service_check(service_check_name, AgentCheck.CRITICAL)
                    is_ok = False

        except Exception, e:
            self.log.warning('kubelet check failed: %s' % str(e))
            self.service_check(service_check_base, AgentCheck.CRITICAL,
                               message='Kubelet check failed: %s' % str(e))

        else:
            if is_ok:
                self.service_check(service_check_base, AgentCheck.OK)
            else:
                self.service_check(service_check_base, AgentCheck.CRITICAL)

    def check(self, instance):

        self.max_depth = instance.get('max_depth', DEFAULT_MAX_DEPTH)
        enabled_gauges = instance.get('enabled_gauges', DEFAULT_ENABLED_GAUGES)
        self.enabled_gauges = ["{0}.{1}".format(NAMESPACE, x) for x in enabled_gauges]
        enabled_rates = instance.get('enabled_rates', DEFAULT_ENABLED_RATES)
        self.enabled_rates = ["{0}.{1}".format(NAMESPACE, x) for x in enabled_rates]

        self.publish_aliases = _is_affirmative(instance.get('publish_aliases', DEFAULT_PUBLISH_ALIASES))
        self.use_histogram = _is_affirmative(instance.get('use_histogram', DEFAULT_USE_HISTOGRAM))
        self.publish_rate = FUNC_MAP[RATE][self.use_histogram]
        self.publish_gauge = FUNC_MAP[GAUGE][self.use_histogram]

        pods_list = self.kubeutil.retrieve_pods_list()

        # kubelet health checks
        self._perform_kubelet_checks(self.kubeutil.kube_health_url)

        # kubelet metrics
        self._update_metrics(instance, pods_list)

        # kubelet events
        self._process_events(instance, pods_list)

    def _publish_raw_metrics(self, metric, dat, tags, depth=0):
        if depth >= self.max_depth:
            self.log.warning('Reached max depth on metric=%s' % metric)
            return

        if isinstance(dat, numbers.Number):
            if self.enabled_rates and any([fnmatch(metric, pat) for pat in self.enabled_rates]):
                self.publish_rate(self, metric, float(dat), tags)
            elif self.enabled_gauges and any([fnmatch(metric, pat) for pat in self.enabled_gauges]):
                self.publish_gauge(self, metric, float(dat), tags)

        elif isinstance(dat, dict):
            for k, v in dat.iteritems():
                self._publish_raw_metrics(metric + '.%s' % k.lower(), v, tags, depth + 1)

        elif isinstance(dat, list):
            self._publish_raw_metrics(metric, dat[-1], tags, depth + 1)

    @staticmethod
    def _shorten_name(name):
        # shorten docker image id
        return re.sub('([0-9a-fA-F]{64,})', lambda x: x.group(1)[0:12], name)

    def _get_post_1_2_tags(self, cont_labels, subcontainer, kube_labels):
        tags = []

        pod_name = cont_labels[KubeUtil.POD_NAME_LABEL]
        pod_namespace = cont_labels[KubeUtil.NAMESPACE_LABEL]
        tags.append(u"pod_name:{0}/{1}".format(pod_namespace, pod_name))
        tags.append(u"kube_namespace:{0}".format(pod_namespace))

        kube_labels_key = "{0}/{1}".format(pod_namespace, pod_name)

        pod_labels = kube_labels.get(kube_labels_key)
        if pod_labels:
            tags += list(pod_labels)

        if "-" in pod_name:
            replication_controller = "-".join(pod_name.split("-")[:-1])
            tags.append("kube_replication_controller:%s" % replication_controller)

        if self.publish_aliases and subcontainer.get("aliases"):
            for alias in subcontainer['aliases'][1:]:
                # we don't add the first alias as it will be the container_name
                tags.append('container_alias:%s' % (self._shorten_name(alias)))

        return tags

    def _get_pre_1_2_tags(self, cont_labels, subcontainer, kube_labels):

        tags = []

        pod_name = cont_labels[KubeUtil.POD_NAME_LABEL]
        tags.append(u"pod_name:{0}".format(pod_name))

        pod_labels = kube_labels.get(pod_name)
        if pod_labels:
            tags.extend(list(pod_labels))

        if "-" in pod_name:
            replication_controller = "-".join(pod_name.split("-")[:-1])
            if "/" in replication_controller:
                namespace, replication_controller = replication_controller.split("/", 1)
                tags.append(u"kube_namespace:%s" % namespace)

            tags.append(u"kube_replication_controller:%s" % replication_controller)

        if self.publish_aliases and subcontainer.get("aliases"):
            for alias in subcontainer['aliases'][1:]:
                # we don't add the first alias as it will be the container_name
                tags.append(u"container_alias:%s" % (self._shorten_name(alias)))

        return tags

    def _update_container_metrics(self, instance, subcontainer, kube_labels):
        tags = list(instance.get('tags', []))  # add support for custom tags

        if len(subcontainer.get('aliases', [])) >= 1:
            # The first alias seems to always match the docker container name
            container_name = subcontainer['aliases'][0]
        else:
            # We default to the container id
            container_name = subcontainer['name']

        tags.append('container_name:%s' % container_name)

        try:
            cont_labels = subcontainer['spec']['labels']
        except KeyError:
            self.log.debug("Subcontainer, doesn't have any labels")
            cont_labels = {}

        # Collect pod names, namespaces, rc...
        if KubeUtil.NAMESPACE_LABEL in cont_labels and KubeUtil.POD_NAME_LABEL in cont_labels:
            # Kubernetes >= 1.2
            tags += self._get_post_1_2_tags(cont_labels, subcontainer, kube_labels)

        elif KubeUtil.POD_NAME_LABEL in cont_labels:
            # Kubernetes <= 1.1
            tags += self._get_pre_1_2_tags(cont_labels, subcontainer, kube_labels)

        else:
            # Those are containers that are not part of a pod.
            # They are top aggregate views and don't have the previous metadata.
            tags.append("pod_name:no_pod")


        stats = subcontainer['stats'][-1]  # take the latest
        self._publish_raw_metrics(NAMESPACE, stats, tags)

        if subcontainer.get("spec", {}).get("has_filesystem"):
            fs = stats['filesystem'][-1]
            fs_utilization = float(fs['usage'])/float(fs['capacity'])
            self.publish_gauge(self, NAMESPACE + '.filesystem.usage_pct', fs_utilization, tags)

        if subcontainer.get("spec", {}).get("has_network"):
            net = stats['network']
            self.publish_rate(self, NAMESPACE + '.network_errors',
                              sum(float(net[x]) for x in NET_ERRORS),
                              tags)

    def _update_metrics(self, instance, pods_list):
        metrics = self.kubeutil.retrieve_metrics()

        excluded_labels = instance.get('excluded_labels')
        kube_labels = self.kubeutil.extract_kube_labels(pods_list, excluded_keys=excluded_labels)

        if not metrics:
            raise Exception('No metrics retrieved cmd=%s' % self.metrics_cmd)

        for subcontainer in metrics:
            try:
                self._update_container_metrics(instance, subcontainer, kube_labels)
            except Exception, e:
                self.log.error("Unable to collect metrics for container: {0} ({1}".format(
                    subcontainer.get('name'), e))

        self._update_pods_metrics(instance, pods_list)

    def _update_pods_metrics(self, instance, pods):
        supported_kinds = [
            "DaemonSet",
            "Deployment",
            "Job",
            "ReplicationController",
            "ReplicaSet",
        ]

        controllers_map = defaultdict(int)
        for pod in pods['items']:
            try:
                created_by = json.loads(pod['metadata']['annotations']['kubernetes.io/created-by'])
                kind = created_by['reference']['kind']
                if kind in supported_kinds:
                    controllers_map[created_by['reference']['name']] += 1
            except KeyError:
                continue

        tags = instance.get('tags', [])
        for ctrl, pod_count in controllers_map.iteritems():
            _tags = tags[:]  # copy base tags
            _tags.append('kube_replication_controller:{0}'.format(ctrl))
            self.publish_gauge(self, NAMESPACE + '.pods.running', pod_count, _tags)

    def _process_events(self, instance, pods_list):
        """
        Retrieve a list of events from kubelet that is relevant for the host the
        agent is running on.

        At the moment there is no support to select events based on a timestamp query, so we
        go through the whole list every time. This should be fine for now as events
        have a TTL of one hour[1] but logic needs to improve as soon as they provide
        query capabilities or at least pagination, see [2][3].

        [1] https://github.com/kubernetes/kubernetes/blob/master/cmd/kube-apiserver/app/options/options.go#L50
        [2] https://github.com/kubernetes/kubernetes/issues/4432
        [3] https://github.com/kubernetes/kubernetes/issues/1362
        """
        node_ip, node_name = self.kubeutil.get_node_info()
        pods = self.kubeutil.filter_pods_list(pods_list, node_ip)
        pod_uids = self.kubeutil.extract_meta(pods, 'uid')

        k8s_namespace = instance.get('namespace', 'default')
        events_endpoint = '{}/namespaces/{}/events'.format(self.kubeutil.kubernetes_api_url, k8s_namespace)
        self.log.debug('Kubernetes API endpoint to query events: %s' % events_endpoint)

        events = self.kubeutil.retrieve_json_auth(events_endpoint, self.kubeutil.get_auth_token())
        event_items = events.get('items') or []
        self.log.debug('Found {} events, filtering out unwanted ones...'.format(len(event_items)))

        last_ts = int(time.time())
        self._last_event_collection_ts[instance.get('port')] = last_ts

        for event in event_items:
            event_ts = int(time.mktime(time.strptime(event.get('lastTimestamp'), '%Y-%m-%dT%H:%M:%SZ')))
            if event_ts < last_ts:
                continue

            involved_obj = event.get('involvedObject')
            if involved_obj and involved_obj.get('uid') in pod_uids:
                self.log.error('Should post this event: {}, reason: {}'.format(event.get('message'), event.get('reason')))
                title = '{} {} on {}'.format(involved_obj.get('name'), event.get('reason'), node_name)
                message = event.get('message')
                source = event.get('source')
                if source:
                    message += '\nSource: {} {}\n'.format(source.get('component', ''), source.get('host', ''))
                msg_body = "%%%\n{}\n```\n{}\n```\n%%%".format(title, message)
                dd_event = {
                    'timestamp': last_ts,
                    'host': self.kubeutil.host,
                    'event_type': EVENT_TYPE,
                    'msg_title': title,
                    'msg_text': msg_body,
                    'source_type_name': EVENT_TYPE,
                    'event_object': 'kubernetes:{}'.format(involved_obj.get('name')),
                }
                self.log.debug('Posting event: {}'.format(dd_event))
                self.event(dd_event)
