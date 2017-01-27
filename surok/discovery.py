import dns.resolver
import dns.query
from dns.exception import DNSException
from .logger import Logger
import sys
import requests

# Default config for Discovery class
_config={
  'default_discovery':'mesos_dns',    # Default discovery system
  'version':'0.7'
}

# Discoveries objects
_discoveries={}

#Logger
logger=Logger()

class DiscoveryTestingTemplate:
    def do_query_a(fqdn):
    return ['10.0.0.1','10.0.0.2']

    def do_query_srv(fqdn):
    return [{'name':'testing.host','port':3333}]

class DiscoveryTemplate(DiscoveryTestingTemplate):
    # Default config values for discovery template
    _config={}
    _defconfig={'enabled':False}

    def __init__(self,conf):
        for key in self._defconfig.keys():
            if key not in self._config.keys():
                self._config[key]=self._defconfig[key]
        self.set_config(conf)

    def set_config(self,conf):
        pass

    def enabled(self):
        return self._config['enabled']

    def update_data(self):
        pass

    def get_group(self,service, app):
        # Check group in app conf
        if 'group' in service:
            return service['group']

        # Check environment variable
        elif app['env'].get('SUROK_DISCOVERY_GROUP'):
            return app['env']['SUROK_DISCOVERY_GROUP']

        # Check marathon environment variable
        elif app['env'].get('MARATHON_APP_ID'):
            return ".".join(app['env']['MARATHON_APP_ID'].split('/')[-2:0:-1])

        else:
            logger.error('Group is not defined in config, SUROK_DISCOVERY_GROUP and MARATHON_APP_ID')
            logger.error('Not in Mesos launch?')
            sys.exit(2)
    # Do DNS queries
    # Return array:
    # ["10.10.10.1", "10.10.10.2"]
    def do_query_a(fqdn):
        servers = []
        try:
            resolver = dns.resolver.Resolver()
            for a_rdata in resolver.query(fqdn, 'A'):
                servers.append(a_rdata.address)
        except DNSException as e:
            logger.error("Could not resolve "+fqdn)

        return servers

    # Do DNS queries
    # Return array:
    # [{"name": "f.q.d.n", "port": 8876, "ip": ["10.10.10.1", "10.10.10.2"]}]
    def do_query_srv(fqdn):
        servers = []
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 1
            resolver.timeout = 1
            query = resolver.query(fqdn, 'SRV')
            for rdata in query:
                info = str(rdata).split()
                servers.append({'name': info[3][:-1], 'port': info[2]})
        except DNSException as e:
            logger.error("Could not resolve " + fqdn)

        return servers


class Discovery:
    def __init__(self,*conf):
        for __conf in conf:
            self.set_config(__conf)

    def set_config(self,conf):
        global _discoveries
        #Get discoveries objects
        if not _discoveries.get('mesos_dns'):
            _discoveries['mesos_dns']=DiscoveryMesos(conf)
        else:
            _discoveries['mesos_dns'].set_config(conf)

        if not _discoveries.get('marathon_api'):
            _discoveries['marathon_api']=DiscoveryMarathon(conf)
        else:
            _discoveries['marathon_api'].set_config(conf)

        if not _discoveries.get('consul_dns'):
            _discoveries['consul_dns']=DiscoveryConsul(conf)
        else:
            _discoveries['consul_dns'].set_config(conf)

        global _config
        if conf.get('default_discovery'):
            discovery=conf.get('default_discovery')
            if discovery in list(_discoveries.keys()):
                _config['default_discovery']=discovery
            else:
                logger.error('Default discovery "'+discovery+'" is not present')
                logger.debug('Conf=',conf)
        if conf.get('version'):
            version=conf.get('version')
            if discovery in ['0.7','0.8']:
                _config['version']=version
            else:
                logger.error('Version "'+version+'" unknown')
                logger.debug('Conf=',conf)

    def resolve(self,app):
        __discovery=_config.get('default_discovery')
        if app.get('discovery'):
            discovery=app.get('discovery')
            if discovery in list(_discoveries.keys()):
                __discovery=discovery
            else:
                logger.warning('Discovery "'+discovery+'" is not present')
                logger.debug('App=',app)
                return {}
        if _discoveries[__discovery].enabled():
            return self.compatible(_discoveries[__discovery].resolve(app))
        else:
            logger.error('Discovery "'+__discovery+'" is disabled')
        return {}

    def update_data(self):
        global _discoveries
        for d in list(_discoveries.keys()):
            if _discoveries[d].enabled():
                _discoveries[d].update_data()

    def compatible(self,hosts):
        __hosts={}
        if _config['version'] == '0.7':
            for service in hosts.keys():
                for host in hosts[service]:
                    ports=host.get('tcp',[])
                    if type(ports).__name__ == 'list':
                        __hosts[service]=[]
                        for port in ports:
                            __hosts[service].append({'name':host['name'],
                                                     'ip':host['ip'],
                                                     'port':str(port)})
                    else:
                        __hosts[service]={}
                        for port in ports.keys():
                            __host=__hosts[service].setdefault(port,[])
                            __host.append({'name':host['name'],
                                           'ip':host['ip'],
                                           'port':ports[port]})

        return(__hosts)


class DiscoveryMesos(DiscoveryTemplate):
    _config={
                'domain':'marathon.mesos'           # Default domain
            }

    def set_config(self,conf):
        # For old version config
        if conf.get('domain'):
            self._config['domain']=conf.get('domain')
            self._config['enabled']=True
        # For current version config
        if conf.get('mesos'):
            _conf=conf['mesos']
            for p in ['domain','enabled']:
                if _conf.get(p):
                    self._config[p]=_conf.get(p)

    def resolve(self,app):
        hosts = {}
        services = app['services']
        domain = self._config['domain']
        for service in services:
            group = self.get_group(service, app)
            ports = service.get('ports')
            name = service['name']
            hosts[name] = {}
            serv = hosts[name]
            for prot in ['tcp','udp']:
                if ports is not None:
                    for port_name in ports:
                        for d in self.do_query_srv('_'+port_name+'._'+name+'.'+group+'._'+prot+'.'+domain):
                            hostname=d['name']
                            if serv.get(hostname) is None:
                                serv[hostname]={"name":hostname, 'ip':self.do_query_a(hostname)}
                            if serv[hostname].get(prot) is None:
                                serv[hostname][prot]={}
                                serv[hostname][prot][port_name]=d['port']
                    hosts[name]=list(hosts[name].values())
                else:
                    for d in self.do_query_srv('_'+name+'.'+group+'._'+prot+'.'+domain):
                        hostname=d['name']
                        if serv.get(hostname) is None:
                            serv[hostname]={"name":hostname, 'ip':self.do_query_a(hostname)}
                        if serv[hostname].get(prot) is None:
                            serv[hostname][prot]=[]
                        serv[hostname][prot].extend([d['port']])

        return hosts


class DiscoveryMarathon(DiscoveryTemplate):
    _config={
                'host':'http://marathon.mesos:8080',
                'force':True
            }
    __tasks = []
    __ports = {}
    def set_config(self,conf):
        # For current version config
        if conf.get('marathon'):
            _conf=conf['marathon']
            for p in ['host','enabled','force']:
                if _conf.get(p):
                    self._config[p]=_conf.get(p)

    def update_data(self):
        try:
            apps = requests.get(self._config['host']+'/v2/apps').json()['apps']
            ports = {}
            for app in apps:
                ports[app['id']] = {}
                if app.get('container') is not None and app['container']['type'] == 'DOCKER':
                    ports[app['id']] = app['container']['docker'].get('portMappings',[])
            self.__ports=ports
        except:
            logger.warning('Apps ('+self._config['host']+'/v2/apps) request from Marathon API is failed')
            pass
        try:
            self.__tasks = requests.get(self._config['host']+'/v2/tasks').json()['tasks']
        except:
            logger.warning('Tasks ('+self._config['host']+'/v2/tasks) request from Marathon API is failed')
            pass

    def resolve(self, app):
        hosts={}
        serv_conf = app['services']
        if not serv_conf:
            serv_conf = [{'name':'*','ports':['*']}]
        for serv in serv_conf:
            # Convert xxx.yyy.zzz to /zzz/yyy/xxx/ format
            group = '/'.join(['']+self.get_group(serv, app).split('.')[::-1]+[''])
            mask = group+serv['name']
            for task in self.__tasks:
                if (mask.endswith('*') and task['appId'].startswith(mask[:-1])) or task['appId'] == mask:
                    name='.'.join(task['appId'][len(group):].split('/')[::-1])
                    hosts[name]={}
                    for port in self.__ports[task['appId']]:
                        if 'ports' in serv:
                            for pp in serv['ports']:
                                if (pp.endswith('*') and port['name'].startswith(pp[:-1])) or port['name'] == pp:
                                    if hosts[name].get(task['host']) is None:
                                        hosts[name][task['host']]={'name':task['host'],
                                                                   'ip':self.do_query_a(task['host'])}
                                    if hosts[name][task['host']].get(port['protocol']) is None:
                                        hosts[name][task['host']][port['protocol']]={}
                                    hosts[name][task['host']][port['protocol']][port['name']]=task['ports'][task['servicePorts'].index(port['servicePort'])]
                        else:
                            if hosts[name].get(task['host']) is None:
                                hosts[name][task['host']]={'name':task['host'],
                                                           'ip':self.do_query_a(task['host'])}
                            if hosts[name][task['host']].get(port['protocol']) is None:
                                hosts[name][task['host']][port['protocol']]=[]
                            hosts[name][task['host']][port['protocol']].extend([task['ports'][task['servicePorts'].index(port['servicePort'])]])
                    hosts[name]=list(hosts[name].values())

        return hosts

class DiscoveryConsul(DiscoveryTemplate):
    _config={
                'domain':None
            }
    def set_config(self,conf):
        # For current version config
        if conf.get('consul'):
            _conf=conf['consul']
            for p in ['domain','enabled']:
                if _conf.get(p):
                    self._config[p]=_conf.get(p)

    def resolve(self,app):
        hosts = {}
        services = app['services']
        domain = self._config['domain']
        for service in services:
            name = service['name']
            for prot in ['tcp','udp']:
                for d in self.do_query_srv('_'+name+'._tcp.'+domain):
                    hostname=d['name']
                    if serv.get(hostname) is None:
                         serv[hostname]={"name":hostname, 'ip':self.do_query_a(hostname)}
                    if serv[hostname].get(prot) is None:
                         serv[hostname][prot]=[]
                    serv[hostname][prot].extend([d['port']])
        hosts[name]=list(hosts[name].values())
        return hosts

