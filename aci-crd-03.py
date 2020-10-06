import asyncio
import base64
import time
import logging
import sys
import json
import requests
import pprint
from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream
from OpenSSL.crypto import FILETYPE_PEM, load_privatekey, sign

logger = logging.getLogger('k8s_events')
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

config.load_kube_config()
v1 = client.CustomObjectsApi()

group = 'aci.ctrl'
version = 'v1'
plurals = 'epgs'
ns = 'aci-containers-system'
cfmap = 'aci-containers-config'

def AciPost(apic, username, privateKey, method, path, payload):
    cert = username + '.crt'
    headers = {}
    sigKey = load_privatekey(FILETYPE_PEM, privateKey)
    sigSignature = base64.b64encode(sign(sigKey, payload, 'sha256')).decode('utf-8')
    sigDn = 'uni/userext/user-%s/usercert-%s' % (username,cert)
    headers['Cookie'] = 'APIC-Certificate-Algorithm=v1.0; ' +\
                        'APIC-Certificate-DN=%s; ' % sigDn +\
                        'APIC-Certificate-Fingerprint=fingerprint; ' +\
                        'APIC-Request-Signature=%s' % (sigSignature)
    url = 'https://' + apic + path
    print(headers['Cookie'])
    req = requests.get(url, headers=headers, verify=False)
    print(req.text)

def getApicInfo():
    ns = 'aci-containers-system'
    v1core = client.CoreV1Api()
    configMap = v1core.read_namespaced_config_map(namespace=ns,name=cfmap)
    configMapJson = json.loads(configMap.data['controller-config'])
    apicHosts = configMapJson['apic-hosts']
    apicUsername = configMapJson['apic-username']
    apicPrivateKeyPath = configMapJson['apic-private-key-path']
    apicTenant = configMapJson['aci-prefix']
    apicInfo = {}
    apicInfo['apicHosts']=apicHosts
    apicInfo['apicUsername']=apicUsername
    apicInfo['apicPrivateKeyPath']=apicPrivateKeyPath
    apicInfo['apicTenant']=apicTenant
    apicInfo['controllerPod']=findAciControllerPod()
    privKey = execCommands(ns, apicInfo['controllerPod'])
    apicInfo['privKey']=privKey
    return(apicInfo)

def findAciControllerPod():
    v1core = client.CoreV1Api()
    ns = 'aci-containers-system'
    pods = v1core.list_namespaced_pod(namespace=ns)
    podList = pods.items
    for pod in podList:
        if 'controller' in pod.metadata.name:
            controllerPod = pod.metadata.name
    return controllerPod

def execCommands(ns,pod):
    v1core = client.CoreV1Api()
    resp = None
    try:
        resp = v1core.read_namespaced_pod(name=pod,namespace=ns)
    except ApiException as e:
        if e.status != 404:
            print("Unknown kubeapi error: %s" % e)
            sys.exit(1)

    if not resp:
        print("Pod %s does not exist - this shouldn't happen; was namespace deleted?" % pod)
        sys.exit(1)
    
    # Calling exec and waiting for response
    exec_command = [
        '/bin/sh',
        '-c',
        'cat /usr/local/etc/aci-cert/user.key']
    resp = stream(v1core.connect_get_namespaced_pod_exec,
                  pod,
                  ns,
                  command=exec_command,
                  stderr=True, stdin=False,
                  stdout=True, tty=False)
    return(resp)

def getApicKey():
    # kubectl exec -t pod/aci-containers-controller-5c67d647c6-tl58z -n=aci-containers-system -- cat /usr/local/etc/aci-cert/user.key
    v1core = client.CoreV1Api()
    configMap = v1core.read_namespaced_config_map(namespace=ns,name=cfmap)
    configMapJson = json.loads(configMap.data['controller-config'])

async def customEvents():
    w = watch.Watch()
    for event in w.stream(v1.list_cluster_custom_object,group,version,plurals):
        timeStamp = event['object']['metadata']['creationTimestamp']
        eventId = event['object']['metadata']['resourceVersion']
        eventType = event['type']
        logger.info("%s Event number %s: %s %s" % (timeStamp, eventId, eventType, event['object']['spec']))
        bd = event['object']['spec']['bd']
        tenant = event['object']['spec']['tenant']
        ap = event['object']['spec']['ap']
        epgName = event['object']['spec']['epgName']
        contracts = event['object']['spec']['contracts']
        if 'ADDED' in eventType:
            logger.info("\t\tCreating EPG %s in tenant %s in AP %s with BD %s and contracts %r" % (epgName, tenant, ap, bd, contracts))
        if 'DELETED' in eventType:
            logger.info("\t\tDeleting EPG %s" % (epgName))

        await asyncio.sleep(0)        

def main():
    apicInfo=getApicInfo()
    for key, value in sorted(apicInfo.items()):
        print("{} : {}".format(key, value))    
    AciPost(apicInfo['apicHosts'][0], apicInfo['apicUsername'], apicInfo['privKey'], 'get', '/api/class/fvTenant.json', 'GET/api/class/fvTenant.json')
    sys.exit(666)


    #kubectl get configmap/aci-containers-config -n=aci-containers-system -o jsonpath='{.data.controller-config}'
    ioloop = asyncio.get_event_loop()

    # I am using async tasks in case I have to monitor multiple types later
    ioloop.create_task(customEvents())
    ioloop.run_forever()

if __name__ == '__main__':
    main()
