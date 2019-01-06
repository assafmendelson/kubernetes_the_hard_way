Kubernetes the hard way - one node on a VM
==========================================


<!-- TOC -->

- [Overview](#overview)
    - [Goals](#goals)
    - [The setup](#the-setup)
        - [The Node setup](#the-node-setup)
        - [The Network setup](#the-network-setup)
    - [Tutorial overview](#tutorial-overview)
- [Create the node](#create-the-node)
- [Initial setup](#initial-setup)
    - [Setup logic hosts](#setup-logic-hosts)
- [Get the tools](#get-the-tools)
- [Configure certificates](#configure-certificates)
    - [Overview and preparations](#overview-and-preparations)
    - [Create the Certificate Authority (CA)](#create-the-certificate-authority-ca)
    - [Create certificates for users (roles) and components](#create-certificates-for-users-roles-and-components)
        - [Overview](#overview-1)
        - [Utility script](#utility-script)
        - [Certificate for the admin user (role)](#certificate-for-the-admin-user-role)
        - [Certificate for the Kubelet worker component](#certificate-for-the-kubelet-worker-component)
        - [The Controller manager certificate](#the-controller-manager-certificate)
        - [The kube proxy certificate](#the-kube-proxy-certificate)
        - [scheduler certificate](#scheduler-certificate)
        - [api server certificate](#api-server-certificate)
        - [Service account key pair.](#service-account-key-pair)
- [Create kubeconfig files](#create-kubeconfig-files)

<!-- /TOC -->



## Overview

### Goals

This tutorial aims to understand the process of installing a production grade Kubernetes cluster from scratch. The idea is that by following the process with all the details, a better understanding of Kubernetes architecture and use can be achieved as well as means to solve problems which may arise over time.
It was inspired by ["Kubernetes the hard way" by Kelsey Hightower](https://github.com/kelseyhightower/kubernetes-the-hard-way).

There are two problems with the original tutorial, however. The first being that the entire tutorial assumes the infrastructure is deployed on google cloud. This means a google cloud account is needed and furthermore, some of the explanations are aimed specifically at that platform and therefore problematic when used on other mediums such as a local laptop installation. The second issue is that more in depth explanation is required (especially regarding alternatives and troubleshooting)

Several online solutions have tried to alleviate these problems such as: [here](https://github.com/yinchuan/kubernetes-the-hard-way-virtualbox), [here](https://github.com/Praqma/LearnKubernetes/blob/master/kamran/Kubernetes-The-Hard-Way-on-BareMetal.md) and [here](https://medium.com/@DrewViles/kubernetes-the-hard-way-on-bare-metal-vms-fdb32bc4fed0), however these solution generally require multiple VMs and there is always the need for more detailed explanations.

The goal of this tutorial is to attempt to convert the original  ["Kubernetes the hard way" tutorial](https://github.com/kelseyhightower/kubernetes-the-hard-way), creating a Kubernetes cluster in a **single VM** (and possibly in the future put it in a docker container). In addition, some additional explanation were added where deemed relevant.

For those wanting to jump to the end and get a local development environment on a laptop, there are ready solutions which are probably easier than this tutorial such as [Minikube](https://github.com/kubernetes/minikube) for running in a VM, [Microk8s](https://microk8s.io/) for an isolated installation on an existing VM and [kubeadm dind cluster](https://github.com/kubernetes-sigs/kubeadm-dind-cluster) to run it in a docker container.

The main goal of this tutorial is to learn "The hard way".

### The setup
As stated before, the aim is to create the entire cluster on a single node. To do so, it is important to first understand the logic of how the cluster would be build. This can be divided into two main elements: The Node setup and the Network setup.

#### The Node setup

This tutorial assumes a single machine (a VM based on ubuntu 18.04 server) holds everything including the cluster itself and the client side (where deployment is initiated). 

Logically, a full blown implementation would have multiple nodes representing multiple elements in the cluster. In this tutorial, the host would be given additional host names to represent these elements (even though these would in practice be private localhost loopback addresses).

The logical nodes include:

* **Client**: This is the basic node which is used to run most of the commands (with emphasis on ```kubectl```). It is the node used by the administrator to control the cluster from.

* **master**: A typical installation would have several nodes acting as [master](https://kubernetes.io/docs/concepts/overview/components/#master-components) which are responsible for controlling the cluster. The master node is often also referred to as controller. <br/>
  Multiple masters are generally used to provide high availability and scalability.<br/>
  A node has several common components which can be split into their own nodes. These include  the [etcd database](https://kubernetes.io/docs/concepts/overview/components/#etcd) (which is often split into nodes of its own which can be scaled separately), [the API server](https://kubernetes.io/docs/concepts/overview/components/#kube-apiserver), the [Scheduler](https://kubernetes.io/docs/concepts/overview/components/#kube-scheduler) and the [controller manager](https://kubernetes.io/docs/concepts/overview/components/#kube-controller-manager).
* **worker**: A typical installation would have several nodes acting as [worker](https://kubernetes.io/docs/concepts/overview/components/#node-components) which are responsible for doing the computer (running the pods etc.).<br/>
  A worker node is composed of three main elements: [kubelet](https://kubernetes.io/docs/concepts/overview/components/#kubelet), [kube-proxy](https://kubernetes.io/docs/concepts/overview/components/#kube-proxy) and [container runtime](https://kubernetes.io/docs/concepts/overview/components/#container-runtime)
* **Load balancer**: This are actually two logical nodes:
  * **API server LB** A solution for high availability of the api server by providing a single public Ip Address for all instances of the api server.
  * **External LB** A solution for load balancing between services (to allow the LoadBalance service type).

The ip addresses and logical names are summarized here:

| logical hostname | loopback ip address | Meaning                             |
| :--------------: | :-----------------: | :----------------------------------:|
| controller       | 127.0.2.110         | Master node (etcd, api server, controller manager and scheduler) |
| worker           | 127.0.2.120         | Worker node |
| k8s-lb           | 127.0.2.101         | Load balancer for the api server |
| worker           | 127.0.2.120         | Load balancer for the services |

#### The Network setup
Logically, three types of networks are included:

1. **Infrastructure Network**: This network represents the network connecting between the underlying nodes. In a real cluster this would include the ip addresses the nodes use to talk with each other. <br/>
In practice in this example it would simply be the single ip address of the node which is used to route to the internet.
2. **"Pod network"**: This network represents the network connecting between the pods. It is aimed to have each pod (container) being able to reach any other container in a single network. That said, this network is NOT a real network on the infrastructure, instead it is a virtual network managed by Kubernetes itself. In this tutorial, this would be represented by the mask: **10.200.0.0/16**.
3. **"Service network"**: Represent the network defined by the service layer, i.e. static ips exposing the pods to the network. Similar to the pod network, the service network is virtual and not real, remaining in the Kubernetes definition alone, this would be represented by the mask: **10.32.0.0/16**.


### Tutorial overview
&#x1F534; add a storyline. &#x1F534;

- creating the nodes
- installing relevant tools
- provisioning certificates



## Create the node

&#x1F534; Put here everything needed to create the node including how to set up the VM, using ubuntu server as base (and later on testing alternatives such as xubuntu for better development), how to set up the disks etc. This should include the full base setup of the machine &#x1F534;


## Initial setup

### Setup logic hosts
As stated before, the node contains various components which would normally be in separate nodes. Therefore, additional names should be added to the /etc/hosts file to represent the virtual nodes.

```bash
sudo cat << EOF | sudo tee /etc/hosts
127.0.2.101 k8s-lb
127.0.2.210 k8s-controllers-lb
127.0.2.110 controller
127.0.2.120 worker
EOF
```

## Get the tools
Several packages and tools need to be added. These include:
- kubectl: Command line interface to interact with Kubernetes.
  - To install:

    ```bash
    curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
    chmod +x kubectl
    sudo mv kubectl /usr/local/bin/
    ```
  - To verify it works:
     ```bash
     kubectl version --client
     ```

- Install dependencies (packages needed for future steps):
  ```bash
   sudo apt install conntrack socat -y
  ```
- PKI tools:
  - For managing PKI and TLS, the cloudfare [cfssl toolkit](https://github.com/cloudflare/cfssl) is used.
  
     **NOTE**: these tools can be removed once installation is complete. &#x1F534; verify this. &#x1F534;
  - Install the tools:
     ```bash
     wget -q --show-progress --https-only --timestamping  https://pkg.cfssl.org/R1.2/cfssl_linux-amd64 https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
     chmod +x cfssl_linux-amd64 cfssljson_linux-amd64
     sudo mv cfssl_linux-amd64 /usr/local/bin/cfssl
     sudo mv cfssljson_linux-amd64 /usr/local/bin/cfssljson
     ```
  - Verify correctness
    ```bash
    cfssl version
    ```
## Configure certificates
Kubernetes uses certificates to authenticate communication between the various components. In this step, certificates for the various elements would be created.

### Overview and preparations

For easy access, the certificates would be located at the root of the user's home directory (~/). To create the certificates, configuration files are required, for simplicity these would be created in a subdirectory (pki_config). To create it do:

```bash
mkdir -p pki_config
```

Creating a certificate generally involves in creating the csr (certificate signing request) configuration and then creating the new certificate by using ```cfssl gencert```. For certificate XXX This will result in three files:

 - XXX.pem: The actual certificate
 - XXX-key.pem: The private key of the certificate
 - XXX.csr: The certificate signing request for the certificate
 
It is possible to then validate the certificate by running:
```bash
cfssl certinfo -cert XXX.pem
```
This will show all relevant information. Note that if "hostname" is defined, its information would be under the "sans" array.

The csr file has a consistent format. A simple example would be:
```
{
  "CN": "KubernetesName",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "IL",
      "L": "Tel Aviv",
      "O": "Kubernetes",
      "OU": "My sample",
      "ST": "None"
    }
  ]
}
```
Note that some of the fields are constant for all certificates (setup for the organization) while some may change per specific goal of a certificate. They are summarized as follows:

| Field notation | Field meaning | value in example | Consistent in all certificates? | Instructions |
| :------------: | :-----------: | :--------------: | :------: | :----------: |
| CN             | Common Name   | KubernetesName | No | This is a name for the host. It could be a server name or a URL. In this case, conventions exists as described below |
| algo | algorithm | rsa | Yes | An algorithm used for signing. In general many can be used, rsa is the simple solution here. |
| size | key size | 2048 | Yes | Number of bits in the crypto key. There are various legal size but just use the default here. |
| C | Country | IL | Yes | Should be one of the codes [here](https://www.digicert.com/ssl-certificate-country-codes.htm)|
| L | Location (city) | Tel Aviv | Yes | City name (anything) |
| O | Organization | Kubernetes | No | The organization the certificate belongs to. In general, some conventions exist for the various roles (see description) |
| OU | Organization Unit | My sample | Yes | Some name of the business unit in the organization, not important here|
| ST | State | None | Yes | State (for countries with state) |


Since this is very repetitive, it is possible to create a script which would generate the relevant configuration automatically by supplying it with the configuration name, the O field and the CN field.

It is therefore simple to create a bash script to generate the relevant files. 
```bash
cat > pki_config/gen_config.sh << 'GEN_CONFIG'
#!/usr/bin/env bash

set -eu
set -o pipefail

__config_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

_usage() {
  cat << HELP_USAGE

  $0 objectName CommonName Organization

    - objectName Name of the object to create (this will generate a file called pki_config/objectName-csr.json)
    - CommonName The common name (CN field)
    - Organization The organization (O field)
HELP_USAGE
}

if [  $# -le 2 ]
then
  _usage
  exit 1
fi

cat > "${__config_dir}/${1}-csr.json" <<EOF
{
  "CN": "$2",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "IL",
      "L": "Tel aviv",
      "O": "$3",
      "OU": "Some name",
      "ST": "None"
    }
  ]
}
EOF
GEN_CONFIG
chmod +x pki_config/gen_config.sh
```

### Create the Certificate Authority (CA)

All the PKI require a Certificate Authority (CA) to manage it, this CA is responsible for defining what certificates are correct by signing them.

The first step in configuring the PKI is therefore to create a new certificate authority.

The first step is to create a csr configuration for the certificate authority (using the new pki_config/gen_config.sh script). This configuration has the base name "ca". Then generate the relevant files (ca.pem, ca-key.pem and ca.csr). Then use ```cfssl gencert``` to create the new files and ```cfssljson``` to expose them:
```bash
pki_config/gen_config.sh ca Kubernetes Kubernetes
cfssl gencert -initca pki_config/ca-csr.json | cfssljson -bare ca
```

The CA should have a profile for all the certificates, create a base configuration to use:

```bash
cat > pki_config/ca-config.json <<EOF
{
  "signing": {
    "default": {
      "expiry": "8760h"
    },
    "profiles": {
      "kubernetes": {
        "usages": ["signing", "key encipherment", "server auth", "client auth"],
        "expiry": "8760h"
      }
    }
  }
}
EOF
```

### Create certificates for users (roles) and components

#### Overview

The creation of a certificate for a user (role) or component requires the creation of the appropriate csr configuration file following by a call to cfssl gencert with some common parameters and then a call to cfssljson e.g.:

```bash
pki_config/gen_config.sh someName CommonName Organization

cfssl gencert \
  -ca=ca.pem \ # The previously created CA certificate
  -ca-key=ca-key.pem \ # The previously created CA private key
  -config=pki_config/ca-config.json \ # The previously created configuration
  -hostname=SomeOptionalHosts \ # if no hosts then -hostname does not appear
  -profile=kubernetes \ # profile as defined in ca-config.json
  pki_config/someName-csr.json | cfssljson -bare someName
```

This means that by setting a base name for the certificate, a common name, an organization and optionally hosts, everything else is the same.

While the name for the certificate is just a matter of taste (to make sure the naming is consistent) and the hosts are based on the connectivity graph (which component on which node connects to which component), the organization name and common name are strongly correlated to roles. In general the organization name defines the "group" and the common name defines the "user". An initial listing of the correct names and roles can be found [here](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) with some additional constraints defined in the detailed description before . Specifically the following table summarizes them:

| component name | role | CommonName (user) | Organization (group) |
| :------------: | :--: | :--------: | :----------: |
| admin  | cluster-admin | admin | system:masters |
| worker | system:node   | system:nodes:worker | system:node |
| kube-controller-manager | system:kube-controller-manager | system:kube-controller-manager | system:kube-controller-manager |
|  kube-proxy | system:node-proxier | system:kube-proxy | system:node-proxier |
| scheduler | system:kube-scheduler | system:kube-scheduler | system:kube-scheduler |
| api server | -- | kubernetes | Kubernetes |
| service account | -- | service-accounts | Kubernetes |


#### Utility script
To simplify this, a simple script is used:

```bash
cat > pki_config/gen_cert.sh << 'GEN_CERT'

#!/usr/bin/env bash

set -eu
set -o pipefail

_usage() {
  cat << HELP_USAGE

  $0 objectName CommonName Organization hosts

    - objectName Name of the object to create (this will generate a file called pki_config/objectName-csr.json)
    - CommonName The common name (CN field)
    - Organization The organization (O field)
    - the hosts list. NOTE: This is assumed to be a single element with , (i.e. a,b rather than a b or a,b)
HELP_USAGE
}

if [[  $# -le 2 || $# -ge 5 ]]
then
  _usage
  exit 1
fi

__config_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "${__config_dir}/gen_config.sh" $@

if [[ ${4:-} == "" ]]
then
  hosts=""
else
  hosts="-hostname=$4"
fi

cfssl gencert -ca=ca.pem -ca-key=ca-key.pem  -config="${__config_dir}/ca-config.json"   -profile=kubernetes ${hosts}  "${__config_dir}/$1-csr.json"  | cfssljson -bare $1
GEN_CERT
chmod +x pki_config/gen_cert.sh
```

#### Certificate for the admin user (role)

As stated above, the admin certificate has a user (common name) of admin and an organization (group) of system:masters

```bash
pki_config/gen_cert.sh admin admin system:masters
```

#### Certificate for the Kubelet worker component

Kubernetes uses a special-purpose authorization mode (https://kubernetes.io/docs/admin/authorization/node/) called Node Authorizer, that specifically authorizes API requests made by Kubelets (the component responsible to manage the containers on the node based on the state from the master).

In order to be authorized by the Node Authorizer, Kubelets must use a credential that identifies them as being in the ```system:nodes``` group, with a username (common name) of ```system:node:<nodeName>```.

In addition, not every host can use this certificate, it would only be relevant for the worker. Legal hostnames for the worker include its used hostname (as defined in /etc/hosts, i.e. worker), the internal ip used (again in /etc/hosts/) and the ip of the node as can be found from the default routing.

This example assumes the certificate is the same for all workers and that only one is used. If multiple workers are used then all of their hostnames and ips should be included (which would become cumbersome). A better way would be to use a a different certificate for each worker (as in the original article). In this case, the difference certificates should match the hosts for that specific worker and have different common name

```bash
# extract the /etc/hosts ip address
WORKER_HOST_IP=$(getent hosts worker | awk '{ print $1 }')
# Get the ip used for routing, 8.8.8.8 is used just to have some address which is not local.
NODE_MAIN_IP=$(ip -o route get to 8.8.8.8 | sed -n 's/.*src \([0-9.]\+\).*/\1/p')

pki_config/gen_cert.sh worker system:node:worker system:nodes worker,$WORKER_HOST_IP,$NODE_MAIN_IP
```

#### The Controller manager certificate  
The controller manager component should have the user of system:kube-controller-manager. For simplicity, the same group is used.

```bash
pki_config/gen_cert.sh kube-controller-manager system:kube-controller-manager system:kube-controller-manager
```

#### The kube proxy certificate  
The proxy component should have the user of system:kube-proxy and a group of system:node-proxier.

```bash
pki_config/gen_cert.sh kube-proxy system:kube-proxy system:node-proxier
```
  
#### scheduler certificate
The scheduler component should have the user of system:kube-scheduler and a group of system:kube-scheduler.

```bash
pki_config/gen_cert.sh kube-scheduler system:kube-scheduler system:kube-scheduler
```

#### api server certificate
The api server uses generic names (kubernetes/Kubernetes). It does have a need to define hosts (ip addresses) if all the ips which can access it (just about everyone):
-The publicly resolved ip address (we used it in NODE_MAIN_IP above). This serves as the address of each node (we have just one) as well as the address used to expose kubernetes to the outside world.
- the localhost
- An address in the service CIDR (we will set this manually at 10.32.0.1)
- A generic hostname (kubernetes.default)

```bash
pki_config/gen_cert.sh api Kubernetes kubernetes 10.32.0.1,${NODE_MAIN_IP},127.0.0.1,kubernetes.default
```

#### Service account key pair.

The Controller Manager component leverages a key pair to generate and sign service account token (see [the documentation](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)). Generating a certificate can solve this as well

```bash
pki_config/gen_cert.sh service-account service-accounts Kubernetes
```

## Create kubeconfig files

[Kubernetes Configuration files](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/), also known as kubeconfigs enable Kubernetes clients to locate and authenticate to the Kubernetes API servers. For all elements which need to connect to the api servers, a proper kubeconfig file is needed. These include the controller manage, kube-proxy and scheduler clients as well as the admin user.


