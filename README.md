# What is this?
[_Please check the master branch - that's where the code is!_]

This is a simple custom controller/operator that creates EPGs in Cisco's ACI fabric from Custom Resources applied on a K8s cluster.
This assumes you have:

1. A functional K8s cluster with cluster-admin privileges
2. An ACI fabric with your compute nodes attached to that fabric (bare metal or virtual)
3. Cisco's ACI-CNI plugin running

# Tell me more

This little project consists of three parts:

1. Custom Resource Definition
1. Custom Resource sample file
1. Custom Controller written in Python

Apply the CRD first.
Create a namespace in K8s that matches the epgName value in the custom resource (aci-crd-02.yaml provides an example) 
Launch the controller (either with python3 aci-crd-03.py or (preferred) as a Docker container using the Dockerfile provided).
_Note: If you dockerize the controller, place your .kube/config file in the src directory and build the image, then run a container from the image._

The custom controller listens to events associated to custom resources.
If you create a new custom resource (use the sample provided in file aci-crd-02.yaml), the controller will detect a ADDED event.
At that point, the controller contacts the ACI fabric (credentials are auto-discovered when you run the ACI-CNI plugin) and creates an EPG inside
the K8s tenant that corresponds to your K8s cluster, under the Application Profile of your choice. It populates that EPG with the BD of your choice,
and the contracts you provided in the custom resource manifest.

The controller then annotates the namespace that matches epgName. 
When you deploy an app in that namespace, all pods appear in the automatically created EPG in your ACI fabric.

The controller also handles deletion events and only deletes the EPG. It will not delete the Application Profile and/or Tenant.

# Disclaimer

This is proof-of-concept code that is provided as-is with no implicit or explicit warranty. 
Make sure you understand the code before deploying it on your K8s cluster.
