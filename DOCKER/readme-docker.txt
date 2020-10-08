Place your /home/user/.kube/config file in the src directory before building the container
Once your kubeconfig is in the src directory, build your container image with docker build -t myimage .
You can then start a new container with docker run --name aciepgcontroller -d myimage
To get logs once the container is running, use docker logs -f aciepgcontroller
