# set base image (host OS)
FROM python:3.8

# set the working directory in the container
RUN mkdir /home/cisco

WORKDIR /home/cisco

# copy the dependencies file to the working directory
COPY requirements.txt .

# install dependencies
RUN pip install -r requirements.txt

# copy the content of the local src directory to the working directory
COPY src/aci-crd-03.py .
COPY src/config .

# command to run on container start
CMD [ "python", "./aci-crd-03.py" ]
