# Use Ubuntu as the base image
FROM ubuntu:latest

# Set non-interactive mode to avoid prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Update package lists and install Python and necessary dependencies
RUN apt-get update && apt-get install -y python3 python3-pip iputils-ping

# Set the working directory inside the container
WORKDIR /app

# Copy the Python script into the container
COPY NetworkApplications.py /app/

# Expose ports for web server and proxy server
EXPOSE 8080
EXPOSE 8000

# Set the entrypoint to run the Python script with arguments
ENTRYPOINT ["python3", "/app/NetworkApplications.py"]

