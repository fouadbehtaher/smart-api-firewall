# Use an official Python runtime as a parent image
# "Slim" variants are much smaller and faster to download
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
# --no-cache-dir keeps the image small
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the current directory contents into the container at /app
COPY . .

# We don't specify a CMD here because we will define specific commands
# for the Backend and Dashboard in the docker-compose.yml file.