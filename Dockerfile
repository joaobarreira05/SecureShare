# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Create a wrapper script for the CLI
RUN echo '#!/bin/bash\npython3 -m cli.main "$@"' > /usr/local/bin/secureshare && \
    chmod +x /usr/local/bin/secureshare

# Expose port 8000 for the FastAPI app
EXPOSE 8000

# Run the application
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--ssl-keyfile", "/app/certs/server.key", "--ssl-certfile", "/app/certs/server.crt"]
