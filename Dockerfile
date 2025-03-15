# Base image
FROM python:latest

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy the rest of the app
COPY . .

# Expose Flask's default port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]
