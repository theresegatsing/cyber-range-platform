FROM python:3.9-slim

WORKDIR /app

# Install Flask
RUN pip install flask

# Copy our app
COPY app.py .

# Expose port 80
EXPOSE 80

# Run the app
CMD ["python", "app.py"]