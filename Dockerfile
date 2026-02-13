# Use official Dart image
FROM dart:stable

# Set working directory inside container
WORKDIR /app

# Copy pubspec files first (for dependency caching)
COPY pubspec.yaml pubspec.lock ./

# Install dependencies
RUN dart pub get

# Copy rest of the project files
COPY . .

# Railway uses PORT env variable (important)
EXPOSE 8080

# Start the backend server
CMD ["dart", "run", "server.dart"]
