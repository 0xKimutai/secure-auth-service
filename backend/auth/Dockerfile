# Use a lightweight Java runtime image
FROM eclipse-temurin:17-jdk-alpine

# Set working directory inside the container
WORKDIR /app

# Copy Maven wrapper and pom.xml
COPY mvnw pom.xml ./
COPY .mvn .mvn

# Download dependencies (offline mode)
RUN ./mvnw dependency:go-offline -B

# Copy all source code
COPY src ./src

# Build the Spring Boot app (skip tests to speed up)
RUN ./mvnw clean package -DskipTests

# Expose the port your app will run on
EXPOSE 8080

# Run the Spring Boot JAR
CMD ["java", "-jar", "target/auth-0.0.1-SNAPSHOT.jar"]
