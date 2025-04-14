FROM docker.io/openjdk:latest
WORKDIR /app
COPY noxy.jar /app/noxy.jar
CMD ["java", "-jar", "/app/noxy.jar", "-c", "/app/conf.yaml"]
