FROM python:3.11-slim

WORKDIR /app

# git        — for cloning repos
# Java 17    — to run ./gradlew and mvn dependency:list (transitive dep resolution)
# Maven      — for Maven projects without a wrapper
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        default-jdk-headless \
        maven \
    && rm -rf /var/lib/apt/lists/*

# Gradle wrapper downloads Gradle on first use — point its cache to a writable dir
ENV GRADLE_USER_HOME=/home/vulnhawk/.gradle

RUN useradd -r -m -s /bin/false vulnhawk && \
    mkdir -p /home/vulnhawk/.local/share/crewai \
             /home/vulnhawk/.gradle \
             /home/vulnhawk/.m2 && \
    chown -R vulnhawk:vulnhawk /home/vulnhawk

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .
RUN chown -R vulnhawk:vulnhawk /app

USER vulnhawk
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
