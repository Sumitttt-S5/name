
FROM python:3.13-slim

# Python runtime configuration
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Create a dedicated non-root sandbox user
RUN useradd --create-home --uid 10001 sandbox

# Worker directory
WORKDIR /sandbox

# Main sandbox execution engine
COPY sandbox/worker/entrypoint.py /sandbox/entrypoint.py

# Monitoring modules
COPY sandbox/monitoring/file_monitor.py /sandbox/file_monitor.py
COPY sandbox/monitoring/process_monitor.py /sandbox/process_monitor.py
COPY sandbox/monitoring/network_monitor.py /sandbox/network_monitor.py
COPY sandbox/monitoring/event_collector.py /sandbox/event_collector.py

# Monitoring integration test scripts
COPY sandbox/worker/test_honeytoken.py /sandbox/test_honeytoken.py
COPY sandbox/worker/test_process_monitor.py /sandbox/test_process_monitor.py
COPY sandbox/worker/test_network_monitor.py /sandbox/test_network_monitor.py
COPY sandbox/worker/test_runtime_report.py /sandbox/test_runtime_report.py

# Directory for dynamically mounted uploaded packages
RUN mkdir -p /input

# Ensure the sandbox engine belongs to the non-root user
RUN chown -R sandbox:sandbox /sandbox

# Run without root privileges
USER 10001:10001

# Start the runtime sandbox worker
ENTRYPOINT ["python", "-I", "/sandbox/entrypoint.py"]
