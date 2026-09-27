FROM mcr.microsoft.com/playwright:v1.63.0-noble
WORKDIR /app
COPY worker/package*.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY worker/src ./src
RUN mkdir -p /home/vm-monitor-worker/tmp && chown -R pwuser:pwuser /home/vm-monitor-worker
USER pwuser
ENV WORKER_DATA_DIR=/home/vm-monitor-worker TMPDIR=/home/vm-monitor-worker/tmp
CMD ["node", "src/main.mjs"]
