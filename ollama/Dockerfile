# FROM ollama/ollama:latest

# # Pre-pull model during container start
# RUN mkdir -p /root/.ollama

# # Custom entrypoint script
# COPY start.sh /start.sh
# RUN chmod +x /start.sh

#  ENTRYPOINT ["/start.sh"]

FROM ollama/ollama:latest

# 🔥 Install curl
RUN apt-get update && apt-get install -y curl

COPY start.sh /start.sh
RUN chmod +x /start.sh

ENTRYPOINT ["/start.sh"]