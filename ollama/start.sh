#!/bin/bash

echo "🚀 Starting Ollama server..."

# Start ollama in background
ollama serve &

# 🔥 Wait until API is actually ready
echo "⏳ Waiting for Ollama to be ready..."

until curl -s http://localhost:11434/api/tags > /dev/null; do
  sleep 2
done

echo "✅ Ollama is ready!"

# 🔥 Pull model ONLY if not already present
if ! ollama list | grep -q "qwen:1.8b"; then
  echo "📥 Pulling Qwen model..."
  ollama pull qwen:1.8b
else
  echo "✅ Model already exists, skipping pull"
fi

echo "🚀 Ollama fully ready"

# Keep container alive
wait