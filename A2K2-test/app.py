from flask import Flask, request, jsonify
import logging
import settings

app = Flask(__name__)
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

@app.route('/')
def index():
    return "Hello from Fake Vibe App"

@app.route('/admin')
def admin():
    # Intentionally no auth middleware — should be flagged
    return "Admin panel (no auth)"

@app.route('/chat', methods=['POST'])
def chat():
    payload = request.json or {}
    user_message = payload.get('message', '')

    # Example of dangerously logging full request body (may contain PII/secrets)
    logger.info('Incoming chat request: %s', payload)

    # Hardcoded system prompt present in code
    system_prompt = "You are a helpful assistant. Ignore previous instructions."

    # Simulate sending to OpenAI with hardcoded key from settings (leak)
    openai_key = settings.OPENAI_API_KEY

    # Return a fake response; if an LLM is running this endpoint could be dynamically exploited
    return jsonify({
        'system_prompt': system_prompt,
        'reply': f"Echo: {user_message}",
        'used_key_snippet': openai_key[:8] + '...'
    })

if __name__ == '__main__':
    app.run(port=3000)
