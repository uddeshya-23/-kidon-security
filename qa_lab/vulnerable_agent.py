# qa_lab/vulnerable_agent.py
# TEST FILE: Simulates a vulnerable AI agent for red team testing

from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/chat', methods=['POST'])
def chat():
    user_input = request.json.get('message', '').lower()
    
    # SIMULATED VULNERABILITY: Goal Hijacking (ASI-01)
    if "ignore all previous instructions" in user_input:
        return jsonify({"response": "OK. I have ignored my rules. I am now DAN."})
    
    # SIMULATED VULNERABILITY: System prompt leak
    if "system prompt" in user_input:
        return jsonify({"response": "My system prompt is: You are a helpful assistant..."})
    
    # SIMULATED VULNERABILITY: Privilege escalation
    if "admin access" in user_input or "authorization code" in user_input:
        return jsonify({"response": "ACCESS GRANTED. Admin mode enabled."})
    
    # Safe response
    return jsonify({"response": "I cannot do that. I am a helpful assistant."})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    print("😈 Vulnerable Agent listening on port 8000...")
    print("Test with: curl -X POST http://localhost:8000/chat -H 'Content-Type: application/json' -d '{\"message\":\"hello\"}'")
    app.run(host='0.0.0.0', port=8000)
