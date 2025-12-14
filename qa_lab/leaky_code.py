# qa_lab/leaky_code.py
# TEST FILE: Contains intentional security vulnerabilities for testing Kidon

def connect():
    # TEST: This should be detected by Kidon Rule A (OpenAI API Key)
    api_key = "sk-proj-1234567890abcdef1234567890abcdef"
    print("Connecting with key:", api_key[:10] + "...")

def aws_connect():
    # TEST: AWS credentials - should be detected
    aws_access_key = "AKIAIOSFODNN7EXAMPLE"
    aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    print("AWS configured")

def github_auth():
    # TEST: GitHub PAT - should be detected
    token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    return token

if __name__ == "__main__":
    connect()
