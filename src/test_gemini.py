import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise SystemExit("GEMINI_API_KEY .env mein nahi mili")

client = genai.Client(api_key=api_key)

response = client.models.generate_content(
    model="gemini-flash-lite-latest",
    contents="You are a SOC analyst. Explain an SSH brute-force attack in two sentences."
)

print("Gemini API connection successful!")
print(response.text)
