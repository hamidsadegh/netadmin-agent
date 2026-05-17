import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

network_log = """
Interface Gi1/0/24 is down
Line protocol is down
Last input never
Description: Uplink-to-Core
"""

prompt = f"""
You are a senior network administrator.
Analyze this network log and give:
1. Possible root cause
2. Commands to verify
3. Safe next steps

Log:
{network_log}
"""

response = client.models.generate_content(
    model="gemini-2.5-flash",
    contents=prompt
)


print(response.text)
