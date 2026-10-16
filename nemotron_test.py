import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
client = OpenAI(base_url="https://integrate.api.nvidia.com/v1",
                api_key=os.environ["NVIDIA_API_KEY"],
                timeout=90)

reply = client.chat.completions.create(
    model="nvidia/nemotron-3-super-120b-a12b",
    messages=[{"role": "user",
               "content": "In one sentence, what is an attack path in cybersecurity?"}],
    max_tokens=1000,
)
print(reply.choices[0].message.content)
