import asyncio
import json
import os
import sys

from dotenv import load_dotenv
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from openai import OpenAI

load_dotenv()
client = OpenAI(base_url="https://integrate.api.nvidia.com/v1",
                api_key=os.environ["NVIDIA_API_KEY"], timeout=120)
MODEL = "nvidia/nemotron-3-super-120b-a12b"
SYSTEM = ("You are AttackPath, a security triage agent. Use the tools: "
          "investigate_network first, then remediate_network, then write a "
          "short plain-English report with the routes before and after, the "
          "fixes in order and why. Use only names and numbers the tools return.")
QUESTION = ("Analyze the 'startup' network. Protect Customer Data. "
            "Investigate and fix what you can.")


async def main():
    params = StdioServerParameters(command=sys.executable,
                                   args=["mcp_server.py"])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            print("Tools discovered through MCP:",
                  [t.name for t in listed.tools], flush=True)
            tools = [{"type": "function", "function": {
                "name": t.name, "description": t.description or "",
                "parameters": t.inputSchema}} for t in listed.tools]
            messages = [{"role": "system", "content": SYSTEM},
                        {"role": "user", "content": QUESTION}]
            for step in range(6):
                print(f"  [thinking... step {step + 1}]", flush=True)
                resp = client.chat.completions.create(
                    model=MODEL, messages=messages, tools=tools,
                    tool_choice="auto", max_tokens=1800)
                msg = resp.choices[0].message
                if not msg.tool_calls:
                    print("\nREPORT:\n" + (msg.content or ""))
                    return
                messages.append({
                    "role": "assistant", "content": msg.content or "",
                    "tool_calls": [{"id": c.id, "type": "function",
                                    "function": {"name": c.function.name,
                                                 "arguments": c.function.arguments}}
                                   for c in msg.tool_calls]})
                for call in msg.tool_calls:
                    args = json.loads(call.function.arguments or "{}")
                    print(f"  [agent used MCP tool] {call.function.name} {args}",
                          flush=True)
                    result = await session.call_tool(call.function.name, args)
                    text = "".join(getattr(c, "text", "") for c in result.content)
                    messages.append({"role": "tool", "tool_call_id": call.id,
                                     "content": text})


asyncio.run(main())
