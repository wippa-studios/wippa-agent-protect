from autogen import AssistantAgent, UserProxyAgent

assistant = AssistantAgent(
    name="assistant",
    system_message="You are a helpful assistant. Say 'Hello from AutoGen running on Wippa!'",
)

user_proxy = UserProxyAgent(
    name="user_proxy",
    human_input_mode="NEVER",
    code_execution_config=False,
)

result = user_proxy.initiate_chat(
    assistant,
    message="Please introduce yourself.",
    max_turns=1,
)

print(result.summary)
