

from huggingface_hub import InferenceClient
print("Hello World")
client = InferenceClient(
    "h2oai/h2o-danube3-4b-chat",
    token="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",
)
print("Hello World")

for message in client.chat_completion(
	messages=[{"role": "user", "content": "What is the capital of France?"}],
	max_tokens=500,
	stream=True,
):
    print(message.choices[0].delta.content, end="")