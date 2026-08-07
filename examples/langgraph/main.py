from langgraph.graph import StateGraph, END
from typing import TypedDict

class State(TypedDict):
    message: str

def greet(state: State) -> State:
    return {"message": "Hello from LangGraph running on Wippa!"}

builder = StateGraph(State)
builder.add_node("greet", greet)
builder.set_entry_point("greet")
builder.add_edge("greet", END)

graph = builder.compile()
result = graph.invoke({"message": ""})
print(result["message"])
