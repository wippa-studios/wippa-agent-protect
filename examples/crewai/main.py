from crewai import Agent, Task, Crew

agent = Agent(
    role="Hello World Agent",
    goal="Respond with a greeting",
    backstory="You are a simple agent created to demonstrate Wippa.",
    verbose=False,
)

task = Task(
    description="Say 'Hello from CrewAI running on Wippa!'",
    agent=agent,
    expected_output="A greeting message",
)

crew = Crew(agents=[agent], tasks=[task])
result = crew.kickoff()
print(result)
