import os
import time
from crewai import Agent, Crew, Process, Task, LLM
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# ==========================================
# 1. API KEY ROTATION & ENVIRONMENT SETUP
# ==========================================
API_KEYS = [
    os.getenv("GEMINI_API_KEY_1"),
    os.getenv("GEMINI_API_KEY_2")
]

# Filter out None or empty values
ACTIVE_KEYS = [k for k in API_KEYS if k]
key_index = 0

def get_next_api_key():
    """Rotates through available Gemini API keys to prevent rate limits."""
    global key_index
    if not ACTIVE_KEYS:
        return os.getenv("GEMINI_API_KEY")
    key = ACTIVE_KEYS[key_index % len(ACTIVE_KEYS)]
    key_index += 1
    return key

# Set initial active key
os.environ["GEMINI_API_KEY"] = get_next_api_key()

# Configure the LLM using Gemini 3.6 Flash via LiteLLM
llm = LLM(
    model="gemini/gemini-3.6-flash",
    temperature=0.2
)

# ==========================================
# 2. AGENT DEFINITIONS (Narrowly Scoped)
# ==========================================
planner_agent = Agent(
    role="Software Architect",
    goal="Analyze user requirements and output a concise technical specification plan.",
    backstory="Veteran architect specialized in micro-specifications and clean modular design.",
    llm=llm,
    verbose=True
)

developer_agent = Agent(
    role="Backend Developer",
    goal="Write clean, PEP 8 compliant Python code with robust error handling based on the plan.",
    backstory="Senior Python engineer focused on production-ready, resilient backend code.",
    llm=llm,
    verbose=True
)

qa_agent = Agent(
    role="Software Tester",
    goal="Generate comprehensive pytest unit tests and edge cases for the code.",
    backstory="Meticulous QA engineer dedicated to finding boundary conditions and breaking code early.",
    llm=llm,
    verbose=True
)

reviewer_agent = Agent(
    role="Senior Developer",
    goal="Review implementation and tests, identify bugs, and produce the final deliverable.",
    backstory="Strict engineering lead ensuring code quality, security, and maintainability.",
    llm=llm,
    verbose=True
)

# ==========================================
# 3. TASK DEFINITIONS (With output_file & Brevity)
# ==========================================
def create_tasks(requirement_prompt: str):
    planning_task = Task(
        description=f"Analyze requirement: '{requirement_prompt}'. Output a concise architecture blueprint with function signatures under 300 words.",
        expected_output="Markdown architecture document.",
        agent=planner_agent,
        output_file="architecture_plan.md"
    )

    coding_task = Task(
        description="Using the architecture plan, generate modular Python code with exception handling. Max 400 lines.",
        expected_output="Python source code block.",
        agent=developer_agent,
        output_file="generated_code.py"
    )

    testing_task = Task(
        description="Write a complete pytest unit test suite covering normal paths and edge cases for the generated code.",
        expected_output="Python pytest file.",
        agent=qa_agent,
        output_file="test_code.py"
    )

    review_task = Task(
        description="Review source code and tests for bugs or security flaws, and compile a final executive development report.",
        expected_output="Final code review report.",
        agent=reviewer_agent,
        output_file="development_report.md"
    )

    return [planning_task, coding_task, testing_task, review_task]

# ==========================================
# 4. RESILIENT EXECUTION WITH RETRY & ROTATION
# ==========================================
def run_dev_crew(requirement_prompt: str, max_retries: int = 3, backoff_delay: int = 5):
    """
    Executes the crew pipeline with retry-enabled error handling,
    backoff delays, and dynamic API key rotation on failure.
    """
    tasks = create_tasks(requirement_prompt)
    dev_crew = Crew(
        agents=[planner_agent, developer_agent, qa_agent, reviewer_agent],
        tasks=tasks,
        process=Process.sequential,
        verbose=True
    )

    attempt = 0
    while attempt < max_retries:
        try:
            print(f"\n[Execution] Starting crew run with Gemini 3.6 Flash (Attempt {attempt + 1}/{max_retries})...")
            result = dev_crew.kickoff()
            print("\n[Success] Crew execution completed successfully. Artifacts saved to disk.")
            return result
        except Exception as e:
            attempt += 1
            print(f"\n[Warning] Execution failed with error: {str(e)}")
            
            if attempt < max_retries:
                new_key = get_next_api_key()
                os.environ["GEMINI_API_KEY"] = new_key
                print(f"[Rotation] Switched to alternative API key. Waiting {backoff_delay}s before retry...")
                time.sleep(backoff_delay)
                backoff_delay *= 2
            else:
                print("\n[Error] Maximum retry attempts reached. Workflow aborted.")
                raise e

# ==========================================
# 5. EXECUTION ENTRYPOINT
# ==========================================
if __name__ == "__main__":
    sample_requirement = "Build a robust Python utility module that securely parses, validates, and batch-processes incoming JSON log files with comprehensive error logging."
    
    # Run the automated pipeline
    run_dev_crew(sample_requirement)