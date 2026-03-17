"""
Crypto Guardian — LangGraph Agent Core
PATCHED FOR GOAT + LANGGRAPH

Replaces the old simple LangChain loop with a proper LangGraph StateGraph:
- Stateful conversation with MemorySaver checkpointer
- Parallel tool calling
- Conditional edges (agent → tools → agent → END)
- Thread-based sessions for multi-user support
"""

import os
import json
from typing import Annotated, TypedDict

from langchain_openai import ChatOpenAI
from langchain_core.messages import (
    HumanMessage, AIMessage, SystemMessage, ToolMessage, BaseMessage
)
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.checkpoint.memory import MemorySaver
from langgraph.prebuilt import ToolNode

from agent.system_prompt import SYSTEM_PROMPT
from agent.tools import ALL_TOOLS, set_blockchain_service, set_threat_intel, set_safe_sdk
from agent.session_keys import session_manager

# ── State Schema ─────────────────────────────────────────────
class AgentState(TypedDict):
    """LangGraph state: messages accumulate via add_messages reducer."""
    messages: Annotated[list[BaseMessage], add_messages]


# ── Module-level objects ─────────────────────────────────────
_graph = None
_checkpointer = None


def init_agent(blockchain_service, threat_intel_service=None, safe_sdk_service=None):
    """Initialize the LangGraph agent with tools and memory."""
    global _graph, _checkpointer

    set_blockchain_service(blockchain_service)
    if threat_intel_service:
        set_threat_intel(threat_intel_service)
    if safe_sdk_service:
        set_safe_sdk(safe_sdk_service)

    # 1. Create the LLM
    model = os.getenv("OPENROUTER_MODEL", "x-ai/grok-4.1-fast")
    llm = ChatOpenAI(
        model=model,
        temperature=0.2,
        max_tokens=4096,
        base_url="https://openrouter.ai/api/v1",
        api_key=os.getenv("OPENROUTER_API_KEY", ""),
        default_headers={
            "HTTP-Referer": "http://localhost:3000",
            "X-Title": "Crypto Guardian",
        },
    ).bind_tools(ALL_TOOLS)

    # 2. Define the agent node (calls LLM)
    async def agent_node(state: AgentState):
        """Call the LLM with current messages."""
        messages = state["messages"]

        # Inject system prompt if not already present
        if not messages or not isinstance(messages[0], SystemMessage):
            messages = [SystemMessage(content=SYSTEM_PROMPT)] + messages

        response = await llm.ainvoke(messages)
        return {"messages": [response]}

    # 3. Define the conditional edge
    def should_continue(state: AgentState):
        """Route: if LLM made tool calls → 'tools', else → END."""
        last = state["messages"][-1]
        if hasattr(last, "tool_calls") and last.tool_calls:
            return "tools"
        return END

    # 4. Build the LangGraph StateGraph
    tool_node = ToolNode(ALL_TOOLS)

    graph_builder = StateGraph(AgentState)
    graph_builder.add_node("agent", agent_node)
    graph_builder.add_node("tools", tool_node)

    graph_builder.add_edge(START, "agent")
    graph_builder.add_conditional_edges("agent", should_continue, {"tools": "tools", END: END})
    graph_builder.add_edge("tools", "agent")  # After tools, go back to agent

    # 5. Compile with memory checkpointer
    _checkpointer = MemorySaver()
    _graph = graph_builder.compile(checkpointer=_checkpointer)

    tool_names = [t.name for t in ALL_TOOLS]
    print(f"[Agent] LangGraph brain initialized via OpenRouter ({model})")
    print(f"[Agent] {len(ALL_TOOLS)} tools loaded: {', '.join(tool_names)}")
    print(f"[Agent] Memory: MemorySaver checkpointer active")


async def run_agent(
    message: str,
    wallet_address: str = None,
    chain: str = "ethereum",
    thread_id: str = "default",
) -> dict:
    """Run the LangGraph agent with a user message.

    Args:
        message: User's natural language message
        wallet_address: Connected wallet address (optional)
        chain: Active chain (default: ethereum)
        thread_id: Session ID for conversation persistence
    """
    if not _graph:
        return {
            "response": "⚠️ Agent not initialized. Check your OPENROUTER_API_KEY in .env.",
            "toolsUsed": [],
        }

    # Enrich message with wallet context + session info
    enriched = message
    if wallet_address:
        sk = session_manager.get_or_create_readonly(wallet_address)
        enriched = (
            f"[Connected wallet: {wallet_address} on {chain}]\n"
            f"[Session: {sk.mode.value} | Budget: ${sk.remaining_budget:.2f} | "
            f"Chains: {','.join(sk.allowed_chains)}]\n\n"
            f"{message}"
        )

    # Config with thread_id for memory persistence
    config = {"configurable": {"thread_id": thread_id}}

    tools_used = []

    try:
        # Stream through the graph
        final_response = ""
        async for event in _graph.astream(
            {"messages": [HumanMessage(content=enriched)]},
            config=config,
            stream_mode="values",
        ):
            last_msg = event["messages"][-1]

            # Collect tool calls
            if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
                for tc in last_msg.tool_calls:
                    tools_used.append({
                        "tool": tc["name"],
                        "input": str(tc.get("args", {}))[:100],
                    })

            # Capture final text response
            if isinstance(last_msg, AIMessage) and last_msg.content:
                if not (hasattr(last_msg, "tool_calls") and last_msg.tool_calls):
                    final_response = last_msg.content

        return {
            "response": final_response or "Analysis complete.",
            "toolsUsed": tools_used,
        }

    except Exception as e:
        print(f"[Agent] Error: {e}")
        return {
            "response": (
                f"⚠️ Agent error: {e}\n\n"
                "You can still use the dashboard — paste a wallet address and click Scan."
            ),
            "toolsUsed": tools_used,
        }
