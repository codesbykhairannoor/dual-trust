"""DualTrust Multi-Agent Framework Adapters (LangChain, LangGraph, CrewAI, AutoGen, OpenAI)."""

from dualtrust.adapters.crewai import guard_crewai_tool
from dualtrust.adapters.langchain import DualTrustCallbackHandler
from dualtrust.adapters.mcp import DualTrustMCPGateway
from dualtrust.adapters.openai import OpenAIToolDispatcher

__all__ = [
    "DualTrustCallbackHandler",
    "OpenAIToolDispatcher",
    "DualTrustMCPGateway",
    "guard_crewai_tool",
]
