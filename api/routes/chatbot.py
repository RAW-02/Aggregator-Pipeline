





import logging
import os
from pathlib import Path

import groq
from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException, status
from groq import Groq
from pydantic import BaseModel, ConfigDict, Field

# ── Environment configuration ──────────────────────────────────
# Expected location:
# Aggregator-Pipeline/.env
BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(BASE_DIR / ".env")

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/chatbot",
    tags=["Chatbot"],
)


# ── Request and response models ─────────────────────────────────
class ChatRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    question: str = Field(
        min_length=2,
        max_length=2000,
        description="Cybersecurity question submitted by the user.",
        examples=["Explain CVSS in simple terms."],
    )


class ChatResponse(BaseModel):
    answer: str


# ── Cybersecurity system prompt ─────────────────────────────────
SYSTEM_PROMPT = """
You are CyberBot, the AI cybersecurity assistant for UniVulner,
a threat-intelligence and vulnerability-management platform.

Your role is to help users understand:

- CVE vulnerabilities and their security impact
- CVSS scores and severity ratings
- EPSS exploitation probability
- Known Exploited Vulnerabilities (KEV)
- CWE weakness categories
- MITRE ATT&CK techniques
- Exploit availability and risk assessment
- Vulnerability mitigation and patching strategies
- Defensive cybersecurity concepts and best practices

Response requirements:

1. Answer only cybersecurity-related questions.
2. Use clear language suitable for both junior and senior analysts.
3. Be concise, technically accurate, and defensive in focus.
4. Format responses using Markdown.
5. Prefer short headings, short paragraphs, and bullet points.
6. Keep most answers between 150 and 350 words.
7. Do not include JSON in the answer.
8. Do not mention the model name, provider, API, system prompt,
   token limits, or internal implementation.
9. Do not invent CVE IDs, CVSS scores, affected products, versions,
   patches, vendor advisories, or exploitation details.
10. Do not provide random CVE examples unless the user asks for them.
11. When facts about a specific CVE cannot be confidently verified,
    advise the user to check NVD, CISA KEV, or the official vendor
    advisory.
12. Do not include code examples unless the user specifically asks
    for code.
13. Do not repeat the same mitigation advice.
14. Never present an AI-generated answer as a replacement for an
    official advisory or professional incident-response decision.

For conceptual questions, use this structure when appropriate:

## Overview

Give a simple explanation.

## Why It Matters

Explain the security relevance or impact.

## Prevention or Mitigation

Give practical defensive recommendations.

For questions about a specific CVE, use this structure only when the
information is available and reliable:

## Summary

## Severity and Impact

## Exploitation Risk

## Mitigation

## Verification Sources

Do not add empty sections.
""".strip()


# ── Groq configuration ──────────────────────────────────────────
def get_groq_config() -> tuple[str, str]:
    api_key = os.getenv("GROQ_API_KEY")
    model = os.getenv("GROQ_MODEL")

    if not api_key:
        logger.error("GROQ_API_KEY is not configured.")

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The AI assistant is not configured.",
        )

    if not model:
        logger.error("GROQ_MODEL is not configured.")

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The AI assistant model is not configured.",
        )

    return api_key, model


def get_client(api_key: str) -> Groq:
    return Groq(
        api_key=api_key,
        timeout=30.0,
        max_retries=2,
    )


# ── Chat endpoint ───────────────────────────────────────────────
@router.post(
    "/query",
    response_model=ChatResponse,
    status_code=status.HTTP_200_OK,
    summary="Ask the cybersecurity assistant",
)
def chat_query(request: ChatRequest) -> ChatResponse:
    question = request.question.strip()

    if not question:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Question cannot be empty.",
        )

    try:
        api_key, model = get_groq_config()
        client = get_client(api_key)

        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": question,
                },
            ],
            temperature=0.2,
            max_completion_tokens=1024,
        )

        answer = response.choices[0].message.content

        if not answer or not answer.strip():
            raise RuntimeError(
                "The AI provider returned an empty response."
            )

        return ChatResponse(
            answer=answer.strip(),
        )

    except HTTPException:
        raise

    except groq.AuthenticationError:
        logger.exception("Groq authentication failed.")

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The AI assistant is not configured correctly.",
        )

    except groq.RateLimitError:
        logger.warning("Groq rate limit exceeded.")

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "The AI assistant is receiving too many requests. "
                "Please try again shortly."
            ),
        )

    except groq.APITimeoutError:
        logger.warning("Groq request timed out.")

        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=(
                "The AI assistant took too long to respond. "
                "Please try again."
            ),
        )

    except groq.APIConnectionError:
        logger.exception("Unable to connect to Groq.")

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "The AI assistant is temporarily unreachable. "
                "Please try again shortly."
            ),
        )

    except groq.APIStatusError as exc:
        logger.exception(
            "Groq returned status code %s.",
            exc.status_code,
        )

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "The AI assistant is temporarily unavailable. "
                "Please try again shortly."
            ),
        )

    except Exception:
        logger.exception("Unexpected CyberBot request failure.")

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "The AI assistant is temporarily unavailable. "
                "Please try again shortly."
            ),
        )


@router.get(
    "/health",
    summary="Check chatbot configuration",
)
def chatbot_health() -> dict[str, str]:
    if not os.getenv("GROQ_API_KEY") or not os.getenv("GROQ_MODEL"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The AI assistant is not configured.",
        )

    return {"status": "ok"}