from __future__ import annotations

import os
import time
from dotenv import load_dotenv
from google import genai
from google.genai import types

from src.config.logging_config import setup_logger

logger = setup_logger()
load_dotenv()


class GeminiClient:
    """
    Client responsible for communicating with Google's Gemini API
    using the official google-genai SDK.
    """

    def __init__(
        self,
        model: str = "gemini-3.1-flash-lite",
        api_key: str | None = None,
        system_instruction: str | None = None,
    ) -> None:

        self.model = model
        self.api_key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        self.system_instruction = system_instruction

        if not self.api_key:
            raise ValueError(
                "GEMINI_API_KEY environment variable is not set. "
                "Please set GEMINI_API_KEY in your environment or .env file."
            )

        self.client = genai.Client(api_key=self.api_key)

        logger.info("=" * 50)
        logger.info("GEMINI CLIENT INITIALIZED")
        logger.info("=" * 50)
        logger.info(f"Model : {self.model}")

    def generate(
        self,
        prompt: str,
        system_instruction: str | None = None,
    ) -> str:
        """
        Send a prompt to Gemini API via google-genai SDK and return the generated response.
        """

        if not prompt or not prompt.strip():
            raise ValueError(
                "Prompt cannot be empty."
            )

        logger.info("=" * 50)
        logger.info("LLM GENERATION")
        logger.info("=" * 50)
        logger.info(
            f"Model : {self.model}"
        )
        logger.info(
            f"Prompt Length : {len(prompt)} characters"
        )

        start_time = time.time()
        max_retries = 3

        sys_inst = system_instruction or self.system_instruction
        config_kwargs = {"temperature": 0.0}
        if sys_inst:
            config_kwargs["system_instruction"] = sys_inst

        for attempt in range(1, max_retries + 1):
            try:
                response = self.client.models.generate_content(
                    model=self.model,
                    contents=prompt,
                    config=types.GenerateContentConfig(**config_kwargs),
                )

                generated_response = response.text or ""
                elapsed = time.time() - start_time

                logger.info(
                    "LLM GENERATION COMPLETE"
                )

                logger.info(
                    f"Response Length : "
                    f"{len(generated_response)} characters"
                )

                logger.info(
                    f"Generation Time : {elapsed:.2f} seconds"
                )

                return generated_response

            except Exception as exc:
                err_str = str(exc)
                if ("503" in err_str or "UNAVAILABLE" in err_str or "429" in err_str) and attempt < max_retries:
                    wait_time = attempt * 3 if "429" not in err_str else 60
                    logger.warning(
                        f"Transient Gemini error on attempt {attempt}/{max_retries}. Retrying in {wait_time}s... ({exc})"
                    )
                    time.sleep(wait_time)
                    continue

                logger.error(
                    f"LLM generation failed on attempt {attempt}: {exc}"
                )
                raise
