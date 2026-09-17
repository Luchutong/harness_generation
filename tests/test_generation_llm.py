import json
from pathlib import Path
import tempfile
import unittest

from harness_generation.llm import (
    FakeLLM,
    LLMClient,
    LLMConfig,
    LLMError,
    LLMGeneration,
    MockLLM,
    OpenAICompatibleLLM,
    RecordedResponseLLM,
    write_recorded_responses,
)
from harness_generation.prompts import stage1_function_doc


def _prompt():
    return stage1_function_doc(
        function_signature="int parse(const unsigned char *data)",
        function_source="int parse(const unsigned char *data) { return data != 0; }",
        usage_context={"role": "ISF"},
    )


class LLMAbstractionTests(unittest.TestCase):
    def test_mock_and_fake_are_deterministic_and_offline(self):
        prompt = _prompt()
        mock = MockLLM(["first", "second"])
        self.assertIsInstance(mock, LLMClient)

        first = mock.generate(prompt)
        second = mock.generate("plain prompt", prompt_version="manual-v3")
        self.assertEqual(first.content, "first")
        self.assertEqual(first.prompt_version, "stage1-function-doc-v1")
        self.assertEqual(first.to_dict()["prompt_version"], prompt.prompt_version)
        self.assertEqual(first.metadata["prompt_name"], "stage1_function_doc")
        self.assertEqual(second.content, "second")
        self.assertEqual(second.prompt_version, "manual-v3")
        self.assertEqual([call["prompt_version"] for call in mock.calls],
                         ["stage1-function-doc-v1", "manual-v3"])
        with self.assertRaisesRegex(LLMError, "exhausted"):
            mock.generate(prompt)

        fake = FakeLLM(["offline"])
        self.assertEqual(fake.generate(prompt).content, "offline")

    def test_plain_prompt_requires_an_explicit_version(self):
        with self.assertRaisesRegex(ValueError, "prompt_version is required"):
            MockLLM(["unused"]).generate("unversioned")

    def test_recorded_response_replay_preserves_metadata(self):
        response = LLMGeneration(
            content="recorded output",
            model="recorded-model",
            prompt_version="stage1-function-doc-v1",
            provider="recorded-fixture",
            response_id="response-1",
            finish_reason="stop",
            usage={"total_tokens": 12},
            metadata={"experiment": "baseline"},
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "responses.json"
            write_recorded_responses(path, [response])
            document = json.loads(path.read_text(encoding="utf-8"))
            replay = RecordedResponseLLM.from_file(path)

        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(document["responses"][0]["prompt_version"],
                         "stage1-function-doc-v1")
        generated = replay.generate(_prompt())
        self.assertEqual(generated, response)
        self.assertEqual(generated.metadata["experiment"], "baseline")
        with self.assertRaisesRegex(LLMError, "exhausted"):
            replay.generate(_prompt())

    def test_recorded_response_rejects_prompt_version_mismatch(self):
        replay = RecordedResponseLLM([
            LLMGeneration("output", "model", "different-v1", "recorded")
        ])
        with self.assertRaisesRegex(LLMError, "version mismatch"):
            replay.generate(_prompt())

    def test_openai_compatible_client_uses_config_and_injected_transport(self):
        captured = {}

        def transport(url, payload, headers, timeout):
            captured.update(
                url=url,
                payload=payload,
                headers=headers,
                timeout=timeout,
            )
            return {
                "id": "chatcmpl-test",
                "model": "served-model",
                "choices": [{
                    "finish_reason": "stop",
                    "message": {"content": "generated C"},
                }],
                "usage": {"prompt_tokens": 20, "completion_tokens": 3},
            }

        config = LLMConfig(
            model="configured-model",
            base_url="http://localhost:9000/v1/",
            api_key_env_name="UNIT_TEST_LLM_KEY",
            temperature=0.35,
            max_tokens=777,
            timeout=9.5,
            thinking="disabled",
        )
        client = OpenAICompatibleLLM(
            config,
            transport=transport,
            environ={"UNIT_TEST_LLM_KEY": "unit-test-placeholder"},
        )
        generated = client.generate(_prompt())

        self.assertEqual(captured["url"], "http://localhost:9000/v1/chat/completions")
        self.assertEqual(captured["payload"]["model"], "configured-model")
        self.assertEqual(captured["payload"]["temperature"], 0.35)
        self.assertEqual(captured["payload"]["max_tokens"], 777)
        self.assertFalse(captured["payload"]["stream"])
        self.assertEqual(captured["payload"]["thinking"], {"type": "disabled"})
        self.assertEqual(captured["timeout"], 9.5)
        self.assertEqual(captured["headers"]["Authorization"],
                         "Bearer unit-test-placeholder")
        self.assertEqual(generated.content, "generated C")
        self.assertEqual(generated.model, "served-model")
        self.assertEqual(generated.prompt_version, "stage1-function-doc-v1")
        self.assertEqual(generated.response_id, "chatcmpl-test")
        self.assertEqual(generated.usage["prompt_tokens"], 20)
        self.assertEqual(generated.metadata["temperature"], 0.35)
        self.assertEqual(generated.metadata["max_tokens"], 777)

        serialized_config = config.to_dict()
        self.assertEqual(serialized_config["api_key_env_name"], "UNIT_TEST_LLM_KEY")
        self.assertNotIn("api_key", serialized_config)
        self.assertNotIn("unit-test-placeholder", json.dumps(serialized_config))

    def test_openai_compatible_response_redacts_api_key_before_persistence(self):
        client = OpenAICompatibleLLM(
            LLMConfig("model", "https://example.test/v1", api_key_env_name="KEY"),
            transport=lambda *_args: {
                "id": "response-secret-value",
                "model": "model-secret-value",
                "usage": {"provider_note": "secret-value"},
                "choices": [{"message": {"content": "leaked secret-value"}}],
            },
            environ={"KEY": "secret-value"},
        )
        generated = client.generate(_prompt())
        self.assertEqual(generated.content, "leaked [REDACTED]")
        self.assertNotIn("secret-value", json.dumps(generated.to_dict()))

    def test_openai_compatible_client_fails_before_transport_without_key(self):
        called = False

        def transport(*_args):
            nonlocal called
            called = True
            return {}

        client = OpenAICompatibleLLM(
            LLMConfig("model", "https://llm.example.test/v1",
                      api_key_env_name="MISSING_TEST_KEY"),
            transport=transport,
            environ={},
        )
        with self.assertRaisesRegex(LLMError, "MISSING_TEST_KEY"):
            client.generate(_prompt())
        self.assertFalse(called)

    def test_config_validation(self):
        invalid = (
            {"model": "", "base_url": "https://example.test/v1"},
            {"model": "m", "base_url": "not-a-url"},
            {"model": "m", "base_url": "https://example.test", "temperature": 2.1},
            {"model": "m", "base_url": "https://example.test", "max_tokens": 0},
            {"model": "m", "base_url": "https://example.test", "timeout": 0},
            {"model": "m", "base_url": "https://example.test", "max_tokens": 1.5},
            {"model": "m", "base_url": "https://example.test", "temperature": True},
            {"model": "m", "base_url": "https://example.test", "thinking": "sometimes"},
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                LLMConfig(**arguments)


if __name__ == "__main__":
    unittest.main()
