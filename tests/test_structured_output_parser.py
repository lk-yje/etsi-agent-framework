from pydantic import BaseModel

from framework.agent_runner import _parse_structured_output


class _Schema(BaseModel):
    clause_id: str
    verdict: str


def test_parser_accepts_json_wrapped_by_compatible_model_prose():
    text = '分析完成。\n```JSON\n{"clause_id":"5.5-1","verdict":"PASS"}\n```\n以上。'

    assert _parse_structured_output(text, _Schema) == {
        "clause_id": "5.5-1",
        "verdict": "PASS",
    }


def test_parser_never_repairs_a_schema_invalid_object():
    assert _parse_structured_output('{"clause_id":"5.5-1"}', _Schema) is None
