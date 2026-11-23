"""Account-specific model discovery and text inference over Responses SSE."""

import json

import httpx

from siwc import AppError, RESOURCE, RemoteError, bearer, check_http, diagnostic, object_body


def list_models(http, token):
    response = http.get(RESOURCE + "/models", headers=bearer(token))
    check_http(response, "Model list")
    models = object_body(response).get("models")
    if not isinstance(models, list):
        raise AppError("OpenAI did not return a ChatGPT plan model catalog.")
    return [
        (model["slug"], model.get("display_name") or model["slug"])
        for model in models
        if isinstance(model, dict) and model.get("visibility") == "list"
        and isinstance(model.get("slug"), str) and model["slug"]
    ]


def response_events(response):
    data_lines = []
    for line in response.iter_lines():
        if line.startswith("data:"):
            data_lines.append(line[5:].removeprefix(" "))
        elif not line and data_lines:
            try:
                payload = json.loads("\n".join(data_lines))
            except ValueError:
                raise AppError("OpenAI returned an invalid inference event.") from None
            if not isinstance(payload, dict):
                raise AppError("OpenAI returned an invalid inference event.")
            yield payload
            data_lines.clear()


def infer(http, token, model, prompt):
    request_body = {
        "model": model,
        "input": [{"role": "user", "content": prompt}],
        "store": False,
        "stream": True,
    }
    text, refusals = [], []
    with http.stream(
        "POST", RESOURCE + "/responses", json=request_body,
        headers={**bearer(token), "Accept": "text/event-stream"},
    ) as response:
        check_http(response, "Inference")
        request_id = diagnostic(response.headers.get("x-request-id"))
        reference = f" (request ID {request_id})" if request_id else ""
        if response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "text/event-stream":
            raise AppError("OpenAI did not return an inference stream" + reference + ".")
        response.encoding = "utf-8"
        try:
            for event in response_events(response):
                kind = event.get("type")
                delta = event.get("delta")
                if kind == "response.output_text.delta" and isinstance(delta, str):
                    text.append(delta)
                elif kind == "response.refusal.delta" and isinstance(delta, str):
                    refusals.append(delta)
                elif kind == "response.completed":
                    return "".join(text or refusals)
                elif kind in ("response.failed", "response.incomplete", "error"):
                    detail = event.get("response")
                    error = detail.get("error") if isinstance(detail, dict) else event
                    reason = detail.get("incomplete_details") if isinstance(detail, dict) else None
                    fields = error if isinstance(error, dict) else {}
                    code = fields.get("code")
                    if not code and isinstance(reason, dict):
                        code = reason.get("reason")
                    raise RemoteError(kind, response.status_code, code, request_id, param=fields.get("param"))
        except httpx.RequestError:
            raise AppError("Inference stream was interrupted" + reference + ".") from None
    raise AppError("Inference ended before the completion event" + reference + ".")
