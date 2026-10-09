from fmb.question_packs import load_packs

_DEFINITIONS = {pack["question_id"]: pack["definition"] for pack in load_packs()}

TARGET_QUESTIONS = {qid: {"title": d["title"], "question_text": d["question_text"]} for qid, d in _DEFINITIONS.items()}
QUESTION_SCOPES = {qid: d["scope"] for qid, d in _DEFINITIONS.items() if "scope" in d}
