"""Single assembly point for direct-Qwen instructions and request data.

Retrieval, fact selection, rule evaluation and validation remain backend-owned.
This module neither calls tools nor changes the selected answer plan.
"""
import json
import re

from qwen_evidence import task_question

PROMPT_REVISION = 'qwen-policy-2'


def _action_requested(question):
    # Preserve the existing chat scope selector; this refactor adds no router.
    return bool(re.search(
        r'대응|조치|완화|방어|복구|차단|해결|명령어|커맨드|설정|CLI|어떻게\s*(?:해야|막|처리)',
        question, re.IGNORECASE))


def _scope(question, question_only):
    if _action_requested(question):
        return ('[이번 답변 범위]\n요청한 대응·조치 범위에서 확인된 사실과 미확인 사항을 먼저 설명한다. '
                '필요한 확인·조사, 변경이 필요한 경우의 조치, 재확인·되돌리기를 요청 범위에 맞게 제시한다. '
                '명령어를 요청했다면 실행할 노드·목적·확인할 결과를 함께 설명한다. '
                '읽기 전용 확인과 변경 명령을 구분한다. 읽기 전용 확인만 요청했다면 변경 절차를 추가하지 않는다. '
                '질문에서 지정한 길이와 형식을 따르고 무관한 공격 설명·긴 일반론을 추가하지 않는다.')
    if question_only:
        return ('[이번 답변 범위]\n최신 질문에 필요한 사실과 한계만 직접 답한다. '
                '선택 로그·이전 질문·조회 자료 때문에 답변 범위를 확대하지 않는다. '
                '좁은 질문에는 간결하게 답하고 상세한 근거를 요청하면 해당 항목을 충분히 설명한다.')
    return ('[이번 답변 범위]\n제공된 실제 로그와 온톨로지 근거로 요청한 분석을 수행한다. '
            '공격 여부, 관련 ATT&CK, 탐지 근거, 불확실성, 방어·완화 방법 중 요청에 필요한 항목을 설명한다.')


def _output_contract(model_keys, fixed, answer_plan, missing_plan, deep_plan=None):
    # These mutually exclusive contracts follow the existing backend plans.
    if missing_plan:
        return ('[이번 API 출력 계약: 미등록 조회]\n'
                '실제 조회 결과인 아래 JSON 객체를 값과 타입을 유지하여 그대로 반환한다. '
                '추가 필드나 설명을 넣지 않고 explanation은 빈 문자열로 둔다. '
                '최종 설명과 사용자 요청 필드는 백엔드가 구성한다.\n'
                + json.dumps(missing_plan['expected_response'], ensure_ascii=False))
    if deep_plan is not None:
        return ('[이번 API 출력 계약: 심층 분석]\n'
                'JSON 객체 {"answers":{},"explanation":"사용자에게 보여줄 완성된 분석 본문","fact_ids":[]}를 반환한다. '
                'explanation은 반드시 비어 있지 않은 문자열이어야 한다. 질문의 비교·의미·판단 요구에 직접 답하고 '
                '확인된 사실과 추정·미확인을 구분한다. 일반 심층 분석은 실제 증거, 관련 기법, 판단의 한계, 필요한 대응을 설명한다. '
                'answers에 설명을 대신 넣지 않는다. answers에 넣을 키는 ' + json.dumps(model_keys)
                + '이며 다른 키를 만들지 않는다. 백엔드가 조립할 값은 ' + json.dumps(fixed, ensure_ascii=False) + '이다. '
                'fact_ids에는 아래 required_fact_ids를 빠짐없이 한 번씩 넣는다. 이 사실 문장들은 본문 뒤에 서버가 표시한다. '
                '본문은 이 사실들을 왜곡하거나 반박하지 말고 질문에 대한 해석과 결론을 제시한다. '
                '전술의 의미를 설명할 때는 reference_definitions의 실제 설명을 따른다. '
                '명칭·소속·값·비교·필드 의미를 확인하는 좁은 질문에는 요청하지 않은 추가 의견, '
                '다른 분류 체계에 대한 추측이나 일반 권고를 덧붙이지 않는다. '
                '원본 ID 목록을 본문에 모두 반복할 필요는 없다. 근거가 없으면 확인 불가의 이유와 필요한 근거를 설명한다.\n'
                + json.dumps(deep_plan, ensure_ascii=False))
    if answer_plan:
        return ('[이번 API 출력 계약: 사실 선택]\n'
                '아래 required_fact_ids를 모두 포함하는 JSON만 반환한다: '
                '{"fact_ids":["필수 사실 ID",...],"explanation":""}. '
                '새 ID나 추가 설명을 만들지 않는다. 최종 문장은 백엔드가 조회값으로 구성한다.\n'
                + json.dumps(answer_plan, ensure_ascii=False))
    return ('[이번 API 출력 계약: 일반 답변]\n'
            'JSON 객체 {"answers":{...},"explanation":"답변 본문"}만 반환한다. '
            '영문 응답 키를 지정하지 않은 일반 질문은 answers를 비우고 explanation에 답한다. '
            '모델이 answers에 채울 키: ' + json.dumps(model_keys) + '. 다른 키를 추가하지 않는다. '
            '백엔드가 조립할 값: ' + json.dumps(fixed, ensure_ascii=False) + '.')


def _glance_reference(question, event_type):
    if not _action_requested(question) or event_type not in (
            'image.member.create', 'image.member.delete', 'image.send'):
        return ''
    # Existing syntax reference, moved unchanged in scope; not execution evidence.
    return ('[Glance 이미지 공유 이벤트의 OpenStack CLI 문법 참고]\n'
            '읽기 전용: `openstack image show <IMAGE_ID> -f yaml`; '
            '`openstack image member list <IMAGE_ID> -f table`. '
            '승인 후 공유 해제가 필요한 경우에만: '
            '`openstack image remove project <IMAGE_ID> <TARGET_PROJECT_ID>`. '
            '실제 IMAGE_ID 및 대상 PROJECT_ID는 원본 로그/API에서 먼저 확인한다. '
            '이 참고는 공격 증거나 명령 실행 결과가 아니다.')


def _command_analysis_evidence(value):
    """Keep action meaning/provenance; command text is rendered by the server."""
    if isinstance(value, list):
        return [_command_analysis_evidence(v) for v in value]
    if isinstance(value, dict):
        return {k: _command_analysis_evidence(v) for k, v in value.items()
                if k not in ('command', 'rollback', 'command_template', 'rollback_template')}
    return value


def build_messages(policy, prompt, context, evidence, assessment, model_keys,
                   fixed, answer_plan, missing_plan, execution, field_requirements=(), deep_plan=None, command_block=None,
                   claim_plan=None):
    question = task_question(str(context.get('question') or prompt))
    system = '\n\n'.join((policy, _scope(question, context.get('question_only', False)),
                          _output_contract(model_keys, fixed, answer_plan, missing_plan, deep_plan)))
    if field_requirements and not answer_plan:
        system += ('\n[이번 질문의 필수 원본 필드]\n아래 필드는 이번 선택 로그에서 확인한 값이다. '
                   '요청된 항목을 모두 답하고, 없는 필드와 값 충돌은 해당 필드별로 확인 불가라고 명시한다.\n'
                   + json.dumps(field_requirements, ensure_ascii=False))
    metadata = {'prompt_revision': PROMPT_REVISION}
    if claim_plan is not None:
        from qwen_claim_checks import claim_instructions
        system += '\n\n' + claim_instructions(claim_plan)
        metadata['claim_contract_revision'] = 'grounded-claims-1'
    if command_block is not None:
        system += ('\n[명령어 표시 담당]\n명령문·대상 ID·조회된 복구 명령은 서버가 실제 조회 결과로 별도 표시한다. '
                   'explanation에는 질문에 필요한 판단, 조치의 이유와 미확인 사항을 자연스러운 한국어로 설명한다. '
                   '명령문, CLI 옵션, 코드블록, 실행 예시를 작성하거나 복구 명령을 새로 만들지 않는다. '
                   '짧은 명령어 질문이면 설명도 간결하게 한다. 서버의 표시 절차나 이 지침을 사용자에게 해설하지 않는다. '
                   '조회되지 않은 명령·복구 방법·현재 상태를 추정하지 않는다. '
                   '출력 JSON에는 command_ids 배열도 넣고, 최신 질문에 필요한 명령의 ID만 선택한다. '
                   '한 가지 조치만 물으면 무관한 조치를 선택하지 않는다. 해당 명령이 없으면 빈 배열로 두고 그 한계를 설명한다. '
                   '아래 목록은 표시할 항목이며 조치가 반드시 필요하다는 판정이 아니다.\n'
                   + json.dumps([{'id': r['id'], '항목': r['label'], '종류': r['kind'], '목적': r['purpose'],
                                  '미확인 값': r['missing'], '조회된 복구 명령 있음': bool(r['rollback'])}
                                 for r in command_block['commands']], ensure_ascii=False))
        metadata['command_output_owner'] = 'server'
    if deep_plan is not None:
        metadata['deep_prompt_revision'] = 'deep-quality-1'
    if missing_plan:
        # Keep the existing minimal context for explicit missing-ID questions.
        requested = {row['requested_id'] for row in missing_plan['expected_response']['lookup_results']}
        model_evidence = [{'tool': item['tool'], 'arguments': item['arguments'],
            'result': {key: item['result'][key] for key in ('id', 'found', 'name') if key in item['result']}}
            for item in evidence if item['tool'] == 'lookup_technique'
            and item['arguments'].get('technique_id') in requested]
        metadata.update(model_context_policy='requested_technique_lookups_only',
                        model_evidence_tools=[item['tool'] for item in model_evidence])
        return [{'role': 'system', 'content': system}, {'role': 'user', 'content':
            '[요청한 ID의 실제 온톨로지 조회 결과]\n' + json.dumps(model_evidence, ensure_ascii=False)
            + '\n[지금 답할 사용자 질문]\n' + question}], metadata

    raw = context.get('raw_event') or {}
    inputs = {'event_type': context.get('event_type') or 'unknown',
              'outcome': context.get('outcome') or 'unknown',
              'previous_user_questions': context.get('previous_questions') or ''}
    # Preserve the existing dashboard input excerpt limit.
    if raw:
        inputs['input_log_excerpt'] = json.dumps(raw, ensure_ascii=False, default=str)[:5000]
    if prompt != context.get('question'):
        inputs['request_context'] = prompt
    reference = '' if command_block is not None else _glance_reference(question, context.get('event_type'))
    model_evidence = _command_analysis_evidence(evidence) if command_block is not None else evidence
    body = ('[선택 로그와 이전 사용자 질문: 맥락 자료]\n' + json.dumps(inputs, ensure_ascii=False)
            + ('\n' + reference if reference else '')
            + '\n[백엔드 실제 조회 결과: 사건 발생 증거와 구분]\n' + json.dumps(model_evidence, ensure_ascii=False)
            + '\n[백엔드 규칙 평가]\n' + json.dumps(assessment, ensure_ascii=False)
            + '\n[실행 사실]\n' + json.dumps(execution, ensure_ascii=False)
            + '\n[지금 답할 사용자 질문 — 이전 질문에 다시 답하지 말 것]\n' + question)
    return [{'role': 'system', 'content': system}, {'role': 'user', 'content': body}], metadata


def repair_message(errors):
    return {'role': 'user', 'content':
            '다음 실제 검증 오류를 수정하라. 백엔드 판정과 조회 근거만 사용하고 없는 내용을 만들지 마라. '
            '원래 사용자 질문에 대한 교정된 답변만 반환하라. 이전 후보의 오류나 수정 과정을 답변에 해설하지 마라. '
            '인용 검사에서 exists 또는 in_context가 true가 아닌 ID와 관련 서술은 최종 답변에서 제거하라. '
            '그 ID의 올바른 이름을 해설하기 위해 다시 인용하지 마라. 질문과 무관한 ID를 새로 추가하지 마라.\n'
            + '\n'.join(errors)}
