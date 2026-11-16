"""Standalone Qwen API analysis: host retrieval/rules, model prose, final audit.

Uses urllib + the project's CTO backend. No Hermes, MCP runtime, model-selected
tools, shell command execution or evaluation reference answers are loaded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request

from qwen_backend import CTOBackend, load_config, live_lookup_plan
from qwen_coverage import complete_requested_techniques
from qwen_answer_quality import build_log_answer_plan, render_log_answer, completion_errors
from qwen_observed_facts import build_observed_answer_plan, fact_response_format
from qwen_missing_lookup import (build_missing_lookup_plan, render_missing_lookup,
                                 missing_lookup_response_format)
from qwen_evidence import (EvidenceLedger, compact_evidence, final_citation_checks,
    live_lookup_allowed, requested_keys, task_question)
from qwen_rules import assess, assemble_answer
from qwen_prompt import build_messages, repair_message
from qwen_response_checks import requested_fields, extend_fact_plan, field_errors, knowledge_name_errors
from qwen_command_checks import (build_command_plan, command_errors, build_response_command_block,
                                 model_command_block_errors, render_response_command_block,
                                 command_block_response_format, select_response_commands)
from qwen_deep_answer import (normalize_deep_text, deep_name_text, deep_citation_text, deep_prose_errors, deep_context, build_deep_plan, deep_response_format,
                              validate_deep_response, render_deep_details)
from qwen_claim_checks import (build_claim_plan, claim_response_format, extract_claims, prose_claim_errors,
                               review_messages, review_response_format, validate_review, append_review_notice)


def unsupported_links(answer, evidence):
    """Reject source links invented by the model, using actual retrieval only."""
    pattern = re.compile(r'https?://[^\s<>\"\'\[\])]+')
    def urls(text):
        return {s.rstrip('.,;!?') for s in pattern.findall(text)}
    allowed = set()
    def visit(value):
        if isinstance(value, str): allowed.update(urls(value))
        elif isinstance(value, dict):
            for child in value.values(): visit(child)
        elif isinstance(value, list):
            for child in value: visit(child)
    visit(evidence)
    return sorted(urls(answer) - allowed)


def require_valid_citations(body):
    if (body.get('all_exist') is not True or body.get('all_in_context') is not True
        or not body.get('results') or any(r.get('exists') is not True or r.get('in_context') is not True
                                        for r in body['results'])):
        raise ValueError('최종 인용의 존재·근거 범위를 확인하지 못했습니다.')


def record_reference_errors(answer, context, evidence):
    """Check full record references, including malformed IDs skipped by CTO regex."""
    allowed = set()
    raw = context.get('raw_event') or {}
    if isinstance(raw, dict) and isinstance(raw.get('recordId'), str):
        allowed.add(raw['recordId'])
    def visit(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ('alert_id', 'incident_id', 'event_id') and isinstance(v, str):
                    allowed.add(v)
                elif isinstance(v, (dict, list)):
                    visit(v)
        elif isinstance(node, list):
            for item in node:
                visit(item)
    for item in evidence:
        result = item.get('result')
        if isinstance(result, dict) and not result.get('error') and result.get('found') is True:
            visit(result)
    candidates = set(re.findall(r'(?<![A-Za-z0-9_])(?:al|in|ev[A-Za-z]*)-[0-9a-fA-F]{8,}(?![A-Za-z0-9_])', answer))
    return ['조회된 원본과 일치하지 않는 기록 ID: ' + ref for ref in sorted(candidates - allowed)]


def request_json(url, body, timeout):
    headers = {'Content-Type': 'application/json'}
    if os.environ.get('QWEN_API_KEY'):
        headers['Authorization'] = 'Bearer ' + os.environ['QWEN_API_KEY']
    request = urllib.request.Request(url, json.dumps(body, ensure_ascii=False).encode(), headers, method='POST')
    return urllib.request.urlopen(request, timeout=max(1, timeout))


def stream_answer(config, messages, mode, remaining, emit, metrics, opener=request_json, response_format=None,
                  purpose='answer'):
    effort = 'none' if mode == 'fast' else 'low'
    body = {'model': config['model'], 'messages': messages, 'stream': True,
            'max_tokens': config.get('max_tokens', 8192), 'reasoning_effort': effort, 'reasoning': None,
            'response_format': response_format or {'type': 'json_object'}}
    # This is the exact body passed to the HTTP opener; no SDK can rewrite it.
    info = {k: body[k] for k in ('model', 'stream', 'max_tokens', 'reasoning_effort')}
    info.update(message_count=len(messages), tool_count=0, tool_names=[],
                policy_present=metrics['_policy_text'] in messages[0]['content'],
                response_format_type=body['response_format']['type'])
    if body['response_format']['type'] == 'json_schema':
        info['response_schema_name'] = body['response_format']['json_schema']['name']
    if purpose != 'answer':
        info['purpose'] = purpose
    if not info['policy_present']: raise RuntimeError('Qwen 지침이 API 요청에 없습니다.')
    metrics['api_requests'].append(info)
    emit({'type': 'system', 'subtype': 'qwen_api_request', **info})
    content, reasoning_chars, finished, done = [], 0, None, False
    with opener(config['base_url']+'/chat/completions', body, remaining()) as response:
        for raw in response:
            remaining()  # Enforce the overall deadline even when chunks keep arriving.
            line = raw.decode('utf-8').strip()
            if not line.startswith('data:'): continue
            data = line[5:].strip()
            if data == '[DONE]':
                done = True
                break
            chunk = json.loads(data)
            if chunk.get('error'): raise RuntimeError('Qwen이 API 오류를 반환했습니다.')
            choices = chunk.get('choices') or []
            if not choices: continue
            choice = choices[0]
            delta = choice.get('delta') or {}
            if delta.get('tool_calls'): raise RuntimeError('직접 API 응답에 허용하지 않은 도구 호출이 있습니다.')
            reasoning_chars += len(delta.get('reasoning_content') or delta.get('reasoning') or '')
            text = delta.get('content')
            if text:
                content.append(text)
                if purpose == 'answer':
                    emit({'type': 'text', 'text': text})
            if choice.get('finish_reason') is not None: finished = choice['finish_reason']
    metrics['reasoning_chars'] = metrics.get('reasoning_chars', 0) + reasoning_chars
    if mode == 'fast' and reasoning_chars:
        raise RuntimeError('빠른 모드인데 API가 추론 내용을 반환했습니다.')
    if not done or finished != 'stop':
        raise RuntimeError('Qwen 답변이 정상적으로 완료되지 않았습니다: '+str(finished))
    answer = ''.join(content).strip()
    if not answer: raise RuntimeError('Qwen이 빈 응답을 반환했습니다.')
    return answer


def run(prompt, context, run_id, mode, timeout, emit, backend=None, opener=request_json, config=None):
    started = time.monotonic()
    deadline = started + timeout
    def remaining():
        value = deadline - time.monotonic()
        if value <= 0: raise TimeoutError('Qwen 분석 제한 시간을 초과했습니다.')
        return value
    config = config or load_config()
    policy_path = Path(config['policy_path']).expanduser()
    policy = policy_path.read_text(encoding='utf-8').strip()
    if not policy: raise RuntimeError('Qwen 지침이 비어 있습니다.')
    question = str(context.get('question') or prompt)
    keys = requested_keys(question)
    ledger = EvidenceLedger(run_id, context)
    backend = backend or CTOBackend()
    metrics = {'execution_mode': 'direct_qwen_api', 'harness_revision': 'direct-13-claims',
        'analysis_mode': mode, 'thinking_enabled': mode == 'deep',
        'wire_reasoning_effort': 'none' if mode == 'fast' else 'low',
        'model': config['model'], 'base_url': config['base_url'],
        'policy_path': str(policy_path.resolve()),
        'policy_sha256': hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        'api_requests': [], 'repair_attempts': 0, 'reasoning_chars': 0,
        'tool_transport': 'local_cto_backend', 'model_tool_loop': False,
        'allow_live_state': live_lookup_allowed(question), 'live_state_query_performed': False,
        'live_state_query_attempted': False, 'live_state_query_succeeded': False,
        '_policy_text': policy}
    def public_metrics():
        return {k:v for k,v in metrics.items() if not k.startswith('_')}
    emit({'type': 'system', 'subtype': 'harness_configuration', **public_metrics()})
    count = 0
    def call(name, arguments):
        nonlocal count
        remaining();count += 1
        call_id = f'{run_id}_{count}'
        full_name = 'cto__'+name
        args = dict(arguments)
        if name == 'validate_citations': args['audit_run_id'] = run_id
        emit({'type': 'tool_use', 'name': full_name, 'input': args, 'tool_call_id': call_id})
        tick = time.monotonic()
        try:
            body = backend.call(name, args)
        except Exception:
            emit({'type': 'tool_result', 'name': full_name, 'tool_call_id': call_id,
                  'is_error': True, 'output': {'error': 'CTO 조회 실패'},
                  'duration_ms': int((time.monotonic()-tick)*1000)})
            raise RuntimeError('CTO 근거 조회에 실패했습니다.') from None
        ledger.record(full_name, args, body)
        emit({'type': 'tool_result', 'name': full_name, 'tool_call_id': call_id,
              'output': compact_evidence(name, body), 'is_error': bool(body.get('error')),
              'duration_ms': int((time.monotonic()-tick)*1000)})
        if body.get('error'): raise RuntimeError('CTO 조회 도구가 오류를 반환했습니다.')
        return body
    try:
        with opener(config['base_url'][:-3]+'/api/show', {'model': config['model']}, min(15, remaining())) as response:
            capabilities = json.load(response).get('thinking') or {}
        if not any(type(v) is bool and v == (mode == 'deep') for v in capabilities.get('values', [])):
            raise RuntimeError('모델이 요청한 추론 ON/OFF 옵션을 지원하지 않습니다.')
        metrics['thinking_capabilities'] = capabilities
        evidence = []
        full_deep_evidence = {}
        def retrieve(name, args):
            body = call(name, args)
            if mode == 'deep':
                # The display compactor omits ontology field definitions. Keep
                # the already retrieved definitions for grounded interpretation
                # and review, without adding tools or changing fast prompts.
                full_deep_evidence[len(evidence)] = body
            evidence.append({'tool': name, 'arguments': args, 'result': compact_evidence(name, body)})
            return body
        for ref in sorted(ledger.requested_refs)[:3]:
            if ref.startswith('al-'): retrieve('get_alert', {'alert_id': ref})
            else: retrieve('summarize_incident', {'incident_id': ref})
        for event, outcome in ledger.events:
            args = {'event_type': event}
            if outcome in ('success', 'failure', 'pending'): args['outcome'] = outcome
            retrieve('explain_log_event', args)
            retrieve('retrieve_log_context', args)
        for ident in sorted(ledger.requested_ids):
            body = retrieve('lookup_technique', {'technique_id': ident})
            if body.get('id') != ident or type(body.get('found')) is not bool:
                raise RuntimeError('기법 조회 결과의 ID·조회 상태를 확인하지 못했습니다. 미등록으로 판정하지 않습니다.')
            if body.get('found') is True: retrieve('get_defenses', {'technique_id': ident})
        if mode == 'deep' and re.search(r'전술|\btactic\b', task_question(question), re.I):
            retrieve('lookup_named_tactics', {'query': task_question(question)[:2000]})
        if not ledger.events and not ledger.requested_ids and not ledger.requested_refs:
            retrieve('search_knowledge', {'query': task_question(question)[:500], 'top_k': 5})
        if ledger.events and re.search(r'대응|완화|방어|조치|복구|명령', task_question(question)):
            direct_ids = []
            for item in evidence:
                if item['tool'] == 'explain_log_event':
                    for event in item['result'].get('results', []):
                        for behavior in event.get('behaviors', []):
                            direct_ids.extend(t['id'] for t in behavior.get('suggested_techniques', []))
            for ident in sorted(set(direct_ids))[:max(0, 7-len(evidence))]:
                retrieve('get_defenses', {'technique_id': ident})
        for action, identifier in live_lookup_plan(question, context):
            from openstack_readonly_core import lookup_openstack
            name, call_id = 'openstack__'+action, f'{run_id}_live_{len(evidence)}'
            metrics['live_state_query_attempted'] = True
            emit({'type':'tool_use','name':name,'input':{'identifier':identifier},'tool_call_id':call_id})
            tick = time.monotonic()
            try:
                data = lookup_openstack(action, identifier)
                metrics['live_state_query_succeeded'] = isinstance(data, dict) and not data.get('error')
                metrics['live_state_query_performed'] = metrics['live_state_query_succeeded']
            except Exception:
                data = {'error':'현재 상태 조회에 실패했습니다. 권한/연결을 확인해야 합니다.'}
            emit({'type':'tool_result','name':name,'tool_call_id':call_id,'output':data,
                  'is_error':bool(data.get('error')),'duration_ms':int((time.monotonic()-tick)*1000)})
            evidence.append({'tool':action,'arguments':{'identifier':identifier},'result':data})
        metrics['preflight_calls'] = len(evidence)
        assessment = assess(context, evidence)
        claim_evidence = [{**item, 'result': full_deep_evidence.get(i, item['result'])}
                          for i, item in enumerate(evidence)]
        claim_plan = build_claim_plan(context, claim_evidence, assessment)
        metrics['rule_assessments'] = assessment['evaluations']
        fixed = {k:v for k,v in assessment['values'].items() if k in keys}
        metrics['backend_owned_fields'] = sorted(fixed)
        model_keys = [k for k in keys if k not in fixed]
        missing_plan = build_missing_lookup_plan(question, ledger.requested_ids, evidence)
        answer_context = deep_context(context) if mode == 'deep' else context
        command_plan = build_command_plan(question, answer_context)
        requirements = requested_fields(question, answer_context) if not missing_plan else []
        if mode == 'deep' and 'log' in (answer_context.get('raw_event') or {}) and answer_context is context:
            requirements = []  # Do not label opaque pasted input as missing JSON fields.
        answer_plan = (missing_plan or command_plan or build_log_answer_plan(question, answer_context, evidence)
                       or build_observed_answer_plan(question, answer_context, evidence))
        answer_plan = extend_fact_plan(answer_plan, requirements)
        command_block = (build_response_command_block(question, answer_context, evidence)
                         if not missing_plan and not command_plan else None)
        deep_plan = None
        if mode == 'deep' and not missing_plan and not command_plan:
            deep_plan = build_deep_plan(question, answer_context, answer_plan, requirements, evidence)
            # Deep analysis retains model prose. Fast fact rendering is unchanged.
            answer_plan = None
            metrics['deep_answer_revision'] = 'deep-quality-1'
            metrics['deep_required_fact_ids'] = deep_plan['required_fact_ids']
        if command_block is not None:
            # Only command text is fixed. Keep Qwen's explanation, including
            # deep-mode reasoning; do not route the whole reply to a template.
            answer_plan = None
            metrics['server_command_block'] = command_block
        metrics['requested_observed_fields'] = requirements
        if missing_plan:
            metrics['backend_owned_fields'] = sorted(keys)
        metrics['answer_policy'] = ({'kind': answer_plan['kind'],
            'required_fact_ids': answer_plan['required_fact_ids'],
            'fact_sources': {fact['id']: fact['sources'] for fact in answer_plan['facts']}}
            if answer_plan else {'kind': 'deep_grounded_analysis' if deep_plan is not None else 'validated_prose'})
        messages, prompt_metrics = build_messages(
            policy, prompt, context, evidence, assessment, model_keys, fixed,
            answer_plan, missing_plan, {'executed': False,
                'live_state_query_attempted': metrics['live_state_query_attempted'],
                'live_state_query_succeeded': metrics['live_state_query_succeeded'],
                'live_state_query_performed': metrics['live_state_query_performed']},
            field_requirements=requirements, deep_plan=deep_plan, command_block=command_block,
            claim_plan=claim_plan if deep_plan is not None else None)
        metrics.update(prompt_metrics)
        response_format = (missing_lookup_response_format(missing_plan) if missing_plan
                           else deep_response_format(model_keys, deep_plan) if deep_plan is not None
                           else fact_response_format(answer_plan) if answer_plan and answer_plan.get('strict') else None)
        if deep_plan is not None:
            response_format = claim_response_format(response_format, claim_plan)
        if command_block is not None:
            response_format = command_block_response_format(command_block, response_format)
        review_cfg = config.get('deep_review') or {}
        review_enabled = deep_plan is not None and review_cfg.get('enabled') is True
        review_done = False
        review_issues = []
        ordinary_repairs = 0
        review_repairs = 0
        metrics['semantic_review'] = {'status': 'pending' if review_enabled else 'not_requested', 'calls': 0}
        _cto_retry_empty_body = False  # 3K1H_EMPTY_ANSWER_RETRY_V1
        # One existing format/fact repair and one separate review correction.
        # The reviewer itself is called at most once, even after correction.
        for attempt in range(3):
            _cto_call_mode = 'fast' if mode == 'fast' and attempt and _cto_retry_empty_body else mode
            raw = stream_answer(config, messages, _cto_call_mode, remaining, emit, metrics, opener,
                                response_format=response_format)
            errors, answer = [], raw
            review_failure = False
            claims = []
            model_body = ''
            normalizations = []
            try:
                model_raw, selected_commands = raw, command_block
                if command_block is not None:
                    model_raw, selected_commands = select_response_commands(raw, command_block)
                    metrics['selected_command_ids'] = [r['id'] for r in selected_commands['commands']]
                    metrics['command_block_normalizations'] = selected_commands['normalizations']
                if missing_plan:
                    answer = render_missing_lookup(raw, missing_plan)
                elif answer_plan:
                    answer = render_log_answer(raw, answer_plan)
                else:
                    if deep_plan is not None:
                        model_raw, claims = extract_claims(model_raw, claim_plan)
                        metrics['structured_claims'] = claims
                        deep_obj = validate_deep_response(model_raw, model_keys, deep_plan)
                        normalized_body = normalize_deep_text(deep_obj['explanation'])
                        metrics['deep_format_normalizations'] = (['escaped_list_line_breaks'] if normalized_body != deep_obj['explanation'] else [])
                        deep_obj['explanation'] = normalized_body
                        semantic_errors = deep_prose_errors(deep_obj['explanation'], deep_plan)
                        metrics['deep_prose_checks'] = {'status': 'fail' if semantic_errors else 'pass', 'errors': semantic_errors}
                        if semantic_errors:
                            raise ValueError('; '.join(semantic_errors))
                    obj = deep_obj if deep_plan is not None else json.loads(model_raw)
                    body_errors = completion_errors(obj.get('explanation') if isinstance(obj, dict) else None)
                    if body_errors:
                        raise ValueError('; '.join(body_errors))
                    model_body = obj['explanation']
                    claim_errors = prose_claim_errors(model_body, obj.get('answers'))
                    metrics['claim_checks'] = {'status': 'fail' if claim_errors else 'pass',
                                              'errors': claim_errors, 'scope': 'supported_claims_and_explicit_outcomes'}
                    if claim_errors:
                        raise ValueError('; '.join(claim_errors))
                    command_prose_errors = model_command_block_errors(obj['explanation'], command_block)
                    if command_prose_errors:
                        raise ValueError('; '.join(command_prose_errors))
                    include_summary = not context.get('question_only') or bool(re.search(r'공격|위험|분류|오류|판정|분석',task_question(question)))
                    answer = assemble_answer(json.dumps(obj, ensure_ascii=False) if deep_plan is not None else model_raw,
                                             keys, assessment, include_summary, normalizations)
                    if deep_plan is not None:
                        answer = render_deep_details(answer, deep_plan, keys)
                    answer = render_response_command_block(answer, selected_commands)
            except (ValueError, TypeError) as exc:
                errors.append(str(exc))
                # An invalid JSON body (e.g. explanation=null) is not prose for
                # downstream name/citation parsers. Preserve raw separately in
                # the failure event and use the bounded repair path.
                answer = ''
            metrics['answer_completion'] = {'status': 'fail' if errors else 'pass',
                'required_fact_ids': (answer_plan or deep_plan or {}).get('required_fact_ids', []),
                'checks': (['typed_lookup_results', 'no_extra_claims', 'grounded_absence_rendering'] if missing_plan
                           else ['required_grounded_facts'] if answer_plan
                           else ['deep_output_schema', 'required_grounded_details', 'nonempty', 'closed_code_marks', 'complete_ending']
                           if deep_plan is not None else ['nonempty', 'closed_code_marks', 'complete_ending'])}
            metrics['answer_normalizations'] = normalizations
            if not errors and not keys:
                answer, coverage = complete_requested_techniques(answer, question, evidence)
                metrics['answer_coverage'] = coverage
            reference_errors = record_reference_errors(answer, context, evidence)
            metrics['record_reference_errors'] = reference_errors
            errors.extend(reference_errors)
            links = unsupported_links(answer, evidence)
            metrics['unsupported_source_links'] = links
            if links:
                errors.append('조회 근거에 없는 출처 URL을 삭제하고 실제 조회된 근거만 설명하라: '
                              + ', '.join(links))
            citation_answer = deep_citation_text(answer) if mode == 'deep' else answer
            ids, negative = ledger.classify_citations(citation_answer)
            probes = [call('validate_citations', {'ids': ids[i:i+50]}) for i in range(0,len(ids),50)]
            ids, negative, checks = final_citation_checks(ledger, citation_answer, probes)
            for body in checks:
                try: require_valid_citations(body)
                except ValueError: errors.append('실제 인용 검증 실패: '+json.dumps(body,ensure_ascii=False))
            missing_fields = field_errors(answer, requirements)
            bad_commands = command_errors(answer, command_plan)
            bad_names, name_checks = knowledge_name_errors(deep_name_text(answer) if mode == 'deep' else answer, probes, evidence)
            errors.extend(missing_fields + bad_commands + bad_names)
            metrics['response_checks'] = {
                'status': 'fail' if missing_fields or bad_commands or bad_names else 'pass',
                'field_errors': missing_fields, 'command_errors': bad_commands,
                'name_errors': bad_names, 'name_pairs': name_checks,
                'command_scope': command_plan['commands'] if command_plan else []}
            metrics.update(final_citation_ids=ids,verified_absent_ids=negative,
                final_citation_checks=checks,final_citation_probe_checks=probes,
                citation_scope_technique_ids=sorted(ledger.techniques),
                final_citation_status='fail' if errors else 'pass' if ids else 'absence_verified' if negative else 'not_applicable')
            if not errors and review_enabled:
                if not review_done:
                    review_done = True
                    review_started = time.monotonic()
                    review_deadline = min(deadline, review_started + max(5, min(120, float(review_cfg.get('timeout_seconds', 90)))))
                    def review_remaining():
                        budget = min(remaining(), review_deadline - time.monotonic())
                        if budget <= 0:
                            raise TimeoutError('심층 근거 검토 제한 시간을 초과했습니다.')
                        return budget
                    audit = metrics['semantic_review']
                    audit.update(status='running', reviewed_body_sha256=hashlib.sha256(model_body.encode()).hexdigest())
                    emit({'type': 'system', 'subtype': 'semantic_review_started'})
                    try:
                        if review_remaining() < 5:
                            raise TimeoutError('심층 근거 검토 시간이 부족합니다.')
                        audit['calls'] = 1
                        review_raw = stream_answer(
                            {**config, 'max_tokens': max(512, min(4096, int(review_cfg.get('max_tokens', 2048))))},
                            review_messages(policy, task_question(question), answer_context, claim_plan, model_body, claims,
                                            displayed_answer=answer),
                            'fast', review_remaining, emit, metrics, opener,
                            response_format=review_response_format(claim_plan), purpose='semantic_review')
                        review = validate_review(review_raw, model_body, claim_plan, task_question(question))
                        review_issues = review['issues']
                        audit.update(status=review['verdict'], issues=review_issues)
                        if review_issues:
                            review_failure = True
                            errors.extend('심층 근거 검토: ' + json.dumps(issue, ensure_ascii=False) for issue in review_issues)
                    except (ValueError, TypeError, RuntimeError, TimeoutError, OSError) as exc:
                        # A broken reviewer is not a pass and must not become a
                        # second unbounded retry loop or a new API failure page.
                        audit.update(status='unavailable', reason=str(exc)[:500])
                    audit['elapsed_sec'] = round(time.monotonic() - review_started, 2)
                    emit({'type': 'system', 'subtype': 'semantic_review_result', **audit})
                elif review_issues:
                    metrics['semantic_review']['status'] = 'revision_unreviewed'
                    # A critique is not proof, but silently returning its exact
                    # disputed sentence unchanged would be a fake repair.
                    for issue in review_issues:
                        if issue['quote'] and issue['quote'] in model_body:
                            review_failure = True
                            errors.append('심층 검토에서 지적된 문장이 수정되지 않았습니다: ' + issue['quote'])
            if review_enabled and not errors:
                status = metrics['semantic_review']['status']
                answer = append_review_notice(answer, status)
                metrics['answer_status'] = 'complete' if status == 'pass' else 'limited_review'
            if not errors:
                metrics['elapsed_sec'] = round(time.monotonic()-started,2)
                emit({'type':'system','subtype':'harness_metrics',**public_metrics()})
                emit({'type':'result','exit_code':0,'text':answer,'session_id':run_id,
                      'status':metrics.get('answer_status', 'complete')})
                return 0
            emit({'type':'system','subtype':'harness_validation_failure','attempt':attempt+1,
                  'errors':errors,'candidate':answer,'model_candidate':raw})
            exhausted = review_repairs >= 1 if review_failure else ordinary_repairs >= 1
            if exhausted or attempt >= 2 or remaining() < 30:
                raise RuntimeError('최종 답변 검증 실패: '+'; '.join(errors))
            if review_failure:
                review_repairs += 1
                metrics['review_repair_attempts'] = review_repairs
            else:
                ordinary_repairs += 1
            metrics['repair_attempts'] += 1
            _cto_retry_empty_body = any('답변 본문이 비어 있습니다' in str(_err) for _err in errors)
            messages += [{'role':'assistant','content':raw}, repair_message(errors)]
    except Exception as exc:
        metrics['elapsed_sec'] = round(time.monotonic()-started,2)
        emit({'type':'system','subtype':'harness_metrics',**public_metrics()})
        safe = str(exc) if isinstance(exc,(ValueError,RuntimeError,TimeoutError)) else type(exc).__name__
        emit({'type':'result','exit_code':1,'error':safe,'session_id':run_id})
        return 1
    finally:
        backend.close()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--prompt-file',required=True)
    parser.add_argument('--context-file')
    parser.add_argument('--run-id',required=True)
    parser.add_argument('--mode',choices=['fast','deep'],default='fast')
    parser.add_argument('--timeout',type=int,default=660)
    args=parser.parse_args()
    if not re.fullmatch(r'dashboard_[0-9]{8}_[0-9]{6}_[0-9a-f]{6}',args.run_id): raise ValueError('Invalid run ID')
    prompt=Path(args.prompt_file).read_text()
    context=json.loads(Path(args.context_file).read_text()) if args.context_file else {'question':prompt}
    return run(prompt,context,args.run_id,args.mode,args.timeout,
               lambda e: print(json.dumps(e,ensure_ascii=False),flush=True))


if __name__=='__main__':
    raise SystemExit(main())
