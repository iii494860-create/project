"""Create an editable DOCX and a printable Korean PDF from an already saved SOC report.

The factual fields must be sourced from the selected Neo4j ObservedEvent/Alert.
The generated AI narrative is clearly identified as model interpretation.
Never fills missing incident details with guesses.
"""
from __future__ import annotations

import html
import io
import json
import re
from datetime import datetime, timezone, timedelta
from xml.sax.saxutils import escape as xml_escape

KST = timezone(timedelta(hours=9))


def _text(v, missing='미확인'):
    if v is None:
        return missing
    if isinstance(v, (list, tuple)):
        v = ', '.join(str(x) for x in v if x is not None and str(x).strip())
    v = str(v).strip()
    return v if v and v not in ('-', 'None', 'null') else missing


def _time(v):
    if v is None or not str(v).strip():
        return '미확인'
    raw = str(v).strip()
    try:
        dt = datetime.fromisoformat(raw.replace('Z', '+00:00'))
        if dt.tzinfo is not None:
            return dt.astimezone(KST).strftime('%Y-%m-%d %H:%M:%S KST')
    except ValueError:
        pass
    if raw.endswith('KST'):
        return raw
    return raw[:50] + ' (시간대 확인 필요)'


def _flatten_ai(markdown):
    """Use only the AI analysis portion of the saved Markdown, not duplicate the fact header."""
    value = str(markdown or '')
    tag = '## AI 보안 분석'
    end = '## 분석 범위 및 주의 사항'
    if tag in value:
        value = value.split(tag, 1)[1]
    if end in value:
        value = value.split(end, 1)[0]
    return value.strip() or 'AI 분석 본문 없음 — 결과 확인 필요'


def build_fields(report_id, event, alerts, markdown, *, citation_status=None, created_at=None):
    """Build display fields from a verified event row, not from AI-generated claims."""
    event = dict(event or {})
    alert_ids = []
    for a in alerts or []:
        if isinstance(a, dict):
            ident = a.get('alert_id') or a.get('id')
        else:
            ident = a
        if isinstance(ident, str) and ident.strip() and ident not in alert_ids:
            alert_ids.append(ident)
    incident_ids = [str(i) for i in event.get('incident_ids') or [] if i]
    sev = event.get('severities') or event.get('severity')
    if isinstance(sev, list):
        sev = sorted([str(v) for v in sev if v], key=lambda s: {'CRITICAL': 0,'HIGH':1,'MEDIUM':2,'LOW':3}.get(s.upper(), 9))
    props = event.get('neo4j_properties') or {}
    detail = props.get('fieldsJson') or {}
    if isinstance(detail, str):
        try:
            detail = json.loads(detail)
        except (ValueError, TypeError):
            detail = {}
    if not isinstance(detail, dict):
        detail = {}
    payload = detail.get('payload') or {}
    if not isinstance(payload, dict):
        payload = {}
    def source_field(*names):
        for obj in (props, detail, payload):
            for name in names:
                if obj.get(name) not in (None, '', '-'): return obj[name]
        return None
    created = created_at or datetime.now(timezone.utc).isoformat()
    return {
        'report_id': _text(report_id),
        'created_at': _time(created),
        'event_id': _text(event.get('event_id')),
        'event_type': _text(event.get('event_type')),
        'outcome': _text(event.get('outcome')),
        'event_time': _time(event.get('event_time') or props.get('observedAt')),
        'username': _text(event.get('username') or props.get('user')),
        'source_ip': _text(event.get('source_ip') or props.get('ip')),
        'severity': _text(sev),
        'alert_ids': alert_ids,
        'incident_ids': incident_ids,
        'resource_id': _text(event.get('resource_id') or source_field('resourceId','resource_id','image_id','imageId','instance_uuid','server_id','security_group_id')),
        'project_id': _text(event.get('project_id') or source_field('project','project_id','projectId','_context_project_id')),
        'citation_status': _text(citation_status, '결과 미기록'),
        'analysis': _flatten_ai(markdown),
        'rag_status': '기존 저장 보고서 — 조회 당시 상태 확인 필요',
    }


def _rows(fields):
    return [
        ('보고서 ID', fields['report_id']),
        ('작성 시각', fields['created_at']),
        ('보고 유형', 'OpenStack 보안 관제 · 위협 이벤트 분석'),
        ('작성 주체', 'AI 보안 에이전트 (담당자 확인 필요)'),
        ('접수 경로', 'Neo4j 탐지 Alert와 연결된 ObservedEvent'),
        ('사고 처리 담당자', '담당자 미기재'),
    ]


def _event_rows(fields):
    return [
        ('탐지 심각도', fields['severity']),
        ('이벤트 유형', fields['event_type']),
        ('탐지 시각', fields['event_time']),
        ('결과', fields['outcome']),
        ('관련 사용자', fields['username']),
        ('출발지 IP', fields['source_ip']),
        ('프로젝트 ID', fields['project_id']),
        ('영향 자원 ID', fields['resource_id']),
        ('이벤트 ID', fields['event_id']),
        ('연결 Alert', _text(fields['alert_ids'])),
        ('연결 Incident', _text(fields['incident_ids'])),
    ]


def _progress_rows(fields):
    return [
        ('1. 탐지 접수', '완료', 'Alert와 이벤트 연결 확인'),
        ('2. 원인 근거 조회', fields.get('rag_status','확인 필요'), '온톨로지·Graph RAG 자료 조회'),
        ('3. 분석 보고서', '생성', 'AI 생성 의견; 담당자 확인 필요'),
        ('4. 실제 차단·복구', '확인 필요', '자동 실행하지 않음; 수행 여부 별도 확인'),
    ]


def _line_text(line):
    line = re.sub(r'\*\*(.*?)\*\*', r'\1', line)
    line = re.sub(r'`([^`]+)`', r'\1', line)
    line = re.sub(r'^\s*[#>*-]+\s*', '', line)
    return line.strip()


def generate_docx(fields):
    from docx import Document
    from docx.shared import Inches, Pt, Cm, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    doc = Document()
    sec = doc.sections[0]
    sec.top_margin = Cm(1.6)
    sec.bottom_margin = Cm(1.6)
    sec.left_margin = Cm(1.8)
    sec.right_margin = Cm(1.8)
    st = doc.styles['Normal']
    st.font.name = 'Malgun Gothic'
    st.font.size = Pt(9)
    st.font.color.rgb = RGBColor(29, 39, 55)
    st.paragraph_format.space_after = Pt(4)
    st.paragraph_format.line_spacing = 1.12
    for name, pts in [('Title', 17), ('Heading 1', 11), ('Heading 2', 10)]:
        pstyle = doc.styles[name]
        pstyle.font.name = 'Malgun Gothic'
        pstyle.font.size = Pt(pts)
        pstyle.font.bold = True
        pstyle.font.color.rgb = RGBColor(23, 48, 81)
    heading = doc.add_paragraph(style='Title')
    heading.alignment = WD_ALIGN_PARAGRAPH.CENTER
    heading.add_run('OpenStack 보안관제 결과 보고서')
    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub.add_run('위협 이벤트 분석 · 사고 조사 및 대응 계획').italic = True

    def cellshade(cell, fill):
        tcpr = cell._tc.get_or_add_tcPr()
        sh = OxmlElement('w:shd'); sh.set(qn('w:fill'), fill); tcpr.append(sh)

    def pairs(rows):
        table = doc.add_table(rows=0, cols=2)
        table.style = 'Table Grid'
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        for label, value in rows:
            cells = table.add_row().cells
            cells[0].width = Cm(4)
            cells[1].width = Cm(12)
            cells[0].text = str(label)
            cells[1].text = str(value)
            cellshade(cells[0], 'EAF0F7')
            for c in cells:
                c.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
                for p in c.paragraphs:
                    p.paragraph_format.space_after = Pt(2)
                    p.paragraph_format.space_before = Pt(2)
                    for run in p.runs:
                        run.font.size = Pt(8.3)
        doc.add_paragraph().paragraph_format.space_after = Pt(0)

    doc.add_heading('1. 보고 및 접수 정보', level=1)
    pairs(_rows(fields))
    doc.add_heading('2. 탐지 대상 및 확인 정보', level=1)
    pairs(_event_rows(fields))
    doc.add_heading('3. 대응 과정 및 조치 현황', level=1)
    t = doc.add_table(rows=1, cols=3)
    t.style = 'Table Grid'
    for c, h in zip(t.rows[0].cells, ['구분', '상태', '확인 내용']):
        c.text = h
        cellshade(c, 'DCE8F5')
    for row in _progress_rows(fields):
        for c, v in zip(t.add_row().cells, row):
            c.text = v
    for row in t.rows:
        for c in row.cells:
            for p in c.paragraphs:
                p.paragraph_format.space_after = Pt(2)
                for r in p.runs:
                    r.font.size = Pt(8.0)
    doc.add_heading('4. 침해 내용·추정 원인·영향 및 권고 대응', level=1)
    doc.add_paragraph('아래는 AI가 탐지 근거를 바탕으로 작성한 분석 의견입니다. 실제 침해 여부와 조치 이력은 담당자가 확인해야 합니다.')
    for raw in fields['analysis'].splitlines():
        v = _line_text(raw)
        if not v or v in ('|---|---|',):
            continue
        if raw.strip().startswith(('#','**')) and len(v) < 100:
            doc.add_heading(v, level=2)
        elif re.match(r'^\s*(?:[-*]|\d+\.)\s+', raw):
            doc.add_paragraph(v, style='List Bullet')
        else:
            doc.add_paragraph(v)
    doc.add_heading('5. 증거자료 및 검증 상태', level=1)
    pairs([('원본 이벤트 ID', fields['event_id']),
           ('연결 Alert', _text(fields['alert_ids'])),
           ('연결 Incident', _text(fields['incident_ids'])),
           ('Citation 상태', fields['citation_status'])])
    doc.add_heading('6. 복구·재발 방지 및 검토 확인', level=1)
    doc.add_paragraph('실제 차단·계정 잠금·권한 회수·자원 변경 등은 본 보고서 생성 과정에서 실행하지 않았습니다. 명령을 실행하기 전 관리자의 승인, 영향도 확인 및 복구 계획이 필요합니다.')
    doc.add_paragraph('담당자 확인: _____________________    확인 일시: _____________________')
    doc.add_paragraph('본 보고서는 자동 작성된 초안이며, 개인정보와 사고 영향의 정확성은 별도 검토가 필요합니다.')
    footer = sec.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer.add_run('3K1H SOC · AI 자동 생성 문서 — 담당자 확인 전 확정 보고서로 사용하지 마십시오').font.size = Pt(7.5)
    bio = io.BytesIO()
    doc.save(bio)
    return bio.getvalue()


def generate_pdf(fields):
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer, KeepTogether

    font = 'HYSMyeongJo-Medium'
    try:
        pdfmetrics.getFont(font)
    except KeyError:
        pdfmetrics.registerFont(UnicodeCIDFont(font))

    stream = io.BytesIO()
    doc = SimpleDocTemplate(stream, pagesize=A4,
                            leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=17*mm, bottomMargin=17*mm,
                            title='OpenStack 보안관제 결과 보고서')
    style = {
        'title': ParagraphStyle('koTitle', fontName=font, fontSize=16, leading=23, alignment=TA_CENTER, spaceAfter=8),
        'sub': ParagraphStyle('koSub', fontName=font, fontSize=9, leading=14, alignment=TA_CENTER, spaceAfter=12),
        'head': ParagraphStyle('koHead', fontName=font, fontSize=10.5, leading=16, spaceBefore=10, spaceAfter=7, textColor=colors.HexColor('#203a59')),
        'normal': ParagraphStyle('koNormal', fontName=font, fontSize=8.3, leading=13.2, wordWrap='CJK', spaceAfter=5),
        'cell': ParagraphStyle('koCell', fontName=font, fontSize=8.0, leading=12.5, wordWrap='CJK'),
        'small': ParagraphStyle('koSmall', fontName=font, fontSize=7.2, leading=11, wordWrap='CJK'),
    }
    story = [Paragraph('OpenStack 보안관제 결과 보고서', style['title']),
             Paragraph('위협 이벤트 분석 · 사고 조사 및 대응 계획', style['sub'])]

    def para(v, name='cell'):
        s = html.escape(str(v))
        # CID-font Paragraph wrapping can struggle with long unbroken record IDs.
        if len(s) > 45 and ' ' not in s:
            s = '<br/>'.join(s[i:i+36] for i in range(0, len(s), 36))
        return Paragraph(s.replace('\n','<br/>'), style[name])

    def group(label, rows):
        story.append(Paragraph(html.escape(label), style['head']))
        data = [[para(a), para(b)] for a, b in rows]
        table = Table(data, colWidths=[44*mm, 130*mm], repeatRows=0, hAlign='LEFT')
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(0,-1),colors.HexColor('#EAF0F7')),
            ('GRID',(0,0),(-1,-1),0.4,colors.HexColor('#B5C2D1')),
            ('VALIGN',(0,0),(-1,-1),'TOP'),
            ('LEFTPADDING',(0,0),(-1,-1),8), ('RIGHTPADDING',(0,0),(-1,-1),8),
            ('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),
        ]))
        story.append(table)
    group('1. 보고 및 접수 정보',_rows(fields))
    group('2. 탐지 대상 및 확인 정보',_event_rows(fields))
    story.append(Paragraph('3. 대응 과정 및 조치 현황',style['head']))
    t = Table([[para(x) for x in ['구분','상태','확인 내용']] + []] +
              [[para(v) for v in row] for row in _progress_rows(fields)],
              colWidths=[43*mm,26*mm,105*mm],repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#DCE8F5')),
        ('GRID',(0,0),(-1,-1),0.4,colors.HexColor('#B5C2D1')),
        ('VALIGN',(0,0),(-1,-1),'TOP'),
        ('LEFTPADDING',(0,0),(-1,-1),7),('RIGHTPADDING',(0,0),(-1,-1),7),
        ('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),
    ]))
    story.append(t)
    story.append(Paragraph('4. 침해 내용·추정 원인·영향 및 권고 대응',style['head']))
    story.append(para('아래는 AI의 분석 의견입니다. 실제 침해 여부와 조치 이력은 담당자 확인이 필요합니다.','small'))
    for raw in fields['analysis'].splitlines():
        v = _line_text(raw)
        if not v or set(v) <= {'|','-',' '}:
            continue
        if raw.strip().startswith(('#','**')) and len(v) < 100:
            story.append(Paragraph(html.escape(v),style['head']))
        else:
            story.append(para(('• ' if re.match(r'^\s*[-*]\s+', raw) else '') + v,'normal'))
    group('5. 증거자료 및 검증 상태',[
        ('원본 이벤트 ID', fields['event_id']),
        ('연결 Alert', _text(fields['alert_ids'])),
        ('연결 Incident', _text(fields['incident_ids'])),
        ('Citation 상태', fields['citation_status'])])
    story.append(Paragraph('6. 복구·재발 방지 및 검토 확인',style['head']))
    story.append(para('실제 차단·계정 잠금·권한 회수 등은 자동 실행하지 않았습니다. 명령 실행에는 관리자 승인과 영향도 확인이 필요합니다.','normal'))
    story.append(para('담당자 확인: ____________________    확인 일시: ____________________','normal'))
    def foot(canvas, pdf):
        canvas.saveState()
        canvas.setFont(font, 7)
        canvas.drawCentredString(A4[0]/2, 11*mm, f'AI 자동 생성 초안 — 담당자 검토 필요   |   {pdf.page}쪽')
        canvas.restoreState()
    doc.build(story,onFirstPage=foot,onLaterPages=foot)
    return stream.getvalue()
