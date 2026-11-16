"""KST OpenStack SOC comprehensive reporting and print-ready table forms.

The entire period's ObservedEvent records are counted. Alert-linked records are
analysed separately; non-alert records are never asserted to be benign. No
unsupported AI judgement or mitigation execution is generated here.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone, timedelta
from io import BytesIO
from xml.sax.saxutils import escape as xml_escape
import json
import re

KST = timezone(timedelta(hours=9))
MAX_DETAILS = 12


def operational_summary(snapshot):
    items = snapshot['items']
    all_events = len(items)
    alert_events = sum(bool(x.get('is_threat')) for x in items)
    outcomes = Counter(str(x.get('outcome') or '미확인').lower() for x in items)
    event_types = Counter(str(x.get('event_type') or '미확인') for x in items)
    days = Counter(x['stamp'].strftime('%Y-%m-%d') for x in items)
    alert_days = Counter(x['stamp'].strftime('%Y-%m-%d') for x in items if x.get('is_threat'))
    return {
        'all_events': all_events,
        'alert_linked_events': alert_events,
        'unlinked_events': all_events-alert_events,
        'outcomes': dict(sorted(outcomes.items(), key=lambda kv:(-kv[1],kv[0]))),
        'event_types': dict(event_types.most_common(15)),
        'per_day': dict(sorted(days.items())),
        'alert_events_per_day': dict(sorted(alert_days.items())),
        'undated_events': snapshot['undated'],
        'scanned_events': snapshot['scanned'],
    }


def richer_alert_details(a, date):
    ev = []
    seen=set()
    for x in a.get('events') or []:
        eid = str(x.get('id') or '')
        if eid and eid not in seen:
            seen.add(eid)
            ev.append({'id': eid, 'type':str(x.get('event_type') or '미확인'),
                       'outcome':str(x.get('outcome') or '미확인')})
    inc=sorted({str(i['id']) for i in a.get('incidents') or [] if i.get('id')})
    tech=sorted({str(t['id']) for t in a.get('techniques') or []
                 if re.fullmatch(r'T\d{4}(?:\.\d{3})?',str(t.get('id') or ''))})
    return {'alert_id':str(a.get('alert_id') or ''),
            'severity':str(a.get('severity') or 'UNKNOWN').upper(),
            'rule':str(a.get('rule') or '미확인 탐지 규칙'),
            'time':date.strftime('%Y-%m-%d %H:%M KST'),
            'events':ev[:10], 'event_count':len(ev), 'incident_ids':inc,
            'technique_ids':tech}


def _pairs(d, max_items=8):
    return list((d or {}).items())[:max_items]


def form_model(data, report_id, created_at=None):
    """JSON-serializable immutable-at-save report view (no raw logs or secrets)."""
    op=data['operations']; cur=data['current']
    created_at = created_at or datetime.now(KST)
    if isinstance(created_at,str): created_at=datetime.fromisoformat(created_at)
    kind=data['kind']
    daylabels=[]
    d=data['start'].date()
    last=data['end'].date()
    while d <= last:
        key=d.isoformat()
        daylabels.append({'date':key,'weekday':'월화수목금토일'[d.weekday()],
                          'events':op['per_day'].get(key,0),
                          'alert_events':op['alert_events_per_day'].get(key,0),
                          'alerts':cur['per_day'].get(key,0)})
        d+=timedelta(days=1)
    details=list(cur.get('details') or [])
    rank={'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}
    details=sorted(details,key=lambda x:(rank.get(x.get('severity'),5),x.get('time','')))[:MAX_DETAILS]
    return {
      'schema_version':2,'id':str(report_id),'kind':kind,
      'created_at':created_at.astimezone(KST).isoformat(),
      'start':data['start'].isoformat(), 'end':data['end'].isoformat(),
      'all_events':op['all_events'],
      'alert_linked_events':op['alert_linked_events'],
      'unlinked_events':op['unlinked_events'],
      'alerts':cur['alerts'],'incidents':cur['incidents'],
      'undated_alerts':data['undated_alerts'],
      'undated_events':op['undated_events'],
      'outcomes':_pairs(op['outcomes'],10),
      'event_types':_pairs(op['event_types'],10),
      'severity':_pairs(cur['severity'],10),
      'rules':_pairs(cur['rules'],10),
      'techniques':_pairs(cur['techniques'],10),
      'days':daylabels,
      'previous_alerts':(data.get('previous') or {}).get('alerts') if kind=='weekly' else None,
      'details':details,
      'policy_note':'Alert가 없는 이벤트는 정상 확정이 아닌 미분류/미연결 이벤트입니다.',
      'review_status':'담당자 검토 전 자동 집계 초안',
    }


def read_model(report):
    raw=report.get('reportDataJson')
    if not raw: return None
    try: m=json.loads(raw) if isinstance(raw,str) else raw
    except (TypeError,ValueError): return None
    if not isinstance(m,dict) or m.get('schema_version')!=2: return None
    return m


def _date(s):
    try:return datetime.fromisoformat(str(s)).astimezone(KST).strftime('%Y-%m-%d %H:%M KST')
    except ValueError:return str(s or '확인 필요')


def _rows(data, limit=8):
    return [[str(k),f'{v:,}건' if isinstance(v,int) else str(v)] for k,v in data[:limit]] or [['확인된 항목 없음','-']]


def layout(m):
    """Return real table sections in a form resembling submitted daily/weekly sheets."""
    kind=m['kind']; weekly=kind=='weekly'
    title='OpenStack 주간 보안관제 업무보고서' if weekly else 'OpenStack 보안관제센터 일일 보고서'
    period=_date(m['start'])+' ~ '+_date(m['end'])
    meta=[['작성 주체','3K1H SOC 자동 집계','작성 일시',_date(m['created_at'])],
          ['집계 기간',period,'문서 상태',m['review_status']],
          ['보고서 ID',m['id'],'담당자 확인','미확인 / 검토 필요']]
    summary=[['전체 수집 이벤트',str(m['all_events'])+'건','Alert 연결 이벤트',str(m['alert_linked_events'])+'건'],
             ['Alert 미연결 이벤트',str(m['unlinked_events'])+'건','탐지 Alert',str(m['alerts'])+'건'],
             ['관련 Incident',str(m['incidents'])+'건','미확인 시각 이벤트',str(m['undated_events'])+'건']]
    sections=[{'title':'01  기본정보','headers':['항목','내용','항목','내용'],'rows':meta},
              {'title':'02  처리결과 및 보안 운영 요약','headers':['항목','집계','항목','집계'],'rows':summary}]
    if weekly:
        dayrows=[[x['date']+' ('+x['weekday']+')',str(x['events']),str(x['alert_events']),str(x['alerts'])] for x in m['days']]
        sections.append({'title':'03  요일별 업무실적·탐지현황',
                         'headers':['일자','수집 로그','위협 관련 이벤트','Alert'],
                         'rows':dayrows})
        prev=m.get('previous_alerts')
        sections.append({'title':'04  주간 운영실적 및 전주 대비',
                         'headers':['항목','이번 주','비교 기준','전주 동일 경과 구간'],
                         'rows':[['Alert',str(m['alerts']), '전주 Alert',str(prev) if prev is not None else '확인 불가'],
                                 ['Alert 증감',f'{m["alerts"]-prev:+d}건' if prev is not None else '확인 불가',
                                  '수집 이벤트','%s건'%m['all_events']]]})
    else:
        sections.append({'title':'03  수집 로그 유형별 현황','headers':['이벤트 유형','발생 건수'],
                         'rows':_rows(m['event_types'],10)})
        sections.append({'title':'04  이벤트 처리 결과','headers':['기록된 outcome','발생 건수'],
                         'rows':_rows(m['outcomes'],8)})
    sections += [
      {'title':('05' if weekly else '05')+'  위협 유형별 처리현황',
       'headers':['탐지 규칙','Alert 건수'],'rows':_rows(m['rules'],10)},
      {'title':'06  위험등급별 탐지 현황','headers':['심각도','Alert 건수'],
       'rows':_rows(m['severity'],8)},
      {'title':'07  주요 위협 사고·탐지 근거',
       'headers':['탐지 시간 / 심각도','탐지 규칙 및 실제 연결 근거'],
       'rows':[
          [d.get('time','-')+'\n'+d.get('severity','UNKNOWN'),
           d.get('rule','-')+'\nAlert: '+d.get('alert_id','-')+
           '\n이벤트: '+(', '.join((e['type']+' ('+e['outcome']+')') for e in d.get('events',[])[:3]) or '연결 정보 없음')+
           '\n기법(연관): '+(', '.join(d.get('technique_ids') or []) or '확인 불가')+
           '\nIncident: '+(', '.join(d.get('incident_ids') or []) or '연결 없음')]
          for d in m.get('details',[])][:8] or [['확인된 위협 Alert 없음','대상 기간에 확인된 Alert가 없습니다.']],
       'note':'탐지 규칙 및 ATT&CK 관계는 공격 성공이나 침해 확정을 의미하지 않습니다.'},
      {'title':'08  대응·완화 및 향후 업무계획' if weekly else '08  조치내용 및 재발 방지',
       'headers':['구분','담당자 확인 및 후속 조치'],
       'rows':[
         ['우선 조사','CRITICAL/HIGH 경보, 반복 탐지 규칙, 의심 인증 실패를 우선 확인'],
         ['원본 대조','Alert와 연결된 원본 이벤트, 사용자, 프로젝트 및 해당 자원 확인'],
         ['조치 결과','실제 차단·복구·승인 여부는 현재 데이터로 확인되지 않음'],
         ['개선 권고','탐지 규칙 임계값과 오탐 가능성 검토, 권한·이미지 공유·보안그룹 설정 점검'],
       ]},
      {'title':'09  특이사항 및 검토 의견',
       'headers':['항목','내용'],
       'rows':[
         ['집계 범위','Neo4j ObservedEvent 전체(시각 확인 가능)를 집계하고, Alert 연결 위협은 별도 분리'],
         ['정상 판정 주의',m['policy_note']+' 단지 Alert가 없다는 이유로 무해하다고 판정하지 않음'],
         ['미확인 시각','전체 조회 중 시각 파싱 불가 이벤트 '+str(m['undated_events'])+'건, Alert '+str(m['undated_alerts'])+'건은 기간 집계에서 제외'],
         ['검토 서명','보고자: 자동 생성    확인자: __________________    검토 일시: ______________'],
       ]}
    ]
    if weekly:
        # Add a weekly-type overview with the same business-report feel.
        sections.insert(5,{'title':'05-A  주간 주요 수집 이벤트',
                           'headers':['이벤트 유형','발생 건수'], 'rows':_rows(m['event_types'],8)})
    return {'title':title,'kind':kind,'subtitle':period,'sections':sections}


def build_markdown(m):
    template=layout(m)
    out=['# '+template['title'],'',
         '생성 기준: '+template['subtitle'],'',
         '> 자동 집계 초안 · 담당자 검토 필요 · 전체 이벤트와 Alert 연결 이벤트를 구분함','']
    for sec in template['sections']:
        out.extend(['## '+sec['title'],''])
        heads=sec['headers']
        out+=['| '+' | '.join(heads)+' |', '| '+' | '.join(['---']*len(heads))+' |']
        for row in sec['rows']:
            out.append('| '+' | '.join(str(x).replace('|','\\|').replace('\n',' / ') for x in row)+' |')
        if sec.get('note'):out.extend(['',sec['note']])
        out.append('')
    return '\n'.join(out)


def _docx_shading(cell,fill):
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    tcPr=cell._tc.get_or_add_tcPr();shd=OxmlElement('w:shd');shd.set(qn('w:fill'),fill);tcPr.append(shd)


def generate_docx(report):
    m=read_model(report)
    if m is None: raise ValueError('구조화 보고서 데이터 없음')
    from docx import Document
    from docx.shared import Cm,Pt,RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml.ns import qn
    from docx.enum.table import WD_TABLE_ALIGNMENT,WD_CELL_VERTICAL_ALIGNMENT
    form=layout(m);doc=Document();sec=doc.sections[0]
    sec.top_margin=Cm(1.35);sec.bottom_margin=Cm(1.4)
    sec.left_margin=Cm(1.6);sec.right_margin=Cm(1.6)
    normal=doc.styles['Normal'];normal.font.name='NanumGothic';normal.font.size=Pt(8.5)
    normal._element.get_or_add_rPr().rFonts.set(qn('w:eastAsia'),'NanumGothic')
    normal.paragraph_format.space_after=Pt(2)
    heading=doc.add_paragraph();heading.alignment=WD_ALIGN_PARAGRAPH.CENTER
    run=heading.add_run(form['title']);run.bold=True;run.font.size=Pt(16)
    run.font.name='NanumGothic';run._element.get_or_add_rPr().rFonts.set(qn('w:eastAsia'),'NanumGothic')
    heading.paragraph_format.space_after=Pt(6)
    sub=doc.add_paragraph(form['subtitle']);sub.alignment=WD_ALIGN_PARAGRAPH.CENTER
    sub.runs[0].font.size=Pt(8)
    color='E5F6F5'  # 공통 주간 보고서 하늘색
    border='D2E3E5'  # 일일·주간 동일한 표 구분선
    for section in form['sections']:
        p=doc.add_paragraph();p.paragraph_format.space_before=Pt(9);p.paragraph_format.space_after=Pt(4);p.paragraph_format.keep_with_next=True
        r=p.add_run('■  '+section['title']);r.bold=True;r.font.size=Pt(10)
        t=doc.add_table(rows=1,cols=len(section['headers']))
        t.style='Table Grid';t.alignment=WD_TABLE_ALIGNMENT.CENTER
        for i,h in enumerate(section['headers']):
            c=t.rows[0].cells[i];c.text=h;_docx_shading(c,color)
        for values in section['rows']:
            cells=t.add_row().cells
            for i,value in enumerate(values):
                cells[i].text=str(value)
                cells[i].vertical_alignment=WD_CELL_VERTICAL_ALIGNMENT.CENTER
                if i==0 and len(values) in (2,4):_docx_shading(cells[i],'F8FAFC')
        for row in t.rows:
            for c in row.cells:
                for para in c.paragraphs:
                    para.paragraph_format.space_after=Pt(0)
                    for run in para.runs:
                        run.font.size=Pt(7.7)
        if section.get('note'):
            p=doc.add_paragraph('※ '+section['note']);p.runs[0].font.size=Pt(7.5)
    tail=doc.add_paragraph('※ 근거 중심 자동 집계 초안이며, 조치 완료 및 침해 확정 여부는 별도 확인 필요')
    tail.paragraph_format.space_before=Pt(9)
    tail.runs[0].font.size=Pt(7.5)
    stream=BytesIO();doc.save(stream);return stream.getvalue()


def _pdf_font():
    from pathlib import Path
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    name='SOCNanum'
    try:pdfmetrics.getFont(name);return name
    except KeyError:pass
    paths=['/usr/share/fonts/truetype/nanum/NanumGothic.ttf',
           '/usr/share/fonts/truetype/nanum/NanumGothicCoding.ttf',
           '/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc']
    for p in paths:
        if Path(p).is_file():
            try:pdfmetrics.registerFont(TTFont(name,p));return name
            except Exception:continue
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    pdfmetrics.registerFont(UnicodeCIDFont('HYGothic-Medium'))
    return 'HYGothic-Medium'


def generate_pdf(report):
    m=read_model(report)
    if m is None:raise ValueError('구조화 보고서 데이터 없음')
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
    font=_pdf_font();form=layout(m)
    buf=BytesIO();doc=SimpleDocTemplate(buf,pagesize=A4,leftMargin=15*mm,rightMargin=15*mm,
                  topMargin=14*mm,bottomMargin=17*mm)
    usable=A4[0]-30*mm
    title=ParagraphStyle('soc_title',fontName=font,fontSize=15,leading=20,alignment=TA_CENTER,spaceAfter=6)
    sub=ParagraphStyle('soc_sub',fontName=font,fontSize=8,leading=12,alignment=TA_CENTER,spaceAfter=10)
    head=ParagraphStyle('soc_head',fontName=font,fontSize=10,leading=13,spaceBefore=9,spaceAfter=4,keepWithNext=True)
    cell=ParagraphStyle('soc_cell',fontName=font,fontSize=7.3,leading=11,wordWrap='CJK')
    story=[Paragraph(xml_escape(form['title']),title),Paragraph(xml_escape(form['subtitle']),sub)]
    fill=colors.HexColor('#E5F6F5')  # 일일·주간 공통 하늘색
    for sect in form['sections']:
        story.append(Paragraph(xml_escape('■  '+sect['title']),head))
        nc=len(sect['headers']);rows=[sect['headers']]+sect['rows']
        matrix=[]
        for row in rows:
            matrix.append([Paragraph(xml_escape(str(x)).replace('\n','<br/>'),cell) for x in row])
        widths=([usable*0.19,usable*0.31,usable*0.19,usable*0.31] if nc==4
                else [usable*.30,usable*.70])
        table=Table(matrix,colWidths=widths,repeatRows=1,hAlign='CENTER')
        ts=[('BACKGROUND',(0,0),(-1,0),fill),('GRID',(0,0),(-1,-1),0.4,colors.HexColor('#AEB8BD')),
            ('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6),
            ('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5)]
        table.setStyle(TableStyle(ts));story.append(table)
        if sect.get('note'):story.append(Paragraph('※ '+xml_escape(sect['note']),sub))
    def footer(canv,report):
        canv.saveState();canv.setFont(font,7)
        canv.drawCentredString(A4[0]/2,10*mm,'자동 집계 초안 · 담당자 검토 필요 · %s쪽'%report.page)
        canv.restoreState()
    doc.build(story,onFirstPage=footer,onLaterPages=footer)
    return buf.getvalue()
