"""Printable/editable Korean operations reports using already verified stored Markdown."""
from __future__ import annotations

import io
import re
from xml.sax.saxutils import escape


def _lines(body):
    return str(body or '').splitlines()


def _simplify(s):
    s=re.sub(r'`([^`]*)`',r'\1',s)
    s=re.sub(r'\*\*(.*?)\*\*',r'\1',s)
    return s.strip()


def generate_docx(report):
    from docx import Document
    from docx.shared import Cm, Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    doc=Document()
    sec=doc.sections[0]
    sec.left_margin=sec.right_margin=Cm(1.7)
    sec.top_margin=sec.bottom_margin=Cm(1.7)
    normal=doc.styles['Normal']
    normal.font.name='Malgun Gothic';normal.font.size=Pt(9)
    normal.font.color.rgb=RGBColor(32,47,69)
    normal._element.rPr.rFonts.set(qn('w:eastAsia'),'Malgun Gothic')
    for style in ('Title','Heading 1','Heading 2'):
        s=doc.styles[style];s.font.name='Malgun Gothic'
        s._element.rPr.rFonts.set(qn('w:eastAsia'),'Malgun Gothic')
    for line in _lines(report.get('content')):
        if not line.strip():continue
        if line.startswith('# '):
            p=doc.add_heading(_simplify(line[2:]),0)
            p.alignment=WD_ALIGN_PARAGRAPH.CENTER
        elif line.startswith('## '):
            doc.add_heading(_simplify(line[3:]),level=1)
        elif line.startswith('- '):
            doc.add_paragraph(_simplify(line[2:]),style='List Bullet')
        else:
            doc.add_paragraph(_simplify(line))
    doc.add_paragraph('담당자 검토 전 자동 집계 초안입니다. 수집 및 실제 조치 정보 확인 필요.')
    bio=io.BytesIO();doc.save(bio);return bio.getvalue()


def generate_pdf(report):
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    font='HYSMyeongJo-Medium'
    try:pdfmetrics.getFont(font)
    except KeyError:pdfmetrics.registerFont(UnicodeCIDFont(font))
    buf=io.BytesIO()
    doc=SimpleDocTemplate(buf,pagesize=A4,leftMargin=19*mm,rightMargin=19*mm,
                          topMargin=17*mm,bottomMargin=17*mm)
    styles={
      'title':ParagraphStyle('PT',fontName=font,fontSize=16,leading=22,
                             spaceAfter=12,alignment=TA_CENTER,textColor=colors.HexColor('#263f62'),wordWrap='CJK'),
      'head':ParagraphStyle('PH',fontName=font,fontSize=11,leading=16,
                            spaceBefore=12,spaceAfter=8,textColor=colors.HexColor('#263f62'),wordWrap='CJK'),
      'normal':ParagraphStyle('PN',fontName=font,fontSize=9,leading=14,
                              spaceAfter=5,wordWrap='CJK'),
    }
    story=[]
    for line in _lines(report.get('content')):
        if not line.strip():
            story.append(Spacer(1,3*mm));continue
        kind='normal';out=_simplify(line)
        if line.startswith('# '):kind='title';out=_simplify(line[2:])
        elif line.startswith('## '):kind='head';out=_simplify(line[3:])
        elif line.startswith('- '):out='• '+_simplify(line[2:])
        story.append(Paragraph(escape(out).replace('\n','<br/>'),styles[kind]))
    def footer(canvas,p):
        canvas.saveState();canvas.setFont(font,7)
        canvas.drawCentredString(A4[0]/2,10*mm,f'자동 집계 초안 · 담당자 검토 필요 · {p.page}쪽')
        canvas.restoreState()
    doc.build(story,onFirstPage=footer,onLaterPages=footer)
    return buf.getvalue()
