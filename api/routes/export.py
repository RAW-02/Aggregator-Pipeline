from io import BytesIO
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from openpyxl import Workbook
from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from io import StringIO
import csv

from api.services.query_resolver import QueryResolver

router = APIRouter(prefix="/export", tags=["Export"])

resolver = QueryResolver()


@router.get("/")
def export_data(query: str, format: str = "json"):

    result = resolver.resolve(
        query=query,
        page=1,
        size=1000
    )

    hits = result["hits"]["hits"]

    data = [
        hit["_source"]
        for hit in hits
    ]

    # ==========================================
    # JSON EXPORT
    # ==========================================

    if format.lower() == "json":

        return {
            "query": query,
            "count": len(data),
            "results": data
        }

    # ==========================================
    # CSV EXPORT
    # ==========================================

    if format.lower() == "csv":
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "cve_id",
            "severity",
            "cvss_score",
            "epss_score",
            "threat_score"
        ])

        for doc in data:
            writer.writerow([
                doc.get("cve_id"),
                doc.get("severity"),
                doc.get("cvss_score"),
                doc.get("epss_score"),
                doc.get("threat_score")
            ])

        output.seek(0)

        return StreamingResponse(
            output,
            media_type="text/csv",
            headers={
                "Content-Disposition":
                "attachment; filename=vulnerabilities.csv"
            }
        )

    return {
        "error": "Unsupported format"
    }


@router.get("/excel")
def export_excel(query: str):

    result = resolver.resolve(
        query=query,
        page=1,
        size=1000
    )

    hits = result["hits"]["hits"]
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Vulnerabilities"

    sheet.append([
        "CVE ID",
        "Severity",
        "CVSS",
        "EPSS",
        "Threat Score"
    ])

    for hit in hits:
        doc = hit["_source"]
        sheet.append([
            doc.get("cve_id"),
            doc.get("severity"),
            doc.get("cvss_score"),
            doc.get("epss_score"),
            doc.get("threat_score")
        ])

    buffer = BytesIO()
    workbook.save(buffer)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type=
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition":
            "attachment; filename=vulnerabilities.xlsx"
        }
    )




@router.get("/pdf")
def export_pdf(query: str):
    result = resolver.resolve(
        query=query,
        page=1,
        size=1000
    )

    hits = result["hits"]["hits"]
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(
        Paragraph(
            "Vulnerability Report",
            styles["Title"]
        )
    )

    elements.append(
        Paragraph(
            f"Query: {query}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"Total Results: {len(hits)}",
            styles["Normal"]
        )
    )

    elements.append(
        Spacer(1, 12)
    )

    table_data = [[
        "CVE ID",
        "Severity",
        "CVSS",
        "EPSS",
        "Threat"
    ]]

    for hit in hits:
        doc_data = hit["_source"]
        table_data.append([
            str(doc_data.get("cve_id", "")),
            str(doc_data.get("severity", "")),
            str(doc_data.get("cvss_score", "")),
            str(doc_data.get("epss_score", "")),
            str(doc_data.get("threat_score", ""))
        ])

    table = Table(table_data)
    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")
        ])
    )

    elements.append(table)
    doc.build(elements)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition":
            "attachment; filename=vulnerabilities.pdf"
        }
    )