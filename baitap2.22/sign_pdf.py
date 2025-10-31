from datetime import datetime
from pyhanko.sign import signers
from pyhanko.stamp.text import TextStampStyle
from pyhanko.pdf_utils import images
from pyhanko.pdf_utils.text import TextBoxStyle
from pyhanko.pdf_utils.layout import SimpleBoxLayoutRule, AxisAlignment, Margins
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.fields import SigFieldSpec, append_signature_field

# ==== Đường dẫn ====
BASE = r"C:\Users\Admin\OneDrive\Desktop\baitap2.22"
PDF_IN = fr"{BASE}\baitap2.pdf"
PDF_OUT = fr"{BASE}\signed.pdf"
KEY_FILE = fr"{BASE}\keys\signer_key.pem"
CERT_FILE = fr"{BASE}\keys\signer_cert.pem"
SIG_IMG = fr"{BASE}\hieu.jpg"

# ==== Load private key và chứng chỉ ====
signer = signers.SimpleSigner.load(KEY_FILE, CERT_FILE)

# ==== Chuẩn bị style chữ ký (ảnh + chữ) ====
stamp_text = (
    f"MA QUOC HIEU\n"
    f"SDT: 0355553996\n"
    f"MSV: K225480106089\n"
    f"Ngày ký: {datetime.now().strftime('%d/%m/%Y')}"
)

stamp_style = TextStampStyle(
    stamp_text=stamp_text,
    background=images.PdfImage(SIG_IMG),
    background_layout=SimpleBoxLayoutRule(
        x_align=AxisAlignment.ALIGN_MIN,
        y_align=AxisAlignment.ALIGN_MID,
        margins=Margins(right=20)
    ),
    inner_content_layout=SimpleBoxLayoutRule(
        x_align=AxisAlignment.ALIGN_MIN,
        y_align=AxisAlignment.ALIGN_MID,
        margins=Margins(left=150)
    ),
    text_box_style=TextBoxStyle(font_size=13),
    border_width=1,
    background_opacity=1.0
)

# ==== Mở file PDF gốc ====
with open(PDF_IN, "rb") as inf:
    writer = IncrementalPdfFileWriter(inf)

    # Thêm trường chữ ký vào trang cuối
    append_signature_field(
        writer,
        SigFieldSpec("SigField1", box=(240, 50, 550, 150), on_page=-1)
    )

    # ==== Metadata chữ ký ====
    meta = signers.PdfSignatureMetadata(
        field_name="SigField1",
        reason="Nộp bài: Chữ ký số PDF - 58KTP",
        location="Thái Nguyên, VN",
        md_algorithm="sha256"
    )

    # ==== Ký PDF ====
    pdf_signer = signers.PdfSigner(
        signature_meta=meta,
        signer=signer,
        stamp_style=stamp_style
    )

    with open(PDF_OUT, "wb") as outf:
        pdf_signer.sign_pdf(writer, output=outf)

print("✅ Đã ký PDF thành công:", PDF_OUT)
